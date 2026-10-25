#include "proxy.h"

/* ── TLS ────────────────────────────────────────────────────────────────
 * Every socket read/write in the proxy goes through net_read()/net_write(),
 * which take the connection's TlsConn (NULL = plain TCP) and present the
 * same contract as read()/write() on a non-blocking fd:
 *     >0 bytes, 0 = orderly EOF, -1 with errno set (EAGAIN = try again).
 * For TLS the "try again" direction isn't always the obvious one (a read
 * can need the socket to become writable and vice versa); `want`, when
 * non-NULL, reports EL_READABLE/EL_WRITABLE for that case, 0 otherwise.
 *
 * Where the kernel supports it (the `tls` module loaded, AES-GCM or
 * ChaCha20-Poly1305 negotiated), OpenSSL hands record encryption and
 * decryption to the kernel after the handshake (kTLS, SSL_OP_ENABLE_KTLS);
 * SSL_read()/SSL_write() then become plain recvmsg()/sendmsg() calls on
 * already-decrypted data, with no change needed here. */

#ifdef USE_TLS
#ifdef __linux__
#include <linux/tls.h>
#endif

SSL_CTX *g_backend_ssl_ctx = NULL;

static void ctx_common(SSL_CTX *ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    /* Partial writes + moving buffers: write buffers are realloc'd and
     * appended to between a WANT_WRITE and its retry. */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                              SSL_MODE_RELEASE_BUFFERS);
    if (g_config.tls_ktls) SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
}

int init_tls(void) {
    if (!g_config.tls_cert[0] || !g_config.tls_key[0]) {
        fprintf(stderr, "TLS: tls-cert/tls-key not set\n");
        return -1;
    }
    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ctx_common(g_ssl_ctx);
    if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx, g_config.tls_cert) <= 0 ||
        SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_config.tls_key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (!SSL_CTX_check_private_key(g_ssl_ctx)) {
        fprintf(stderr, "TLS: cert/key mismatch\n");
        return -1;
    }
    if (g_config.tls_auth_clients) {
        if (!g_config.tls_ca_cert[0] || SSL_CTX_load_verify_locations(g_ssl_ctx, g_config.tls_ca_cert, NULL) != 1) {
            fprintf(stderr, "TLS: tls-auth-clients needs a valid tls-ca-cert\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }
        int mode = SSL_VERIFY_PEER;
        if (g_config.tls_auth_clients == 1) mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_CTX_set_verify(g_ssl_ctx, mode, NULL);
    }
    SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_id_context(g_ssl_ctx, (const unsigned char *)"valkey-proxy", 12);
    printf("TLS (clients) enabled  cert=%s%s  ktls=%s\n", g_config.tls_cert,
           g_config.tls_auth_clients == 1   ? "  client-auth=required"
           : g_config.tls_auth_clients == 2 ? "  client-auth=optional"
                                            : "",
           g_config.tls_ktls ? "requested" : "off");
    return 0;
}

int init_backend_tls(void) {
    g_backend_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_backend_ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ctx_common(g_backend_ssl_ctx);
    if (g_config.tls_backend_verify) {
        int ok = g_config.tls_backend_ca_cert[0]
                     ? SSL_CTX_load_verify_locations(g_backend_ssl_ctx, g_config.tls_backend_ca_cert, NULL)
                     : SSL_CTX_set_default_verify_paths(g_backend_ssl_ctx);
        if (ok != 1) {
            fprintf(stderr, "TLS: can't load backend CA (tls-backend-ca-cert)\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }
        SSL_CTX_set_verify(g_backend_ssl_ctx, SSL_VERIFY_PEER, NULL);
    }
    if (g_config.tls_backend_cert[0]) {
        if (SSL_CTX_use_certificate_chain_file(g_backend_ssl_ctx, g_config.tls_backend_cert) <= 0 ||
            SSL_CTX_use_PrivateKey_file(g_backend_ssl_ctx, g_config.tls_backend_key, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
    printf("TLS (backends) enabled  verify=%s%s\n", g_config.tls_backend_verify ? "yes" : "no",
           g_config.tls_backend_cert[0] ? "  client-cert=yes" : "");
    return 0;
}

TlsConn *tls_new(int fd, int server) {
    SSL_CTX *ctx = server ? g_ssl_ctx : g_backend_ssl_ctx;
    if (!ctx) return NULL;
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, fd);
    if (server)
        SSL_set_accept_state(ssl);
    else
        SSL_set_connect_state(ssl);
    return ssl;
}

void tls_free(TlsConn *ssl) {
    if (ssl) SSL_free(ssl);
}

/* Maps an SSL_get_error() result onto the read()/write() contract. */
static ssize_t ssl_result(SSL *ssl, int rc, int *want) {
    int err = SSL_get_error(ssl, rc);
    switch (err) {
        case SSL_ERROR_WANT_READ:
            if (want) *want = EL_READABLE;
            errno = EAGAIN;
            return -1;
        case SSL_ERROR_WANT_WRITE:
            if (want) *want = EL_WRITABLE;
            errno = EAGAIN;
            return -1;
        case SSL_ERROR_ZERO_RETURN: return 0;
        case SSL_ERROR_SYSCALL:
            if (errno == 0) return 0; /* EOF without close_notify (peer just closed the socket) */
            return -1;
        default: errno = EIO; return -1;
    }
}

/* With TLS 1.3 kTLS RX the kernel can't tell where a record's content ends
 * until it has decrypted it (padding), so by default it decrypts into a
 * kernel buffer and copies out. Peers using OpenSSL/BoringSSL/rustls don't
 * pad, so promising "no padding" lets it decrypt straight into our buffer;
 * a padded record is just decrypted again (slower, still correct). */
static void ktls_tune(SSL *ssl) {
#if defined(__linux__) && defined(TLS_RX_EXPECT_NO_PAD)
    if (SSL_version(ssl) == TLS1_3_VERSION && BIO_get_ktls_recv(SSL_get_rbio(ssl))) {
        int one = 1;
        setsockopt(SSL_get_fd(ssl), SOL_TLS, TLS_RX_EXPECT_NO_PAD, &one, sizeof(one));
    }
#else
    (void)ssl;
#endif
}

int tls_handshake(TlsConn *ssl, int *want) {
    ERR_clear_error();
    errno = 0;
    int rc = SSL_do_handshake(ssl);
    if (rc == 1) {
        ktls_tune(ssl);
        return 1;
    }
    ssize_t r = ssl_result(ssl, rc, want);
    if (r < 0 && errno == EAGAIN) return 0;
    return -1;
}

int tls_ktls_state(TlsConn *ssl) {
    int s = 0;
    if (BIO_get_ktls_send(SSL_get_wbio(ssl))) s |= 1;
    if (BIO_get_ktls_recv(SSL_get_rbio(ssl))) s |= 2;
    return s;
}

const char *tls_describe(TlsConn *ssl, char *buf, int cap) {
    int k = tls_ktls_state(ssl);
    snprintf(buf, (size_t)cap, "%s %s ktls=%s", SSL_get_version(ssl), SSL_get_cipher_name(ssl),
             k == 3   ? "tx+rx"
             : k == 1 ? "tx"
             : k == 2 ? "rx"
                      : "off");
    return buf;
}

/* Blocking handshake on a still-blocking fd (startup discovery, the legacy
 * pool's connects); timeout_ms bounds each wait. */
TlsConn *tls_connect_blocking(int fd, int timeout_ms) {
    TlsConn *ssl = tls_new(fd, 0);
    if (!ssl) return NULL;
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ERR_clear_error();
    if (SSL_connect(ssl) != 1) {
        unsigned long e = ERR_peek_error();
        fprintf(stderr, "TLS: backend handshake failed: %s\n", e ? ERR_reason_error_string(e) : strerror(errno));
        SSL_free(ssl);
        return NULL;
    }
    ktls_tune(ssl);
    struct timeval zero = {0, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &zero, sizeof(zero));
    return ssl;
}
#endif

ssize_t net_read(int fd, TlsConn *ssl, void *buf, size_t n, int *want) {
    if (want) *want = 0;
#ifdef USE_TLS
    if (ssl) {
        ERR_clear_error();
        errno = 0;
        int rc = SSL_read(ssl, buf, n > INT32_MAX ? INT32_MAX : (int)n);
        return rc > 0 ? rc : ssl_result(ssl, rc, want);
    }
#else
    (void)ssl;
#endif
    return read(fd, buf, n);
}

ssize_t net_write(int fd, TlsConn *ssl, const void *buf, size_t n, int *want) {
    if (want) *want = 0;
#ifdef USE_TLS
    if (ssl) {
        if (n == 0) return 0;
        ERR_clear_error();
        errno = 0;
        int rc = SSL_write(ssl, buf, n > INT32_MAX ? INT32_MAX : (int)n);
        return rc > 0 ? rc : ssl_result(ssl, rc, want);
    }
#else
    (void)ssl;
#endif
    return write(fd, buf, n);
}

/* Short reads only prove the socket is drained for plain TCP: OpenSSL may
 * still hold decrypted bytes (and the kernel more records) after an
 * SSL_read() that didn't fill the buffer. */
int net_short_read_drained(TlsConn *ssl) {
    return ssl == NULL;
}

/* Writes all of buf, blocking-style (fd in blocking mode): for the startup
 * discovery and legacy pool setup paths only. */
int net_write_all(int fd, TlsConn *ssl, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        ssize_t w = net_write(fd, ssl, p, n, NULL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}
