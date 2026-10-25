#include "proxy.h"
#include <sys/stat.h>

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

/* The live contexts are swapped on reload (tls_reload()) while workers keep
 * creating connections from them: SSL_new() and the swap both hold ctx_lock.
 * SSL_new() takes a reference on its context, so existing connections keep
 * the old one alive until they close; the proxy's own reference is dropped
 * right after the swap. */
static pthread_rwlock_t ctx_lock = PTHREAD_RWLOCK_INITIALIZER;

static SSL_CTX *build_server_ctx(void) {
    if (!g_config.tls_cert[0] || !g_config.tls_key[0]) {
        fprintf(stderr, "TLS: tls-cert/tls-key not set\n");
        return NULL;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) goto err;
    ctx_common(ctx);
    if (SSL_CTX_use_certificate_chain_file(ctx, g_config.tls_cert) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, g_config.tls_key, SSL_FILETYPE_PEM) <= 0)
        goto err;
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "TLS: cert/key mismatch\n");
        goto err;
    }
    if (g_config.tls_auth_clients) {
        if (!g_config.tls_ca_cert[0] || SSL_CTX_load_verify_locations(ctx, g_config.tls_ca_cert, NULL) != 1) {
            fprintf(stderr, "TLS: tls-auth-clients needs a valid tls-ca-cert\n");
            goto err;
        }
        int mode = SSL_VERIFY_PEER;
        if (g_config.tls_auth_clients == 1) mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_CTX_set_verify(ctx, mode, NULL);
    }
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"valkey-proxy", 12);
    return ctx;
err:
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
}

static SSL_CTX *build_backend_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) goto err;
    ctx_common(ctx);
    if (g_config.tls_backend_verify) {
        int ok = g_config.tls_backend_ca_cert[0] ? SSL_CTX_load_verify_locations(ctx, g_config.tls_backend_ca_cert, NULL)
                                                 : SSL_CTX_set_default_verify_paths(ctx);
        if (ok != 1) {
            fprintf(stderr, "TLS: can't load backend CA (tls-backend-ca-cert)\n");
            goto err;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    if (g_config.tls_backend_cert[0] &&
        (SSL_CTX_use_certificate_chain_file(ctx, g_config.tls_backend_cert) <= 0 ||
         SSL_CTX_use_PrivateKey_file(ctx, g_config.tls_backend_key, SSL_FILETYPE_PEM) <= 0))
        goto err;
    return ctx;
err:
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
}

/* ── certificate reload ─────────────────────────────────────────────── */
/* Identity of every file the contexts were built from, to notice when any
 * changes (Kubernetes rewrites a mounted secret by swapping a symlink, so
 * the inode and mtime of the path both change). */
typedef struct {
    dev_t dev;
    ino_t ino;
    off_t size;
    struct timespec mtime;
} FileStamp;
static FileStamp tls_stamps[7];

static void tls_stamp_files(FileStamp *out) {
    const char *files[7] = {g_config.tls_cert,        g_config.tls_key,          g_config.tls_ca_cert,
                            g_config.tls_backend_ca_cert, g_config.tls_backend_cert, g_config.tls_backend_key,
                            NULL};
    for (int i = 0; i < 7; i++) {
        struct stat st;
        memset(&out[i], 0, sizeof(out[i]));
        if (files[i] && files[i][0] && stat(files[i], &st) == 0) {
            out[i].dev = st.st_dev;
            out[i].ino = st.st_ino;
            out[i].size = st.st_size;
            out[i].mtime = st.st_mtim;
        }
    }
}

int tls_files_changed(void) {
    if (!g_config.tls_enabled && !g_config.tls_backend) return 0;
    FileStamp now[7];
    tls_stamp_files(now);
    return memcmp(now, tls_stamps, sizeof(now)) != 0;
}

/* Rebuilds the contexts from the configured files and swaps them in. On
 * any failure the current ones stay in use. Called from main() only. */
int tls_reload(void) {
    SSL_CTX *srv = NULL, *be = NULL;
    if (g_config.tls_enabled && !(srv = build_server_ctx())) goto fail;
    if (g_config.tls_backend && !(be = build_backend_ctx())) goto fail;
    pthread_rwlock_wrlock(&ctx_lock);
    SSL_CTX *old_srv = g_ssl_ctx, *old_be = g_backend_ssl_ctx;
    if (srv) g_ssl_ctx = srv;
    if (be) g_backend_ssl_ctx = be;
    pthread_rwlock_unlock(&ctx_lock);
    if (srv) SSL_CTX_free(old_srv);
    if (be) SSL_CTX_free(old_be);
    tls_stamp_files(tls_stamps);
    printf("TLS certificates reloaded\n");
    return 0;
fail:
    SSL_CTX_free(srv);
    tls_stamp_files(tls_stamps); /* don't retry the same broken files every check */
    fprintf(stderr, "TLS reload failed: keeping the current certificates\n");
    return -1;
}

int init_tls(void) {
    if (!(g_ssl_ctx = build_server_ctx())) return -1;
    tls_stamp_files(tls_stamps);
    printf("TLS (clients) enabled  cert=%s%s  ktls=%s\n", g_config.tls_cert,
           g_config.tls_auth_clients == 1   ? "  client-auth=required"
           : g_config.tls_auth_clients == 2 ? "  client-auth=optional"
                                            : "",
           g_config.tls_ktls ? "requested" : "off");
    return 0;
}

int init_backend_tls(void) {
    if (!(g_backend_ssl_ctx = build_backend_ctx())) return -1;
    tls_stamp_files(tls_stamps);
    printf("TLS (backends) enabled  verify=%s%s%s\n", g_config.tls_backend_verify ? "yes" : "no",
           g_config.tls_backend_verify && g_config.tls_backend_verify_host ? "  verify-host=yes" : "",
           g_config.tls_backend_cert[0] ? "  client-cert=yes" : "");
    return 0;
}

/* host (client side only, may be NULL): the name the node is known by --
 * sent as SNI if it's a DNS name, and with tls-backend-verify-host checked
 * against the certificate (as a DNS name or an IP address). */
TlsConn *tls_new(int fd, int server, const char *host) {
    pthread_rwlock_rdlock(&ctx_lock);
    SSL_CTX *ctx = server ? g_ssl_ctx : g_backend_ssl_ctx;
    SSL *ssl = ctx ? SSL_new(ctx) : NULL;
    pthread_rwlock_unlock(&ctx_lock);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, fd);
    if (server) {
        SSL_set_accept_state(ssl);
        return ssl;
    }
    SSL_set_connect_state(ssl);
    if (host && host[0]) {
        unsigned char tmp[16];
        int is_ip = inet_pton(AF_INET, host, tmp) == 1 || inet_pton(AF_INET6, host, tmp) == 1;
        if (!is_ip) SSL_set_tlsext_host_name(ssl, host);
        if (g_config.tls_backend_verify && g_config.tls_backend_verify_host) {
            int ok = is_ip ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host) : SSL_set1_host(ssl, host);
            if (ok != 1) {
                SSL_free(ssl);
                return NULL;
            }
        }
    }
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
TlsConn *tls_connect_blocking(int fd, int timeout_ms, const char *host) {
    TlsConn *ssl = tls_new(fd, 0, host);
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
