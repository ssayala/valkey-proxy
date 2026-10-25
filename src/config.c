#include "proxy.h"
#include <netdb.h>
#include <sys/stat.h>
#include <netinet/tcp.h>

/* ── config parsing ─────────────────────────────────────────────────── */
/* ── config parsing ──────────────────────────────────────────────────
 * One "key value" per line; '#' starts a comment (also after a value).
 * Anything unexpected -- an unknown key, a malformed or out-of-range number,
 * a switch that isn't yes/no -- stops startup with the file and line, rather
 * than being ignored: a typo in "tls-backend" must not silently mean
 * "plaintext". */
typedef enum { OPT_INT, OPT_BOOL, OPT_STR, OPT_OCTAL, OPT_AUTH_CLIENTS } OptType;
typedef struct {
    const char *name;
    OptType type;
    void *dst;
    size_t size;            /* OPT_STR: buffer size */
    long long min, max;     /* OPT_INT / OPT_OCTAL */
} ConfOpt;

#define INT_OPT(n, field, lo, hi) {n, OPT_INT, &g_config.field, 0, lo, hi}
#define BOOL_OPT(n, field) {n, OPT_BOOL, &g_config.field, 0, 0, 1}
#define STR_OPT(n, field) {n, OPT_STR, g_config.field, sizeof(g_config.field), 0, 0}
#define POOL_OPT(n, arr, type) {n, OPT_INT, &arr[type], 0, 0, 1000000}

static const ConfOpt CONF_OPTS[] = {
    STR_OPT("server-ip", server_ip),
    INT_OPT("server-port", server_port, 1, 65535),
    STR_OPT("bind", bind_ip),
    INT_OPT("port", proxy_port, 1, 65535),
    INT_OPT("worker-thread-no", worker_thread_no, 1, MAX_WORKERS),
    INT_OPT("db", db, 0, 1000000),
    STR_OPT("unix-socket", unix_socket_path),
    {"unix-socket-perm", OPT_OCTAL, &g_config.unix_socket_perm, 0, 0, 0777},
    BOOL_OPT("tls-enabled", tls_enabled),
    STR_OPT("tls-cert", tls_cert),
    STR_OPT("tls-key", tls_key),
    STR_OPT("tls-ca-cert", tls_ca_cert),
    {"tls-auth-clients", OPT_AUTH_CLIENTS, &g_config.tls_auth_clients, 0, 0, 0},
    BOOL_OPT("tls-backend", tls_backend),
    STR_OPT("tls-backend-ca-cert", tls_backend_ca_cert),
    STR_OPT("tls-backend-cert", tls_backend_cert),
    STR_OPT("tls-backend-key", tls_backend_key),
    BOOL_OPT("tls-backend-verify", tls_backend_verify),
    BOOL_OPT("tls-backend-verify-host", tls_backend_verify_host),
    BOOL_OPT("tls-ktls", tls_ktls),
    BOOL_OPT("tls-auto-reload", tls_auto_reload),
    INT_OPT("tls-handshake-timeout", tls_handshake_timeout, 0, 3600),
    INT_OPT("max_multikey_payload", max_multikey_payload, 1024, 1LL << 30),
    INT_OPT("max_command_size", max_command_size, 1024, 1LL << 30),
    INT_OPT("max_connection", max_connection, 64, 10000000),
    INT_OPT("maxclients", maxclients, 1, 10000000),
    INT_OPT("client-output-buffer-limit-pubsub", obuf_limit_pubsub, 0, INT32_MAX),
    INT_OPT("client-output-buffer-limit-normal", obuf_limit_normal, 0, INT32_MAX),
    INT_OPT("cluster_refresh_interval_ms", cluster_refresh_interval_ms, 0, 3600000),
    INT_OPT("cluster_node_fail_grace_ms", cluster_node_fail_grace_ms, 0, 3600000),
    INT_OPT("backend_connect_timeout_ms", backend_connect_timeout_ms, 10, 600000),
    INT_OPT("tcp-keepalive", tcp_keepalive, 0, 86400),
    INT_OPT("timeout", client_timeout, 0, 100000000),
    INT_OPT("shutdown-timeout", shutdown_timeout, 0, 3600),
    BOOL_OPT("worker-cpu-affinity", worker_cpu_affinity),
    INT_OPT("cpu-affinity-base", cpu_affinity_base, 0, 4096),
    BOOL_OPT("verbose", verbose),
    POOL_OPT("min_normal_connection", g_pool_min, POOL_NORMAL),
    POOL_OPT("max_normal_connection", g_pool_max, POOL_NORMAL),
    POOL_OPT("min_blocking_connection", g_pool_min, POOL_BLOCKING),
    POOL_OPT("max_blocking_connection", g_pool_max, POOL_BLOCKING),
    POOL_OPT("min_subscription_connection", g_pool_min, POOL_SUBSCRIPTION),
    POOL_OPT("max_subscription_connection", g_pool_max, POOL_SUBSCRIPTION),
    POOL_OPT("min_transaction_connection", g_pool_min, POOL_TRANSACTION),
    POOL_OPT("max_transaction_connection", g_pool_max, POOL_TRANSACTION),
    POOL_OPT("min_acl_connection", g_pool_min, POOL_ACL),
    POOL_OPT("max_acl_connection", g_pool_max, POOL_ACL),
};

static void conf_fail(const char *path, int lineno, const char *fmt, const char *a, const char *b) {
    fprintf(stderr, "%s:%d: ", path, lineno);
    fprintf(stderr, fmt, a, b);
    fprintf(stderr, "\n");
    exit(1);
}

static int parse_ll(const char *s, int base, long long *out) {
    char *end;
    errno = 0;
    long long v = strtoll(s, &end, base);
    if (errno || end == s || *end) return -1;
    *out = v;
    return 0;
}

static void conf_set(const char *path, int lineno, const char *key, const char *val) {
    for (size_t i = 0; i < sizeof(CONF_OPTS) / sizeof(CONF_OPTS[0]); i++) {
        const ConfOpt *o = &CONF_OPTS[i];
        if (strcmp(o->name, key) != 0) continue;
        long long v;
        char range[64];
        switch (o->type) {
            case OPT_STR:
                if (strlen(val) >= o->size) conf_fail(path, lineno, "value for '%s' is too long%s", key, "");
                snprintf((char *)o->dst, o->size, "%s", val);
                return;
            case OPT_BOOL:
                if (strcmp(val, "yes") && strcmp(val, "no"))
                    conf_fail(path, lineno, "'%s' must be yes or no, got '%s'", key, val);
                *(int *)o->dst = !strcmp(val, "yes");
                return;
            case OPT_AUTH_CLIENTS:
                if (strcmp(val, "yes") && strcmp(val, "no") && strcmp(val, "optional"))
                    conf_fail(path, lineno, "'%s' must be yes, no or optional, got '%s'", key, val);
                *(int *)o->dst = !strcmp(val, "yes") ? 1 : !strcmp(val, "optional") ? 2 : 0;
                return;
            case OPT_INT:
            case OPT_OCTAL:
                if (parse_ll(val, o->type == OPT_OCTAL ? 8 : 10, &v) < 0)
                    conf_fail(path, lineno, "'%s' needs a whole number, got '%s'", key, val);
                if (v < o->min || v > o->max) {
                    snprintf(range, sizeof(range), "%lld..%lld", o->min, o->max);
                    conf_fail(path, lineno, "'%s' must be in %s", key, range);
                }
                *(int *)o->dst = (int)v;
                return;
        }
    }
    conf_fail(path, lineno, "unknown setting '%s'%s", key, "");
}

void parse_conf(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        exit(1);
    }
    g_config.worker_thread_no = 1;
    g_config.db = 0;
    g_config.tls_enabled = 0;
    g_config.tls_backend_verify = 1;
    g_config.tls_ktls = 0; /* see the tls-ktls note in README.md */
    g_config.tls_auto_reload = 1;
    g_config.max_multikey_payload = 64 * 1024 * 1024;
    g_config.max_connection = DEFAULT_MAX_CONNECTIONS;
    g_config.maxclients = 10000;
    g_config.obuf_limit_pubsub = 32 * 1024 * 1024; /* Valkey's pubsub hard limit */
    g_config.obuf_limit_normal = 0;                 /* unlimited, as in Valkey */
    g_config.cluster_refresh_interval_ms = 2000;
    g_config.cluster_node_fail_grace_ms = 10000;
    g_config.backend_connect_timeout_ms = 1000;
    g_config.max_command_size = 512 * 1024 * 1024;
    g_config.tls_handshake_timeout = 10;
    g_config.shutdown_timeout = 10;
    g_config.tcp_keepalive = 300; /* same default as Valkey */

    char line[2048];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        size_t len = strlen(line);
        if (len == sizeof(line) - 1 && line[len - 1] != '\n') conf_fail(path, lineno, "line too long%s%s", "", "");
        /* '#' starts a comment at the start of a line or after whitespace. */
        for (char *h = line; (h = strchr(h, '#')); h++)
            if (h == line || h[-1] == ' ' || h[-1] == '\t') {
                *h = '\0';
                break;
            }
        char key[128], val[1024], extra[2];
        int n = sscanf(line, "%127s %1023s %1s", key, val, extra);
        if (n <= 0) continue; /* blank or comment-only */
        if (n == 1) conf_fail(path, lineno, "'%s' has no value%s", key, "");
        if (n == 3) conf_fail(path, lineno, "'%s' takes a single value%s", key, "");
        conf_set(path, lineno, key, val);
    }
    fclose(f);

    if (!g_config.server_ip[0]) conf_fail(path, 0, "missing required setting '%s'%s", "server-ip", "");
    if (!g_config.server_port) conf_fail(path, 0, "missing required setting '%s'%s", "server-port", "");
    if (!g_config.proxy_port) conf_fail(path, 0, "missing required setting '%s'%s", "port", "");
    for (int t = 0; t < POOL_TYPE_COUNT; t++)
        if (g_pool_min[t] > g_pool_max[t] || g_pool_max[t] < 1)
            conf_fail(path, 0, "min_%s_connection exceeds max (or max < 1)%s", POOL_NAME[t], "");
}

/* ── TCP / Unix helpers ─────────────────────────────────────────────── */
void set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

void set_tcp_keepalive(int fd) {
    int idle = g_config.tcp_keepalive;
    if (idle <= 0) return;
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) < 0) return;
#ifdef __linux__
    /* Probe after `idle` seconds, then every idle/3, give up after 3 misses:
     * a vanished peer is detected within about 2x tcp-keepalive. */
    int intvl = idle / 3 > 0 ? idle / 3 : 1, cnt = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
}

/* timeout_ms bounds only the "still connecting" wait (TCP handshake in
 * flight); ECONNREFUSED and similar immediate errors return right away
 * regardless of it. Kept separate from tcp_connect() below because the
 * right value differs sharply by caller: fetch_cluster_nodes()'s one-shot
 * startup discovery (before any thread exists to block) can afford a
 * generous wait, but pool_new_fd() (worker thread, reconnecting to a
 * possibly still-booting promoted replica) and the periodic topology
 * refresh (its own thread, but retried every cycle) both want to fail fast
 * instead of tying up a thread for seconds on end. */
int resolve_addr(const char *host, int port, struct sockaddr_storage *sa, socklen_t *salen) {
    char ps[16];
    snprintf(ps, sizeof(ps), "%d", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
    int rc = getaddrinfo(host, ps, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "Could not resolve %s: %s\n", host, gai_strerror(rc));
        return -1;
    }
    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

int tcp_connect_timeout(const char *ip, int port, int timeout_ms) {
    struct sockaddr_storage a;
    socklen_t alen;
    if (resolve_addr(ip, port, &a, &alen) < 0) return -1;
    return tcp_connect_addr(&a, alen, ip, port, timeout_ms);
}

/* As tcp_connect_timeout(), to an already-resolved address (ip/port only
 * label error messages). */
int tcp_connect_addr(const struct sockaddr_storage *sa, socklen_t salen, const char *ip, int port, int timeout_ms) {
    struct sockaddr_storage a = *sa;
    socklen_t alen = salen;
    int fd = socket(a.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    set_tcp_keepalive(fd);

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(fd, (struct sockaddr *)&a, alen);
    if (ret < 0 && errno != EINPROGRESS) {
        if (errno == ECONNREFUSED)
            fprintf(stderr, "Could not connect to Valkey at %s:%d: Connection refused\n", ip, port);
        else
            perror("connect");
        close(fd);
        return -1;
    }

    if (ret != 0) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        if (select(fd + 1, NULL, &wset, NULL, &tv) <= 0) {
            fprintf(stderr, "Could not connect to Valkey at %s:%d: Connection timed out\n", ip, port);
            close(fd);
            return -1;
        }
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) {
            if (err == ECONNREFUSED)
                fprintf(stderr, "Could not connect to Valkey at %s:%d: Connection refused\n", ip, port);
            else
                fprintf(stderr, "Could not connect to Valkey at %s:%d: %s\n", ip, port, strerror(err));
            close(fd);
            return -1;
        }
    }

    fcntl(fd, F_SETFL, flags);
    return fd;
}

int tcp_connect(const char *ip, int port) {
    return tcp_connect_timeout(ip, port, 5000);
}

/* ip: an IPv4/IPv6 literal or hostname; "" = all interfaces (dual-stack
 * "::" where IPv6 is available, else 0.0.0.0). */
int create_tcp_listener(const char *ip, int port, int reuseport) {
    struct sockaddr_storage a;
    socklen_t alen;
    memset(&a, 0, sizeof(a));
    int any = !ip[0];
    if (any) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&a;
        a6->sin6_family = AF_INET6;
        a6->sin6_addr = in6addr_any;
        a6->sin6_port = htons((uint16_t)port);
        alen = sizeof(*a6);
    } else if (resolve_addr(ip, port, &a, &alen) < 0) {
        return -1;
    }
    int fd = socket(a.ss_family, SOCK_STREAM, 0);
    if (fd < 0 && any) { /* no IPv6 here: plain IPv4 any-address */
        struct sockaddr_in *a4 = (struct sockaddr_in *)&a;
        memset(&a, 0, sizeof(a));
        a4->sin_family = AF_INET;
        a4->sin_addr.s_addr = INADDR_ANY;
        a4->sin_port = htons((uint16_t)port);
        alen = sizeof(*a4);
        fd = socket(AF_INET, SOCK_STREAM, 0);
    }
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    int yes = 1, no = 0;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (a.ss_family == AF_INET6 && any) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
#ifdef SO_REUSEPORT
    if (reuseport && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) < 0) {
        perror("setsockopt(SO_REUSEPORT)");
        close(fd);
        return -1;
    }
#else
    (void)reuseport;
#endif
    set_nonblocking(fd);
    if (bind(fd, (struct sockaddr *)&a, alen) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

int create_unix_listener(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket(unix)");
        return -1;
    }
    struct sockaddr_un a;
    if (strlen(path) >= sizeof(a.sun_path)) {
        fprintf(stderr, "unix-socket path too long (max %zu bytes): %s\n", sizeof(a.sun_path) - 1, path);
        close(fd);
        return -1;
    }
    set_nonblocking(fd);
    unlink(path);
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%.107s", path);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 ||
        (g_config.unix_socket_perm && chmod(path, (mode_t)g_config.unix_socket_perm) < 0)) {
        perror("bind(unix)");
        close(fd);
        return -1;
    }
    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen(unix)");
        close(fd);
        return -1;
    }
    return fd;
}

/* Blocking connect (+ TLS handshake when tls-backend is on) to a backend
 * node; returns a blocking fd, or -1. */
int backend_connect_blocking(const char *ip, int port, const struct sockaddr_storage *sa, socklen_t salen,
                             int timeout_ms, const char *tls_host, TlsConn **ssl_out) {
    *ssl_out = NULL;
    int fd = (sa && salen) ? tcp_connect_addr(sa, salen, ip, port, timeout_ms) : tcp_connect_timeout(ip, port, timeout_ms);
    if (fd < 0) return -1;
#ifdef USE_TLS
    if (g_config.tls_backend) {
        *ssl_out = tls_connect_blocking(fd, timeout_ms, tls_host ? tls_host : ip);
        if (!*ssl_out) {
            close(fd);
            return -1;
        }
    }
#endif
    return fd;
}
