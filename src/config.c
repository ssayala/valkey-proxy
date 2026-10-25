#include "proxy.h"
#include <netdb.h>
#include <sys/stat.h>
#include <netinet/tcp.h>

/* ── config parsing ─────────────────────────────────────────────────── */
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
    g_config.max_multikey_payload = 64 * 1024 * 1024;
    g_config.max_connection = DEFAULT_MAX_CONNECTIONS;
    g_config.cluster_refresh_interval_ms = 0; /* 0 = periodic refresh disabled */
    g_config.cluster_node_fail_grace_ms = 10000;
    g_config.backend_connect_timeout_ms = 1000;
    g_config.max_command_size = 512 * 1024 * 1024;
    g_config.tls_handshake_timeout = 10;
    g_config.shutdown_timeout = 10;
    g_config.tcp_keepalive = 300; /* same default as Valkey */
    char line[512], key[64], val[448];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63s %447s", key, val) != 2) continue;
        if (!strcmp(key, "server-ip"))
            snprintf(g_config.server_ip, sizeof(g_config.server_ip), "%.255s", val);
        else if (!strcmp(key, "server-port"))
            g_config.server_port = atoi(val);
        else if (!strcmp(key, "bind"))
            snprintf(g_config.bind_ip, sizeof(g_config.bind_ip), "%.255s", val);
        else if (!strcmp(key, "port"))
            g_config.proxy_port = atoi(val);
        else if (!strcmp(key, "worker-thread-no"))
            g_config.worker_thread_no = atoi(val);
        else if (!strcmp(key, "db"))
            g_config.db = atoi(val);
        else if (!strcmp(key, "unix-socket"))
            snprintf(g_config.unix_socket_path, 256, "%.255s", val);
        else if (!strcmp(key, "tls-enabled"))
            g_config.tls_enabled = (!strcmp(val, "yes"));
        else if (!strcmp(key, "tls-cert"))
            snprintf(g_config.tls_cert, 256, "%.255s", val);
        else if (!strcmp(key, "tls-key"))
            snprintf(g_config.tls_key, 256, "%.255s", val);
        else if (!strcmp(key, "tls-ca-cert"))
            snprintf(g_config.tls_ca_cert, 256, "%.255s", val);
        else if (!strcmp(key, "tls-auth-clients"))
            g_config.tls_auth_clients = !strcmp(val, "yes") ? 1 : !strcmp(val, "optional") ? 2 : 0;
        else if (!strcmp(key, "tls-backend"))
            g_config.tls_backend = (!strcmp(val, "yes"));
        else if (!strcmp(key, "tls-backend-ca-cert"))
            snprintf(g_config.tls_backend_ca_cert, 256, "%.255s", val);
        else if (!strcmp(key, "tls-backend-cert"))
            snprintf(g_config.tls_backend_cert, 256, "%.255s", val);
        else if (!strcmp(key, "tls-backend-key"))
            snprintf(g_config.tls_backend_key, 256, "%.255s", val);
        else if (!strcmp(key, "tls-backend-verify"))
            g_config.tls_backend_verify = (!strcmp(val, "yes"));
        else if (!strcmp(key, "tls-ktls"))
            g_config.tls_ktls = (!strcmp(val, "yes"));
        else if (!strcmp(key, "max_multikey_payload"))
            g_config.max_multikey_payload = atoi(val);
        else if (!strcmp(key, "max_connection"))
            g_config.max_connection = atoi(val);
        else if (!strcmp(key, "cluster_refresh_interval_ms"))
            g_config.cluster_refresh_interval_ms = atoi(val);
        else if (!strcmp(key, "cluster_node_fail_grace_ms"))
            g_config.cluster_node_fail_grace_ms = atoi(val);
        else if (!strcmp(key, "tcp-keepalive"))
            g_config.tcp_keepalive = atoi(val);
        else if (!strcmp(key, "shutdown-timeout"))
            g_config.shutdown_timeout = atoi(val);
        else if (!strcmp(key, "unix-socket-perm"))
            g_config.unix_socket_perm = (int)strtol(val, NULL, 8);
        else if (!strcmp(key, "timeout"))
            g_config.client_timeout = atoi(val);
        else if (!strcmp(key, "tls-handshake-timeout"))
            g_config.tls_handshake_timeout = atoi(val);
        else if (!strcmp(key, "worker-cpu-affinity"))
            g_config.worker_cpu_affinity = (!strcmp(val, "yes"));
        else if (!strcmp(key, "cpu-affinity-base"))
            g_config.cpu_affinity_base = atoi(val);
        else if (!strcmp(key, "max_command_size"))
            g_config.max_command_size = atoi(val);
        else if (!strcmp(key, "verbose"))
            g_config.verbose = (!strcmp(val, "yes"));
        else if (!strcmp(key, "backend_connect_timeout_ms"))
            g_config.backend_connect_timeout_ms = atoi(val);
        else if (!strcmp(key, "min_normal_connection"))
            g_pool_min[POOL_NORMAL] = atoi(val);
        else if (!strcmp(key, "max_normal_connection"))
            g_pool_max[POOL_NORMAL] = atoi(val);
        else if (!strcmp(key, "min_blocking_connection"))
            g_pool_min[POOL_BLOCKING] = atoi(val);
        else if (!strcmp(key, "max_blocking_connection"))
            g_pool_max[POOL_BLOCKING] = atoi(val);
        else if (!strcmp(key, "min_subscription_connection"))
            g_pool_min[POOL_SUBSCRIPTION] = atoi(val);
        else if (!strcmp(key, "max_subscription_connection"))
            g_pool_max[POOL_SUBSCRIPTION] = atoi(val);
        else if (!strcmp(key, "min_transaction_connection"))
            g_pool_min[POOL_TRANSACTION] = atoi(val);
        else if (!strcmp(key, "max_transaction_connection"))
            g_pool_max[POOL_TRANSACTION] = atoi(val);
        else if (!strcmp(key, "min_acl_connection"))
            g_pool_min[POOL_ACL] = atoi(val);
        else if (!strcmp(key, "max_acl_connection"))
            g_pool_max[POOL_ACL] = atoi(val);
    }
    fclose(f);

    if (g_config.max_connection <= 0) {
        fprintf(stderr, "Warning: max_connection must be positive (got %d); falling back to default %d\n",
                g_config.max_connection, DEFAULT_MAX_CONNECTIONS);
        g_config.max_connection = DEFAULT_MAX_CONNECTIONS;
    }
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
                             int timeout_ms, TlsConn **ssl_out) {
    *ssl_out = NULL;
    int fd = (sa && salen) ? tcp_connect_addr(sa, salen, ip, port, timeout_ms) : tcp_connect_timeout(ip, port, timeout_ms);
    if (fd < 0) return -1;
#ifdef USE_TLS
    if (g_config.tls_backend) {
        *ssl_out = tls_connect_blocking(fd, timeout_ms);
        if (!*ssl_out) {
            close(fd);
            return -1;
        }
    }
#endif
    return fd;
}
