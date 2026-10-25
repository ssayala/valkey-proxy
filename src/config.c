#include "proxy.h"

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
    g_config.tls_ktls = 1;
    g_config.max_multikey_payload = 64 * 1024 * 1024;
    g_config.max_connection = DEFAULT_MAX_CONNECTIONS;
    g_config.cluster_refresh_interval_ms = 0; /* 0 = periodic refresh disabled */
    g_config.cluster_node_fail_grace_ms = 10000;
    g_config.backend_connect_timeout_ms = 1000;
    g_config.max_command_size = 512 * 1024 * 1024;
    char line[512], key[64], val[448];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63s %447s", key, val) != 2) continue;
        if (!strcmp(key, "server-ip"))
            snprintf(g_config.server_ip, 64, "%.63s", val);
        else if (!strcmp(key, "server-port"))
            g_config.server_port = atoi(val);
        else if (!strcmp(key, "bind"))
            snprintf(g_config.bind_ip, 64, "%.63s", val);
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

/* timeout_ms bounds only the "still connecting" wait (TCP handshake in
 * flight); ECONNREFUSED and similar immediate errors return right away
 * regardless of it. Kept separate from tcp_connect() below because the
 * right value differs sharply by caller: fetch_cluster_nodes()'s one-shot
 * startup discovery (before any thread exists to block) can afford a
 * generous wait, but pool_new_fd() (worker thread, reconnecting to a
 * possibly still-booting promoted replica) and the periodic topology
 * refresh (its own thread, but retried every cycle) both want to fail fast
 * instead of tying up a thread for seconds on end. */
int tcp_connect_timeout(const char *ip, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(fd, (struct sockaddr *)&a, sizeof(a));
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

int create_tcp_listener(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    set_nonblocking(fd);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (ip[0])
        inet_pton(AF_INET, ip, &a.sin_addr);
    else
        a.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 128) < 0) {
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
    set_nonblocking(fd);
    unlink(path);
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%.107s", path);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        perror("bind(unix)");
        close(fd);
        return -1;
    }
    if (listen(fd, 128) < 0) {
        perror("listen(unix)");
        close(fd);
        return -1;
    }
    return fd;
}

/* Blocking connect (+ TLS handshake when tls-backend is on) to a backend
 * node; returns a blocking fd, or -1. */
int backend_connect_blocking(const char *ip, int port, int timeout_ms, TlsConn **ssl_out) {
    *ssl_out = NULL;
    int fd = tcp_connect_timeout(ip, port, timeout_ms);
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
