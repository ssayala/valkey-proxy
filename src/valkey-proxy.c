#ifdef __linux__
#define _GNU_SOURCE /* pthread_setaffinity_np, CPU_SET */
#endif
#include "proxy.h"
#include <sys/resource.h>
#include <netinet/tcp.h>
#include <signal.h>

/* ── global definitions ─────────────────────────────────────────────── */
/* All on-demand: ordinary traffic uses the shared muxes (mux.c), and pools
 * grow in the background when the legacy paths do need them (pool.c). */
int g_pool_min[POOL_TYPE_COUNT] = {0, 0, 0, 0, 0};
/* Blocking, subscription and ACL connections are each held by one client
 * for as long as it blocks / stays subscribed / stays logged in, so their
 * caps bound concurrent such clients per node per worker -- keep them high. */
int g_pool_max[POOL_TYPE_COUNT] = {20, 1000, 1000, 10, 1000};

Config g_config;
ClusterNode g_nodes[MAX_NODES];
int g_node_count = 0;
int g_slot_map[CLUSTER_SLOTS];
int g_node_gen[MAX_NODES];
int g_node_has_slots[MAX_NODES];
atomic_int g_topology_version = 0;
atomic_int g_backend_resp3_active = 0;
atomic_llong g_next_client_id = 0;
atomic_int g_shutdown = 0;
atomic_int g_stop = 0;
pthread_rwlock_t g_topology_lock = PTHREAD_RWLOCK_INITIALIZER;
Worker g_workers[MAX_WORKERS];
int g_tcp_fd = -1, g_unix_fd = -1;
int g_listen_per_worker = 0;
#ifdef USE_TLS
SSL_CTX *g_ssl_ctx = NULL;
#endif

/* ── resource limits ───────────────────────────────────────────────── */
/* g_config.max_connection only caps how many fds the proxy's own bookkeeping
 * arrays can index; the OS-level RLIMIT_NOFILE soft limit is what actually
 * determines whether accept()/connect() can hand out fds that high. Raise
 * it to cover max_connection plus a small margin for stdio/log fds, falling
 * back to whatever the hard limit allows. */
static void adjust_open_files_limit(void) {
    rlim_t want = (rlim_t)g_config.max_connection + 64;
    struct rlimit lim;
    if (getrlimit(RLIMIT_NOFILE, &lim) < 0) {
        perror("getrlimit(RLIMIT_NOFILE)");
        return;
    }
    if (lim.rlim_cur >= want) return;

    rlim_t old_soft = lim.rlim_cur;
    lim.rlim_cur = (lim.rlim_max == RLIM_INFINITY || lim.rlim_max > want) ? want : lim.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &lim) < 0 || lim.rlim_cur < want) {
        fprintf(stderr,
                "Warning: could not raise RLIMIT_NOFILE to %llu (stuck at %llu); "
                "effective connection capacity is reduced accordingly, since "
                "client and backend connections share this fd budget. Raise the "
                "'nofile' limit for this process/user to reach max_connection=%d.\n",
                (unsigned long long)want, (unsigned long long)lim.rlim_cur, g_config.max_connection);
    } else {
        printf("Raised RLIMIT_NOFILE: %llu -> %llu (max_connection=%d)\n", (unsigned long long)old_soft,
               (unsigned long long)lim.rlim_cur, g_config.max_connection);
    }
}

/* Formats sa as "ip:port" into out (size cap); returns 1 on success
 * (AF_INET/AF_INET6), 0 otherwise (e.g. AF_UNIX, whose sockaddr carries no
 * usable address -- caller falls back to the configured unix socket path). */
static int format_sockaddr(struct sockaddr_storage *sa, char *out, int cap) {
    if (sa->ss_family == AF_INET) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        snprintf(out, (size_t)cap, "%s:%d", ip, ntohs(sin->sin_port));
        return 1;
    }
    if (sa->ss_family == AF_INET6) {
        char ip[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        snprintf(out, (size_t)cap, "%s:%d", ip, ntohs(sin6->sin6_port));
        return 1;
    }
    return 0;
}

const char *client_laddr(ClientConn *client) {
    if (!client->laddr[0]) {
        struct sockaddr_storage lsa;
        socklen_t lsalen = sizeof(lsa);
        if (getsockname(client->fd, (struct sockaddr *)&lsa, &lsalen) != 0 ||
            !format_sockaddr(&lsa, client->laddr, sizeof(client->laddr)))
            snprintf(client->laddr, sizeof(client->laddr), "%s:0", g_config.unix_socket_path);
    }
    return client->laddr;
}

/* ── accept ─────────────────────────────────────────────────────────── */
static void do_accept(Worker *w, int listen_fd) {
    /* listen_fd is registered edge-triggered (EPOLLET): a single readiness
     * notification can represent multiple queued connections, so every one
     * of them must be drained here or the leftover ones never get another
     * edge and sit in the kernel backlog forever. */
    for (;;) {
        struct sockaddr_storage sa;
        socklen_t salen = sizeof(sa);
#ifdef __linux__
        int fd = accept4(listen_fd, (struct sockaddr *)&sa, &salen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        int fd = accept(listen_fd, (struct sockaddr *)&sa, &salen);
#endif
        if (fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("accept");
            return;
        }
        int total = 0;
        for (int i = 0; i < g_config.worker_thread_no && i < MAX_WORKERS; i++)
            total += atomic_load_explicit(&g_workers[i].nclients, memory_order_relaxed);
        if (fd >= g_config.max_connection || total >= g_config.maxclients) {
            /* Tell the client why, as Valkey does, instead of a bare close. */
            static const char FULL[] = "-ERR max number of clients reached\r\n";
            ssize_t wr = write(fd, FULL, sizeof(FULL) - 1);
            (void)wr;
            close(fd);
            continue;
        }
#ifndef __linux__
        set_nonblocking(fd);
#endif
        if (sa.ss_family == AF_INET || sa.ss_family == AF_INET6) {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            set_tcp_keepalive(fd);
        }
        fd_reset(w, fd);

        ClientConn *client = calloc(1, sizeof(ClientConn));
        if (!client) {
            close(fd);
            continue;
        }
        client->fd = fd;
        client->db = g_config.db;
        client->state = CS_READING_HDR;
        client->resp = 2;
        client->id = atomic_fetch_add(&g_next_client_id, 1) + 1;
        client->connect_time = client->last_interaction = time(NULL);
        client->multi_count = -1;

        if (!format_sockaddr(&sa, client->addr, sizeof(client->addr)))
            snprintf(client->addr, sizeof(client->addr), "%s:0", g_config.unix_socket_path);


#ifdef USE_TLS
        /* TCP clients only (a local unix socket stays plaintext). The
         * handshake runs non-blocking from the event loop, driven by
         * handle_client_readable()/writable() via client_tls_continue(). */
        if (g_config.tls_enabled && listen_fd != g_unix_fd) { /* g_ssl_ctx: only under tls.c's lock */
            client->ssl = tls_new(fd, 1, NULL);
            if (!client->ssl) {
                close(fd);
                free(client);
                continue;
            }
            client->tls_hs = 1;
        }
#endif

        if (sa.ss_family == AF_INET || sa.ss_family == AF_INET6) {
            LOG_VERBOSE("[worker %d] client connected: %s  fd=%d%s\n", w->thread_id, client->addr, fd,
                   g_config.tls_enabled ? "  (TLS)" : "");
        } else {
            LOG_VERBOSE("[worker %d] client connected: unix socket  fd=%d\n", w->thread_id, fd);
        }
        w->client_map[fd] = client;
        atomic_fetch_add(&w->nclients, 1);
        fd_watch(w, fd, EL_READABLE);
    }
}

/* ── event dispatch ─────────────────────────────────────────────────── */
void worker_dispatch_events(Worker *w, int n) {
    for (int i = 0; i < n; i++) {
        int fd = w->el->fired[i].fd;
        int mask = w->el->fired[i].mask;
        if (fd == w->listen_fd || fd == g_unix_fd) {
            do_accept(w, fd);
            continue;
        }
        if (fd == w->wake_r) {
            /* Just a nudge -- the actual sync already ran above as soon
             * as el_poll returned. Drain so the (edge-triggered) pipe
             * doesn't accumulate unread bytes across many wake-ups. */
            char drain[256];
            while (read(fd, drain, sizeof(drain)) > 0) {}
            pool_drain_connects(w);
            continue;
        }
        if (fd < 0 || fd >= g_config.max_connection) continue;
        if (w->client_map[fd]) {
            ClientConn *cl = w->client_map[fd];
            if (mask & EL_HANGUP) cl->peer_closed = 1;
            if (mask & EL_READABLE) handle_client_readable(w, cl);
            if (cl == w->client_map[fd] && (mask & EL_WRITABLE)) handle_client_writable(w, cl);
        } else if (w->backend_map[fd]) {
            PoolConn *pc = w->backend_map[fd];
            uint32_t epoch = pc->epoch;
            if (mask & EL_WRITABLE) handle_backend_writable(w, pc);
            /* pc==backend_map[fd] catches destruction/replacement; epoch
             * catches an in-place hand-off to a new owner (pool_release's
             * waiter reassignment) -- either way this fd's PoolConn is no
             * longer the one this event was originally reported for. */
            if (pc == w->backend_map[fd] && pc->epoch == epoch && (mask & EL_READABLE))
                handle_backend_readable(w, pc);
        } else if (w->mux_map[fd]) {
            MuxConn *m = w->mux_map[fd];
            if (mask & EL_HANGUP) m->peer_closed = 1;
            if (mask & EL_WRITABLE) handle_mux_writable(w, m);
            if (m == w->mux_map[fd] && (mask & EL_READABLE)) handle_mux_readable(w, m);
        }
    }
}

/* ── worker thread ──────────────────────────────────────────────────── */
static void *worker_thread(void *arg) {
    Worker *w = (Worker *)arg;
    w->el = el_create(g_config.max_connection);
    w->db_groups = NULL;
    w->db_group_count = 0;
    w->db_group_cap = 0;
    w->client_map = calloc((size_t)g_config.max_connection, sizeof(*w->client_map));
    w->backend_map = calloc((size_t)g_config.max_connection, sizeof(*w->backend_map));
    w->fd_mask = calloc((size_t)g_config.max_connection, sizeof(*w->fd_mask));
    w->mux_map = calloc((size_t)g_config.max_connection, sizeof(*w->mux_map));
    if (!w->client_map || !w->backend_map || !w->fd_mask || !w->mux_map) {
        fprintf(stderr, "out of memory allocating connection tables (max_connection=%d)\n", g_config.max_connection);
        return NULL;
    }
    pthread_mutex_init(&w->db_lock, NULL);
    pthread_mutex_init(&w->cj_mu, NULL);
    if (!w->el) {
        fprintf(stderr, "el_create failed\n");
        return NULL;
    }

#ifdef __linux__
    if (g_config.worker_cpu_affinity) {
        cpu_set_t set;
        CPU_ZERO(&set);
        int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
        CPU_SET((g_config.cpu_affinity_base + w->thread_id) % (ncpu > 0 ? ncpu : 1), &set);
        if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0)
            fprintf(stderr, "[worker %d] could not set CPU affinity\n", w->thread_id);
    }
#endif
    if (w->listen_fd >= 0) fd_watch(w, w->listen_fd, EL_READABLE);
    if (g_unix_fd >= 0) fd_watch(w, g_unix_fd, EL_READABLE);

    /* Self-pipe so the topology refresh thread can pull this worker straight
     * out of el_poll(-1) the moment it publishes a change, instead of this
     * worker only noticing on its next unrelated client/backend event (see
     * wake_all_workers() in cluster.c). */
    if (w->wake_r >= 0) fd_watch(w, w->wake_r, EL_READABLE); /* pipe created by main() */

    /* Seed this worker's topology snapshot from the global state before the
     * first db_group_create() reads it (fetch_cluster_nodes() has already
     * populated the globals by the time worker threads are spawned -- see
     * main()). No lock needed here: at this point the refresh thread may
     * already be running, but pthread_create()'s happens-before guarantee
     * plus the fact that a torn read here only means this worker starts
     * from a topology that's at most one refresh cycle stale (it'll pick up
     * the rest on its first worker_sync_topology() call) makes a plain
     * rdlock'd copy sufficient. */
    pthread_rwlock_rdlock(&g_topology_lock);
    memcpy(w->topo.nodes, g_nodes, sizeof(w->topo.nodes));
    memcpy(w->topo.node_gen, g_node_gen, sizeof(w->topo.node_gen));
    memcpy(w->topo.node_has_slots, g_node_has_slots, sizeof(w->topo.node_has_slots));
    memcpy(w->topo.slot_map, g_slot_map, sizeof(w->topo.slot_map));
    w->topo.node_count = g_node_count;
    w->topo.version = atomic_load_explicit(&g_topology_version, memory_order_acquire);
    pthread_rwlock_unlock(&g_topology_lock);
    w->topology_version_seen = w->topo.version;

    db_group_get(w, g_config.db);

    w->last_sweep = time(NULL);
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        int n = el_poll(w->el, worker_has_ready_backlog(w) ? 0 : worker_sweep_interval_ms(w));
        if (n < 0) break;
        w->now = time(NULL);
        if (w->topology_version_seen != topology_version_load()) worker_sync_topology(w);
        worker_dispatch_events(w, n);
        mux_check_connect_timeouts(w);
        worker_after_events(w);
        worker_sweep_clients(w);
        if (atomic_load_explicit(&g_shutdown, memory_order_relaxed)) worker_drain(w);
    }
    return NULL;
}

/* ── main ───────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    const char *conf_path = argc > 1 ? argv[1] : "proxy.conf";
    setbuf(stdout, NULL);

    /* A write() to a backend/client socket whose peer already sent RST (e.g.
     * the old primary being demoted/killed during a cluster failover) raises
     * SIGPIPE; left at its default disposition that kills the whole process,
     * dropping every client on every worker thread at once. Ignoring it here
     * makes such a write just fail with -1/EPIPE, which every write() call
     * site already handles. */
    signal(SIGPIPE, SIG_IGN);

    /* SIGTERM/SIGINT are taken synchronously by main() (sigwait below), so
     * block them before any thread exists -- every thread inherits this. */
    sigset_t stopsigs;
    sigemptyset(&stopsigs);
    sigaddset(&stopsigs, SIGTERM);
    sigaddset(&stopsigs, SIGINT);
    sigaddset(&stopsigs, SIGHUP); /* reload TLS certificates */
    pthread_sigmask(SIG_BLOCK, &stopsigs, NULL);

    parse_conf(conf_path);
    cmd_info_init();
    adjust_open_files_limit();

    memset(g_slot_map, -1, sizeof(g_slot_map));

    printf("Event loop backend : %s\n", el_backend_name());
    printf("Config: server=%s:%d  bind=%s:%d  workers=%d  default-db=%d\n", g_config.server_ip, g_config.server_port,
           g_config.bind_ip, g_config.proxy_port, g_config.worker_thread_no, g_config.db);
    printf("Pool sizes (min/max): normal=%d/%d  blocking=%d/%d"
           "  subscription=%d/%d  transaction=%d/%d  acl=%d/%d\n\n",
           g_pool_min[POOL_NORMAL], g_pool_max[POOL_NORMAL], g_pool_min[POOL_BLOCKING], g_pool_max[POOL_BLOCKING],
           g_pool_min[POOL_SUBSCRIPTION], g_pool_max[POOL_SUBSCRIPTION], g_pool_min[POOL_TRANSACTION],
           g_pool_max[POOL_TRANSACTION], g_pool_min[POOL_ACL], g_pool_max[POOL_ACL]);

#ifdef USE_TLS
    if (g_config.tls_enabled && init_tls() < 0) exit(1);
    if (g_config.tls_backend && init_backend_tls() < 0) exit(1);
#else
    if (g_config.tls_enabled || g_config.tls_backend) {
        fprintf(stderr, "TLS configured but this build has no TLS support (built with NO_TLS=1)\n");
        exit(1);
    }
#endif

    /* Must be set before the refresh thread can possibly start signalling
     * workers (see wake_all_workers() in cluster.c) -- each worker's real
     * wake_w isn't ready until its own worker_thread() runs, which happens
     * after this point, so -1 here is what tells wake_all_workers() to skip
     * a worker that isn't listening yet instead of writing to fd 0. */
    for (int i = 0; i < MAX_WORKERS; i++) g_workers[i].wake_r = g_workers[i].wake_w = -1;

    int nw = g_config.worker_thread_no;
    if (nw < 1) nw = 1;
    if (nw > MAX_WORKERS) nw = MAX_WORKERS;
    /* Each worker's wake pipe exists before any thread that writes to it
     * (refresh thread, connector threads, main at shutdown) can start. */
    for (int i = 0; i < nw; i++) {
        int wakefds[2];
        if (pipe(wakefds) != 0) {
            perror("pipe(wake)");
            exit(1);
        }
        set_nonblocking(wakefds[0]);
        set_nonblocking(wakefds[1]);
        g_workers[i].wake_r = wakefds[0];
        g_workers[i].wake_w = wakefds[1];
    }

    fetch_cluster_nodes();
    topology_start_refresh_thread();

    /* Linux: one SO_REUSEPORT listener per worker, all bound before any
     * worker starts accepting, so the kernel spreads new connections evenly
     * instead of every worker racing on one shared socket (whichever wakes
     * first wins, which left some workers with half the load of others).
     * Elsewhere SO_REUSEPORT doesn't load-balance, so share one socket. */
#ifdef __linux__
    int per_worker = 1;
#else
    int per_worker = 0;
#endif
    for (int i = 0; i < nw; i++) {
        if (i == 0 || per_worker) {
            g_workers[i].listen_fd = create_tcp_listener(g_config.bind_ip, g_config.proxy_port, per_worker);
            if (g_workers[i].listen_fd < 0) exit(1);
        } else {
            g_workers[i].listen_fd = g_workers[0].listen_fd;
        }
    }
    g_tcp_fd = g_workers[0].listen_fd;
    g_listen_per_worker = per_worker;
    printf("Listening on %s:%d (TCP%s)\n", g_config.bind_ip, g_config.proxy_port,
           per_worker && nw > 1 ? ", one SO_REUSEPORT socket per worker" : "");

    if (g_config.unix_socket_path[0]) {
        g_unix_fd = create_unix_listener(g_config.unix_socket_path);
        if (g_unix_fd < 0) exit(1);
        printf("Listening on %s (Unix socket)\n", g_config.unix_socket_path);
    }
    printf("\n");

    printf("Starting %d worker thread(s)...\n\n", nw);

    for (int i = 0; i < nw; i++) {
        g_workers[i].thread_id = i;
        pthread_create(&g_workers[i].tid, NULL, worker_thread, &g_workers[i]);
    }
    /* Graceful shutdown (e.g. a Kubernetes pod stopping): on SIGTERM stop
     * accepting, let every client finish what's in flight, close clients as
     * they go idle, and exit once none are left -- or after
     * shutdown-timeout seconds, or on a second signal. */
    /* Until told to stop: SIGHUP reloads the TLS certificates, and with
     * tls-auto-reload the files are checked every few seconds (Kubernetes
     * secret rotation replaces them in place). */
    int sig;
    for (;;) {
        struct timespec every = {5, 0};
        sig = sigtimedwait(&stopsigs, NULL, &every);
        if (sig == SIGTERM || sig == SIGINT) break;
#ifdef USE_TLS
        if (g_config.tls_enabled || g_config.tls_backend) {
            if (sig == SIGHUP) {
                printf("SIGHUP: reloading TLS certificates\n");
                tls_reload();
            } else if (g_config.tls_auto_reload && tls_files_changed()) {
                printf("TLS certificate files changed: reloading\n");
                tls_reload();
            }
        }
#endif
    }
    printf("Received %s: draining clients (up to %ds)...\n", sig == SIGTERM ? "SIGTERM" : "SIGINT",
           g_config.shutdown_timeout);
    atomic_store(&g_shutdown, 1);
    /* No new unix-socket clients from here on (the listener itself stays
     * open until exit: workers still compare fds against it). */
    if (g_config.unix_socket_path[0]) unlink(g_config.unix_socket_path);
    for (int i = 0; i < nw; i++) {
        char b = 's';
        if (g_workers[i].wake_w >= 0 && write(g_workers[i].wake_w, &b, 1) < 0) {}
    }
    struct timespec tick = {0, 100 * 1000000L};
    for (int waited_ms = 0;; waited_ms += 100) {
        int left = 0;
        for (int i = 0; i < nw; i++) left += atomic_load(&g_workers[i].nclients);
        if (left == 0) break;
        if (waited_ms >= g_config.shutdown_timeout * 1000) {
            printf("Shutdown timeout: closing %d remaining client(s)\n", left);
            break;
        }
        int s2 = sigtimedwait(&stopsigs, NULL, &tick);
        if (s2 == SIGTERM || s2 == SIGINT) {
            printf("Second signal: exiting now (%d client(s) still connected)\n", left);
            break;
        }
    }
    /* Stop every thread before returning: exit() runs OpenSSL's cleanup,
     * which must not race a thread still inside OpenSSL. */
    atomic_store(&g_stop, 1);
    for (int i = 0; i < nw; i++) {
        char b = 'x';
        if (write(g_workers[i].wake_w, &b, 1) < 0) {}
    }
    for (int i = 0; i < nw; i++) pthread_join(g_workers[i].tid, NULL);
    topology_stop_refresh_thread();
    connector_stop();
    if (g_config.unix_socket_path[0]) unlink(g_config.unix_socket_path);
    printf("Bye.\n");
    return 0;
}
