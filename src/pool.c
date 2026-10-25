#include "proxy.h"

/* ── connection pool ────────────────────────────────────────────────── */
static int send_select(int fd, TlsConn *ssl, int db) {
    char cmd[64];
    int n = snprintf(cmd, sizeof(cmd), "*2\r\n$6\r\nSELECT\r\n$%d\r\n%d\r\n", db < 10 ? 1 : db < 100 ? 2 : 3, db);
    if (net_write_all(fd, ssl, cmd, (size_t)n) < 0) return -1;
    char resp[32];
    ssize_t r = net_read(fd, ssl, resp, sizeof(resp) - 1, NULL);
    if (r <= 0) return -1;
    resp[r] = '\0';
    return (resp[0] == '+') ? 0 : -1;
}

static void close_conn_fd(int fd, TlsConn *ssl) {
#ifdef USE_TLS
    tls_free(ssl);
#else
    (void)ssl;
#endif
    close(fd);
}

/* Opens a backend connection for pool p; *ssl_out gets its TLS session
 * (NULL for plain TCP). */
static int pool_new_fd(Worker *w, ConnPool *p, TlsConn **ssl_out) {
    const ClusterNode *node = &w->topo.nodes[p->node_idx];
    /* Short, configurable timeout (not tcp_connect()'s fixed 5s) -- this
     * runs on the worker thread, so a node that's momentarily unreachable
     * (a replica still finishing promotion, a node about to be grace-
     * released) would otherwise stall every client this worker is serving,
     * not just the one triggering the (re)connect. */
    int fd = backend_connect_blocking(node->ip, node->port, &node->sa, node->salen, g_config.backend_connect_timeout_ms,
                                      ssl_out);
    if (fd < 0) return -1;
    if (p->db != 0 && send_select(fd, *ssl_out, p->db) < 0) {
        close_conn_fd(fd, *ssl_out);
        *ssl_out = NULL;
        return -1;
    }
    set_nonblocking(fd);
    if (fd < g_config.max_connection) w->backend_map[fd] = NULL;
    return fd;
}

/* Creates AVAILABLE connections (via pool_new_fd, i.e. against whatever
 * address w->topo currently has for p->node_idx) until the pool reaches
 * `want` or p->max, whichever is smaller, stopping early on the first
 * connect failure -- a still-recovering backend gets picked up again next
 * time this (or the lazy pool_acquire_nb path) runs, rather than being
 * hammered in a tight retry loop. Safe to call on a pool that already has
 * live connections (unlike re-running pool_init, which would wipe them):
 * used both for a brand-new pool's initial warm-up and for topping an
 * existing pool back up after worker_sync_topology() flushes it. */
/* Installs a freshly connected fd as a new connection of pool p (room is
 * guaranteed by the caller) and hands it straight to the longest-waiting
 * client, if any -- otherwise a client that queued up while this pool had
 * zero live connections (e.g. its node just died) would never be woken even
 * once the pool is repopulated, since nothing but pool_release() ever
 * drains wait_queue. Mirrors pool_release()'s own waiter hand-off. */
static void pool_add_conn(Worker *w, ConnPool *p, int fd, TlsConn *ssl, int startup) {
    const ClusterNode *node = &w->topo.nodes[p->node_idx];
    PoolConn *c = &p->conns[p->count];
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->ssl = ssl;
    c->state = CONN_AVAILABLE;
    c->db = p->db;
    c->pool = p;
    if (fd < g_config.max_connection) w->backend_map[fd] = c;
    fd_reset(w, fd);
    fd_watch(w, fd, EL_READABLE);
    if (startup)
        printf("        [%d] fd=%-4d  %s:%d  db=%d\n", p->count, fd, node->ip, node->port, p->db);
    else
        LOG_VERBOSE("[worker %d] [pool:%s] connected fd=%d node=%s:%d (%d/%d)\n", w->thread_id, POOL_NAME[p->type], fd,
                    node->ip, node->port, p->count + 1, p->max);
    p->count++;
    if (p->wait_len > 0) {
        ClientConn *next = p->wait_queue[0];
        memmove(p->wait_queue, p->wait_queue + 1, (size_t)(p->wait_len - 1) * sizeof(ClientConn *));
        p->wait_len--;
        next->waiting_pool = NULL;
        c->state = CONN_IN_USE;
        c->waiting_client = next;
        c->epoch++;
        next->pending_conn = c;
        LOG_VERBOSE("        [%d] fd=%-4d  %s:%d  db=%d  → reassigned to client-fd=%d  (queue=%d)\n", p->count - 1, fd,
                    node->ip, node->port, p->db, next->fd, p->wait_len);
        resume_client_after_conn(w, next, c);
    }
}

/* Synchronously creates AVAILABLE connections until the pool reaches `want`
 * or p->max, stopping at the first failure. Only used for a brand-new pool's
 * warm-up (worker start-up / a newly discovered shard); later growth and
 * reconnects go through pool_connect_async(). */
static void pool_fill_to(Worker *w, ConnPool *p, int want) {
    if (want <= 0) return;
    if (!p->conns) {
        p->conns = calloc((size_t)p->max, sizeof(PoolConn));
        if (!p->conns) return;
    }
    const ClusterNode *node = &w->topo.nodes[p->node_idx];
    while (p->count < want && p->count + p->pending < p->max) {
        TlsConn *ssl;
        int fd = pool_new_fd(w, p, &ssl);
        if (fd < 0) {
            fprintf(stderr, "        [%d] %s:%d FAILED\n", p->count, node->ip, node->port);
            break;
        }
        pool_add_conn(w, p, fd, ssl, 1);
    }
}

/* ── background connects ───────────────────────────────────────────────
 * Connecting (TCP, TLS handshake, SELECT) is blocking, so pool growth after
 * start-up runs on a few connector threads instead of the worker: a slow or
 * unreachable node would otherwise stall every client on the worker for up
 * to backend_connect_timeout_ms. The requesting client waits in the pool's
 * wait_queue, and the finished connection comes back through the worker's
 * wake pipe (pool_drain_connects()). */
#define CONNECTOR_THREADS 2

struct ConnectJob {
    Worker *w;
    ConnPool *p;
    int gen; /* w->topo.node_gen[p->node_idx] at submission */
    char ip[256];
    int port, db;
    struct sockaddr_storage sa; /* resolved by discovery: no DNS in the connector either */
    socklen_t salen;
    int fd;
    TlsConn *ssl;
    ConnectJob *next;
};

static pthread_mutex_t cj_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cj_cv = PTHREAD_COND_INITIALIZER;
static ConnectJob *cj_head, *cj_tail;
static pthread_once_t cj_once = PTHREAD_ONCE_INIT;
static pthread_t cj_tids[CONNECTOR_THREADS];
static int cj_nstarted = 0, cj_stopping = 0;

static void *connector_loop(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&cj_mu);
        while (!cj_head && !cj_stopping) pthread_cond_wait(&cj_cv, &cj_mu);
        if (cj_stopping) {
            pthread_mutex_unlock(&cj_mu);
            break;
        }
        ConnectJob *j = cj_head;
        cj_head = j->next;
        if (!cj_head) cj_tail = NULL;
        pthread_mutex_unlock(&cj_mu);

        j->fd = backend_connect_blocking(j->ip, j->port, &j->sa, j->salen, g_config.backend_connect_timeout_ms, &j->ssl);
        if (j->fd >= 0 && j->db != 0 && send_select(j->fd, j->ssl, j->db) < 0) {
            close_conn_fd(j->fd, j->ssl);
            j->fd = -1;
            j->ssl = NULL;
        }
        if (j->fd >= 0) set_nonblocking(j->fd);

        Worker *w = j->w;
        pthread_mutex_lock(&w->cj_mu);
        j->next = w->cj_done;
        w->cj_done = j;
        pthread_mutex_unlock(&w->cj_mu);
        char b = 'c';
        ssize_t r = write(w->wake_w, &b, 1);
        (void)r;
    }
    return NULL;
}

static void connector_start(void) {
    for (int i = 0; i < CONNECTOR_THREADS; i++)
        if (pthread_create(&cj_tids[cj_nstarted], NULL, connector_loop, NULL) == 0) cj_nstarted++;
}

/* Called by main() after every worker has been joined (so no new jobs, and
 * cj_nstarted -- set under pthread_once by a worker -- is visible). */
void connector_stop(void) {
    pthread_mutex_lock(&cj_mu);
    cj_stopping = 1;
    pthread_cond_broadcast(&cj_cv);
    pthread_mutex_unlock(&cj_mu);
    for (int i = 0; i < cj_nstarted; i++) pthread_join(cj_tids[i], NULL);
    cj_nstarted = 0;
}

/* Queues one background connect for pool p if it has room. */
static void pool_connect_async(Worker *w, ConnPool *p) {
    if (p->count + p->pending >= p->max || w->wake_w < 0) return;
    if (!p->conns && !(p->conns = calloc((size_t)p->max, sizeof(PoolConn)))) return;
    ConnectJob *j = calloc(1, sizeof(*j));
    if (!j) return;
    pthread_once(&cj_once, connector_start);
    const ClusterNode *nd = &w->topo.nodes[p->node_idx];
    j->w = w;
    j->p = p;
    j->gen = w->topo.node_gen[p->node_idx];
    snprintf(j->ip, sizeof(j->ip), "%s", nd->ip);
    j->port = nd->port;
    j->sa = nd->sa;
    j->salen = nd->salen;
    j->db = p->db;
    p->pending++;
    pthread_mutex_lock(&cj_mu);
    if (cj_tail)
        cj_tail->next = j;
    else
        cj_head = j;
    cj_tail = j;
    pthread_cond_signal(&cj_cv);
    pthread_mutex_unlock(&cj_mu);
}

static void pool_fail_all_waiters(Worker *w, ConnPool *p, const char *msg);

/* Worker side: installs connections finished by the connector threads. */
void pool_drain_connects(Worker *w) {
    pthread_mutex_lock(&w->cj_mu);
    ConnectJob *j = w->cj_done;
    w->cj_done = NULL;
    pthread_mutex_unlock(&w->cj_mu);
    while (j) {
        ConnectJob *next = j->next;
        ConnPool *p = j->p;
        p->pending--;
        int idx = p->node_idx;
        int stale = j->gen != w->topo.node_gen[idx] || !w->topo.node_has_slots[idx];
        if (j->fd >= 0 && (stale || j->fd >= g_config.max_connection)) {
            close_conn_fd(j->fd, j->ssl);
            j->fd = -1;
        }
        if (j->fd >= 0) {
            pool_add_conn(w, p, j->fd, j->ssl, 0);
        } else if (stale && w->topo.node_has_slots[idx] && p->wait_len > 0) {
            pool_connect_async(w, p); /* node moved while connecting: retry at the new address */
        } else if (p->count == 0 && p->pending == 0 && p->wait_len > 0) {
            /* Nothing to wait for any more: fail them rather than hang. */
            pool_fail_all_waiters(w, p, "backend connection error");
        }
        free(j);
        j = next;
    }
}

/* Like pool_acquire_nb(), but never connects on the worker thread: with no
 * idle connection it queues a background connect (if the pool has room)
 * and returns NULL, and the caller parks the client with
 * pool_enqueue_waiter() as usual. */
PoolConn *pool_acquire_or_connect(Worker *w, ConnPool *p) {
    for (int i = 0; i < p->count; i++) {
        if (p->conns[i].state == CONN_AVAILABLE) {
            p->conns[i].state = CONN_IN_USE;
            p->conns[i].epoch++;
            return &p->conns[i];
        }
    }
    pool_connect_async(w, p);
    return NULL;
}

/* background: warm up via the connector threads instead of connecting on
 * the worker thread (for shards discovered while serving traffic). */
void pool_init(Worker *w, ConnPool *p, PoolType type, int node_idx, int db, int background) {
    p->type = type;
    p->max = g_pool_max[type];
    p->count = 0;
    p->pending = 0;
    p->conns = NULL;
    p->node_idx = node_idx;
    p->db = db;
    p->el = w->el;
    p->wait_queue = NULL;
    p->wait_len = 0;
    p->wait_cap = 0;
    pthread_mutex_init(&p->lock, NULL);
    int want = g_pool_min[type];
    if (want == 0) {
        printf("      %-14s pool:  0/%d (on-demand)\n", POOL_NAME[type], p->max);
        return;
    }
    if (background) {
        for (int i = 0; i < want; i++) pool_connect_async(w, p);
        return;
    }
    printf("      %-14s pool: (0/%d)\n", POOL_NAME[type], p->max);
    pool_fill_to(w, p, want);
    printf("      %-14s pool: %d/%d connections ready\n", POOL_NAME[type], p->count, p->max);
}

/* Non-blocking acquire: returns NULL if pool is full (caller must enqueue). */
PoolConn *pool_acquire_nb(Worker *w, ConnPool *p) {
    for (int i = 0; i < p->count; i++) {
        if (p->conns[i].state == CONN_AVAILABLE) {
            p->conns[i].state = CONN_IN_USE;
            p->conns[i].epoch++;
            return &p->conns[i];
        }
    }
    /* Synchronous connect: only for callers that can't park the client in
     * wait_queue (see pool_acquire_or_connect() for the rest). */
    if (p->count + p->pending < p->max) {
        if (!p->conns) {
            p->conns = calloc((size_t)p->max, sizeof(PoolConn));
            if (!p->conns) return NULL;
        }
        TlsConn *ssl;
        int fd = pool_new_fd(w, p, &ssl);
        if (fd >= 0) {
            const ClusterNode *node = &w->topo.nodes[p->node_idx];
            PoolConn *c = &p->conns[p->count];
            memset(c, 0, sizeof(*c));
            c->fd = fd;
            c->ssl = ssl;
            c->state = CONN_IN_USE;
            c->db = p->db;
            c->pool = p;
            if (fd < g_config.max_connection) w->backend_map[fd] = c;
            fd_reset(w, fd);
            fd_watch(w, fd, EL_READABLE);
            LOG_VERBOSE("  [%s pool] node [%s:%d] db=%d: new conn fd=%d (%d/%d)\n", POOL_NAME[p->type], node->ip, node->port,
                   p->db, fd, p->count + 1, p->max);
            p->count++;
            return c;
        }
    }
    return NULL;
}

void pool_enqueue_waiter(ConnPool *p, ClientConn *client) {
    if (p->wait_len == p->wait_cap) {
        int nc = p->wait_cap ? p->wait_cap * 2 : 8;
        ClientConn **tmp = realloc(p->wait_queue, (size_t)nc * sizeof(ClientConn *));
        if (!tmp) return;
        p->wait_queue = tmp;
        p->wait_cap = nc;
    }
    p->wait_queue[p->wait_len++] = client;
    client->waiting_pool = p;
}

void pool_remove_waiter(ConnPool *p, ClientConn *client) {
    for (int i = 0; i < p->wait_len; i++) {
        if (p->wait_queue[i] == client) {
            memmove(&p->wait_queue[i], &p->wait_queue[i + 1], (size_t)(p->wait_len - i - 1) * sizeof(ClientConn *));
            p->wait_len--;
            return;
        }
    }
}

/* A pool's node has been confirmed permanently gone (grace period elapsed,
 * nobody else claimed its slots -- see worker_sync_topology()'s
 * !still_owns_slots branch): no future pool_release()/pool_fill_to() will
 * ever be able to service anyone still parked in p->wait_queue, since there
 * is no live or prospective connection left for this pool. Fail every
 * queued waiter with a clear error instead of leaving it hung forever. */
static void pool_fail_all_waiters(Worker *w, ConnPool *p, const char *msg) {
    for (int i = 0; i < p->wait_len; i++) {
        ClientConn *client = p->wait_queue[i];
        client_send_error(w, client, msg);
        client->pending_conn = NULL;
        client->hbuf_len = 0;
        client->pbuf_len = 0;
        client->using_pbuf = 0;
        client->waiting_pool = NULL;
        client->state = CS_READING_HDR;
        fd_watch(w, client->fd, EL_READABLE);
    }
    p->wait_len = 0;
}

void pool_release(Worker *w, PoolConn *c) {
    if (c->discard_on_release) {
        c->discard_on_release = 0;
        /* The underlying node identity moved on while this connection was
         * checked out (see worker_sync_topology()): retire it and connect a
         * replacement at the node's current address in the background --
         * this lets an in-flight failover finish without disrupting the
         * request that held it, and any waiter gets the new connection. */
        ConnPool *p = c->pool;
        pool_destroy_conn(w, c);
        if (p->wait_len > 0 || p->count + p->pending < g_pool_min[p->type]) pool_connect_async(w, p);
        return;
    }

    ConnPool *p = c->pool;
    const ClusterNode *nd = &w->topo.nodes[p->node_idx];
    if (p->wait_len > 0) {
        ClientConn *next = p->wait_queue[0];
        memmove(p->wait_queue, p->wait_queue + 1, (size_t)(p->wait_len - 1) * sizeof(ClientConn *));
        p->wait_len--;
        LOG_VERBOSE("[worker %d] [pool:%s] release  fd=%-4d  node=%s:%d  db=%d  → reassigned to client-fd=%d  (queue=%d)\n",
               w->thread_id, POOL_NAME[p->type], c->fd, nd->ip, nd->port, c->db, next->fd, p->wait_len);
        c->waiting_client = next;
        c->epoch++;
        next->pending_conn = c;
        resume_client_after_conn(w, next, c);
    } else {
        c->state = CONN_AVAILABLE;
        c->waiting_client = NULL;
        int avail = 0;
        if (g_config.verbose)
            for (int i = 0; i < p->count; i++)
                if (p->conns[i].state == CONN_AVAILABLE) avail++;
        LOG_VERBOSE("[worker %d] [pool:%s] release  fd=%-4d  node=%s:%d  db=%d  → available=%d  max=%d  waiting=%d\n",
               w->thread_id, POOL_NAME[p->type], c->fd, nd->ip, nd->port, c->db, avail, p->max, p->wait_len);
    }
}

/* Close a pool connection and remove it from the pool array. */
void pool_destroy_conn(Worker *w, PoolConn *c) {
    ConnPool *p = c->pool;
    const ClusterNode *nd = &w->topo.nodes[p->node_idx];

    LOG_VERBOSE("[worker %d] [pool:%s] destroy  fd=%-4d  node=%s:%d  db=%d  (pool count: %d→%d)\n", w->thread_id,
           POOL_NAME[p->type], c->fd, nd->ip, nd->port, c->db, p->count, p->count - 1);

    fd_unwatch(w, c->fd, EL_READABLE | EL_WRITABLE);
    if (c->fd >= 0) {
        if (c->fd < g_config.max_connection) w->backend_map[c->fd] = NULL;
        close_conn_fd(c->fd, c->ssl);
        c->ssl = NULL;
    }

    free(c->wbuf);
    c->wbuf = NULL;
    free(c->rbuf);
    c->rbuf = NULL;
    free(c->resp3_deferred_cmd);
    c->resp3_deferred_cmd = NULL;

    int idx = (int)(c - p->conns);
    p->count--;
    if (idx < p->count) {
        p->conns[idx] = p->conns[p->count];
        PoolConn *moved = &p->conns[idx];
        if (moved->fd >= 0 && moved->fd < g_config.max_connection) w->backend_map[moved->fd] = moved;
        if (moved->waiting_client) {
            /* waiting_client means pending_conn ownership everywhere except
             * the pub/sub path (sub_conn ownership) and the ACL path
             * (acl_conns[node_idx] ownership, which stays set for the whole
             * lifetime of the dedicated connection, not just one in-flight
             * request -- see src/acl.c). */
            if (p->type == POOL_SUBSCRIPTION) {
                moved->waiting_client->sub_conn = moved;
            } else if (p->type == POOL_ACL) {
                /* moved used to live at &p->conns[p->count]. A HELLO AUTH
                 * login probe is owned via hello_auth_conn, not acl_conns[]
                 * (which may still hold the client's previous identity's
                 * conn for this node -- see hello.c). */
                ClientConn *wc = moved->waiting_client;
                if (wc->hello_auth_conn == &p->conns[p->count]) {
                    wc->hello_auth_conn = moved;
                } else {
                    wc->acl_conns[p->node_idx] = moved;
                    if (wc->pending_conn) wc->pending_conn = moved;
                }
            } else {
                moved->waiting_client->pending_conn = moved;
            }
        }
        if (moved->fanout_sub) moved->fanout_sub->conn = moved;
    }
    memset(&p->conns[p->count], 0, sizeof(PoolConn));
}

/* ── db group ───────────────────────────────────────────────────────── */
static DbGroup *db_group_create(Worker *w, int db) {
    if (w->db_group_count == w->db_group_cap) {
        int nc = w->db_group_cap ? w->db_group_cap * 2 : 4;
        DbGroup *tmp = realloc(w->db_groups, (size_t)nc * sizeof(DbGroup));
        if (!tmp) {
            perror("realloc");
            return NULL;
        }
        w->db_groups = tmp;
        w->db_group_cap = nc;
    }
    DbGroup *g = &w->db_groups[w->db_group_count];
    g->db = db;
    /* Fixed at MAX_NODES regardless of the node count seen at creation time,
     * so a shard discovered by a later worker_sync_topology() has a slot
     * ready to use instead of running off the end of this array. */
    g->node_pools = calloc(MAX_NODES, sizeof(NodePools));
    if (!g->node_pools) {
        perror("calloc");
        return NULL;
    }
    printf("  [worker %d] creating db%d group (%d node(s))\n", w->thread_id, db, w->topo.node_count);
    int total = 0;
    for (int ni = 0; ni < MAX_NODES; ni++) {
        NodePools *np = &g->node_pools[ni];
        if (ni >= w->topo.node_count) {
            np->node_idx = -1;
            np->gen = -1;
            continue;
        }
        np->node_idx = ni;
        printf("    node [%s:%d]\n", w->topo.nodes[ni].ip, w->topo.nodes[ni].port);
        for (int pt = 0; pt < POOL_TYPE_COUNT; pt++) {
            pool_init(w, &np->pools[pt], (PoolType)pt, ni, db, 0);
            total += np->pools[pt].count;
        }
        np->gen = w->topo.node_gen[ni];
    }
    printf("  [worker %d] db%d ready — %d connections established\n\n", w->thread_id, db, total);
    w->db_group_count++;
    return g;
}

DbGroup *db_group_get(Worker *w, int db) {
    pthread_mutex_lock(&w->db_lock);
    for (int i = 0; i < w->db_group_count; i++)
        if (w->db_groups[i].db == db) {
            pthread_mutex_unlock(&w->db_lock);
            return &w->db_groups[i];
        }
    DbGroup *g = db_group_create(w, db);
    pthread_mutex_unlock(&w->db_lock);
    return g;
}

/* ── topology sync ──────────────────────────────────────────────────── */
/* Called once per worker event-loop wakeup whenever g_topology_version has
 * moved since this worker last looked (see the check in worker_thread()).
 * Refreshes this worker's private snapshot, then reconciles every db_group's
 * NodePools against it: newly-live indices get their pools warmed up to
 * `min`, and indices whose node identity moved on (failover / grace-period
 * eviction, both signalled by a generation bump) get their idle connections
 * flushed and their in-use ones marked to be reconnected on release. */
void worker_sync_topology(Worker *w) {
    pthread_rwlock_rdlock(&g_topology_lock);
    memcpy(w->topo.nodes, g_nodes, sizeof(w->topo.nodes));
    memcpy(w->topo.node_gen, g_node_gen, sizeof(w->topo.node_gen));
    memcpy(w->topo.node_has_slots, g_node_has_slots, sizeof(w->topo.node_has_slots));
    memcpy(w->topo.slot_map, g_slot_map, sizeof(w->topo.slot_map));
    w->topo.node_count = g_node_count;
    w->topo.version = atomic_load_explicit(&g_topology_version, memory_order_acquire);
    pthread_rwlock_unlock(&g_topology_lock);

    for (int gi = 0; gi < w->db_group_count; gi++) {
        DbGroup *grp = &w->db_groups[gi];
        for (int idx = 0; idx < w->topo.node_count; idx++) {
            NodePools *np = &grp->node_pools[idx];
            if (np->gen == -1) {
                np->node_idx = idx;
                printf("  [worker %d] db%d: new shard [%d] %s:%d discovered, warming pools\n", w->thread_id, grp->db,
                       idx, w->topo.nodes[idx].ip, w->topo.nodes[idx].port);
                for (int pt = 0; pt < POOL_TYPE_COUNT; pt++) pool_init(w, &np->pools[pt], (PoolType)pt, idx, grp->db, 1);
                np->gen = w->topo.node_gen[idx];
            } else if (np->gen != w->topo.node_gen[idx]) {
                /* Whether this gen bump means "a new/promoted node took over
                 * these slots" (scenario 3 -- w->topo.nodes[idx] now points
                 * at it, worth reconnecting to) or "grace period expired
                 * with nobody claiming these slots" (scenario 2 -- idx owns
                 * nothing right now, reconnecting would just hammer a dead
                 * address) hinges entirely on node_has_slots[idx]. */
                int still_owns_slots = w->topo.node_has_slots[idx];
                printf("  [worker %d] db%d: shard [%d] identity changed (now %s:%d), flushing pools%s\n", w->thread_id,
                       grp->db, idx, w->topo.nodes[idx].ip, w->topo.nodes[idx].port,
                       still_owns_slots ? "" : " (no longer owns any slot, not reconnecting)");
                for (int pt = 0; pt < POOL_TYPE_COUNT; pt++) {
                    ConnPool *p = &np->pools[pt];
                    /* Iterate back-to-front: pool_destroy_conn compacts the
                     * array by swapping the last live element into the
                     * removed slot, so walking backwards visits every
                     * original element exactly once despite the array
                     * shrinking underneath the loop. */
                    for (int i = p->count - 1; i >= 0; i--) {
                        PoolConn *c = &p->conns[i];
                        if (c->state == CONN_AVAILABLE) {
                            pool_destroy_conn(w, c);
                            continue;
                        }
                        if (!still_owns_slots && c->fanout_sub) {
                            /* This node is confirmed gone for good and nothing
                             * will ever call pool_release()/handle_fanout_sub_readable()
                             * on this conn again (no epoll event may ever fire,
                             * e.g. a silent network partition rather than a
                             * clean kill/RST) -- complete the sub as an error
                             * right now instead of leaving its FanoutCtx
                             * waiting forever. */
                            FanoutSub *sub = c->fanout_sub;
                            FanoutCtx *ctx = sub->ctx;
                            sub->error = 1;
                            sub->done = 1;
                            c->fanout_sub = NULL;
                            pool_destroy_conn(w, c);
                            sub->conn = NULL;
                            ctx->had_error = 1;
                            ctx->ndone++;
                            if (ctx->ndone == ctx->nsubs) fanout_aggregate_and_reply(w, ctx);
                        } else if (!still_owns_slots && c->waiting_client) {
                            /* Symmetric case for an already-dispatched single-key
                             * request: same "nobody will ever release this"
                             * reasoning as above. */
                            client_recover_after_backend_error(w, c->waiting_client, c, "backend node unavailable");
                        } else {
                            c->discard_on_release = 1;
                        }
                    }
                    /* Reconnect against the new address right away instead
                     * of waiting for the next client command to lazily grow
                     * the pool -- this is what lets an in-progress failover
                     * (scenario 3) finish without a client-visible gap. Skip
                     * it when the index no longer owns any slot at all
                     * (scenario 2): there is nothing live to reconnect to. */
                    if (still_owns_slots) {
                        int want = g_pool_min[pt] > 0 ? g_pool_min[pt] : (p->wait_len > 0);
                        while (p->count + p->pending < want && p->count + p->pending < p->max)
                            pool_connect_async(w, p);
                    }
                    /* Scenario 2: this node is gone for good and nothing will
                     * ever call pool_release()/pool_fill_to() on this pool
                     * again, so anyone already parked in wait_queue (e.g. a
                     * client whose backend connection died before the node
                     * was confirmed unreachable) would otherwise hang
                     * forever. Fail them now instead. */
                    else if (p->wait_len > 0)
                        pool_fail_all_waiters(w, p, "backend node unavailable");
                }
                mux_node_changed(w, np, still_owns_slots);
                np->gen = w->topo.node_gen[idx];
            }
        }
    }
    w->topology_version_seen = w->topo.version;
}
