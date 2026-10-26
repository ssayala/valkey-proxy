#include "proxy.h"
#include <netinet/tcp.h>
#include <stddef.h>

/* ── pipelined fast path ────────────────────────────────────────────────
 *
 * Plain single-key commands (GET/SET/HSET/INCR/...: see cmd_info()->fast)
 * from every client on a worker are written, back to back, onto one shared
 * connection per (db, node, RESP version) -- a MuxConn -- instead of each
 * command checking out a pool connection of its own for a full round trip.
 * The backend answers in order, so a FIFO of in-flight Reqs is enough to
 * route each reply back; each client additionally keeps its own Reqs in
 * command order so pipelined commands that fan out to different shards are
 * still answered in the order they were sent.
 *
 * Output is batched per event-loop iteration: commands are appended to
 * mux->obuf and replies to client->wbuf, and both are written once in
 * worker_after_events() -- one write() per socket per iteration rather than
 * one per command.
 *
 * Everything else (multi-key fan-out, blocking, pub/sub, MULTI, ACL, HELLO,
 * container commands, ...) still runs through the original one-command-at-
 * a-time state machine (legacy_dispatch() in client.c). A legacy command is
 * only started once all of the client's earlier fast-path replies have been
 * flushed, and no further input is processed until it completes, so the two
 * paths never interleave on one client. */

#define CLIENT_MAX_INFLIGHT    1024              /* fast-path requests outstanding per client */
#define CLIENT_MAX_PENDING_OUT (4 * 1024 * 1024) /* stop parsing while this much reply data is unflushed */
#define CLIENT_READ_PAUSE      (4 * 1024 * 1024) /* stop reading while this much input is unparsed */
#define IO_CHUNK               16384
#define MAX_REDIRECTS          5
#define MAX_RETAINED_CMD       65536 /* larger commands aren't kept for MOVED/ASK retry */
#define MAX_INLINE_LINE        65536

/* ── intrusive worker lists ─────────────────────────────────────────── */
static void pw_add(Worker *w, ClientConn *c) {
    if (c->in_pw) return;
    c->in_pw = 1;
    c->pw_prev = NULL;
    c->pw_next = w->pw_head;
    if (w->pw_head) w->pw_head->pw_prev = c;
    w->pw_head = c;
}
static void pw_remove(Worker *w, ClientConn *c) {
    if (!c->in_pw) return;
    if (c->pw_prev)
        c->pw_prev->pw_next = c->pw_next;
    else
        w->pw_head = c->pw_next;
    if (c->pw_next) c->pw_next->pw_prev = c->pw_prev;
    c->in_pw = 0;
    c->pw_prev = c->pw_next = NULL;
}
static void bl_add(Worker *w, ClientConn *c) {
    if (c->in_bl) return;
    c->in_bl = 1;
    c->bl_prev = NULL;
    c->bl_next = w->bl_head;
    if (w->bl_head) w->bl_head->bl_prev = c;
    w->bl_head = c;
}
static void bl_remove(Worker *w, ClientConn *c) {
    if (!c->in_bl) return;
    if (c->bl_prev)
        c->bl_prev->bl_next = c->bl_next;
    else
        w->bl_head = c->bl_next;
    if (c->bl_next) c->bl_next->bl_prev = c->bl_prev;
    c->in_bl = 0;
    c->bl_prev = c->bl_next = NULL;
}
static void pf_add(Worker *w, MuxConn *m) {
    if (m->in_pf) return;
    m->in_pf = 1;
    m->pf_prev = NULL;
    m->pf_next = w->pf_head;
    if (w->pf_head) w->pf_head->pf_prev = m;
    w->pf_head = m;
}
static void pf_remove(Worker *w, MuxConn *m) {
    if (!m->in_pf) return;
    if (m->pf_prev)
        m->pf_prev->pf_next = m->pf_next;
    else
        w->pf_head = m->pf_next;
    if (m->pf_next) m->pf_next->pf_prev = m->pf_prev;
    m->in_pf = 0;
    m->pf_prev = m->pf_next = NULL;
}

static void ct_add(Worker *w, MuxConn *m) {
    if (m->in_ct) return;
    m->in_ct = 1;
    m->ct_prev = NULL;
    m->ct_next = w->ct_head;
    if (w->ct_head) w->ct_head->ct_prev = m;
    w->ct_head = m;
}
static void ct_remove(Worker *w, MuxConn *m) {
    if (!m->in_ct) return;
    if (m->ct_prev)
        m->ct_prev->ct_next = m->ct_next;
    else
        w->ct_head = m->ct_next;
    if (m->ct_next) m->ct_next->ct_prev = m->ct_prev;
    m->in_ct = 0;
    m->ct_prev = m->ct_next = NULL;
}

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void client_list_unlink(Worker *w, ClientConn *c) {
    pw_remove(w, c);
    bl_remove(w, c);
}

/* ── Req allocation (per-worker freelist) ───────────────────────────── */
static Req *req_new(Worker *w) {
    Req *r = w->req_free;
    if (r)
        w->req_free = r->mnext;
    else if (!(r = malloc(sizeof(Req))))
        return NULL;
    memset(r, 0, offsetof(Req, cmd_inl));
    return r;
}
static void req_free(Worker *w, Req *r) {
    free(r->reply);
    r->reply = NULL;
    if (r->cmd != r->cmd_inl) free(r->cmd);
    r->cmd = NULL;
    r->mnext = w->req_free;
    w->req_free = r;
}

/* Keeps a copy of the command so a MOVED/ASK reply can be retried. */
static void req_keep_cmd(Req *r, const char *data, int len) {
    if (len > MAX_RETAINED_CMD) return;
    r->cmd = len <= (int)sizeof(r->cmd_inl) ? r->cmd_inl : malloc((size_t)len);
    if (!r->cmd) return;
    memcpy(r->cmd, data, (size_t)len);
    r->cmd_len = len;
}

/* ── buffers ────────────────────────────────────────────────────────── */
/* Makes room for `need` more bytes after buf[*len], first by discarding the
 * already-consumed prefix buf[0..*off), then by growing. Returns -1 on OOM. */
static int buf_reserve(char **buf, int *len, int *off, int *cap, int need) {
    if (*cap - *len >= need) return 0;
    if (off && *off > 0) {
        int live = *len - *off;
        if (live > 0) memmove(*buf, *buf + *off, (size_t)live);
        *len = live;
        *off = 0;
        if (*cap - *len >= need) return 0;
    }
    long long nc = *cap ? *cap : IO_CHUNK;
    while (nc - *len < need) nc *= 2;
    if (nc > INT32_MAX) return -1;
    char *tmp = realloc(*buf, (size_t)nc);
    if (!tmp) return -1;
    *buf = tmp;
    *cap = (int)nc;
    return 0;
}

void client_queue_reply(Worker *w, ClientConn *c, const char *data, int len);

/* client-output-buffer-limit: a client that lets more than the limit of
 * replies pile up (a slow pub/sub subscriber, typically) is disconnected
 * instead of growing the proxy's memory without bound. */
int client_check_obuf_limit(Worker *w, ClientConn *c) {
    int limit = (c->in_subscribe || c->sub_conn) ? g_config.obuf_limit_pubsub : g_config.obuf_limit_normal;
    if (limit <= 0 || c->close_asap || c->wbuf_len - c->wbuf_off <= limit) return 0;
    fprintf(stderr, "[worker %d] closing %s: output buffer %d bytes over the %s limit\n", w->thread_id, c->addr,
            c->wbuf_len - c->wbuf_off, (c->in_subscribe || c->sub_conn) ? "pubsub" : "normal");
    c->close_asap = 1;
    pw_add(w, c);
    return -1;
}

static void client_out_append(Worker *w, ClientConn *c, const char *data, int len) {
    if (c->close_asap) return;
    if (c->wbuf_off == c->wbuf_len) c->wbuf_off = c->wbuf_len = 0;
    if (buf_reserve(&c->wbuf, &c->wbuf_len, &c->wbuf_off, &c->wbuf_cap, len) < 0) {
        c->close_asap = 1;
        pw_add(w, c);
        return;
    }
    memcpy(c->wbuf + c->wbuf_len, data, (size_t)len);
    c->wbuf_len += len;
    pw_add(w, c);
    client_check_obuf_limit(w, c);
}

/* A legacy command (legacy_dispatch()) hasn't finished: some of them wait
 * on fan-out sub-requests or a pool connection without leaving
 * CS_READING_HDR, so the state alone doesn't tell. Nothing else of the
 * client's may start meanwhile, or its reply would overtake this one. */
static int client_legacy_busy(const ClientConn *c) {
    return c->state != CS_READING_HDR || c->fanout_ctx || c->pending_conn || c->hello_auth_conn;
}

/* Blocked in BLPOP & co, or subscribed: what such a client waits on can
 * last forever, so if it hangs up it's closed at once (as Valkey does). */
static int client_parked(const ClientConn *c) {
    return (c->pending_conn && c->pending_conn->pool && c->pending_conn->pool->type == POOL_BLOCKING) || c->sub_conn ||
           c->in_subscribe;
}

/* Reply bytes not yet written to the socket. */
static int client_out_bytes(const ClientConn *c) {
    return c->wbuf_len - c->wbuf_off;
}

void client_queue_reply(Worker *w, ClientConn *c, const char *data, int len) {
    client_out_append(w, c, data, len);
}

/* ── reply ordering ─────────────────────────────────────────────────── */
static void client_rq_pop(ClientConn *c) {
    c->rq_head = c->rq_head->cnext;
    if (!c->rq_head) c->rq_tail = NULL;
    c->rq_count--;
}

/* A fan-out sub-request's reply: store it the way the pooled path did
 * (handle_fanout_sub_readable() in fanout.c) and aggregate once every sub
 * of the command is in. `failed` = the connection broke rather than the
 * backend answering. */
static void sub_deliver(Worker *w, FanoutSub *sub, const char *data, int len, int failed) {
    FanoutCtx *ctx = sub->ctx;
    sub->req = NULL;
    if (failed) {
        sub->error = 1;
    } else {
        char *buf = malloc((size_t)len);
        if (!buf) {
            sub->error = 1;
        } else {
            memcpy(buf, data, (size_t)len);
            free(sub->rbuf);
            sub->rbuf = buf;
            sub->rbuf_len = sub->rbuf_cap = len;
        }
    }
    sub->done = 1;
    if (sub->error) ctx->had_error = 1;
    ctx->ndone++;
    if (ctx->ndone == ctx->nsubs) fanout_aggregate_and_reply(w, ctx);
}

/* Request r (already off any mux FIFO) has its reply. If it's next in its
 * client's order, write it straight to the client along with any later
 * replies that were held back waiting for it; otherwise park a copy. */
static void fan_sub_done(Worker *w, struct FastFan *f, int idx, const char *data, int len, int failed);

static void req_deliver_ex(Worker *w, Req *r, const char *data, int len, int failed) {
    if (r->client && r->inflight_kind) {
        if (r->inflight_kind == 2)
            r->client->pin_inflight--;
        else
            r->client->shared_inflight--;
        r->inflight_kind = 0;
    }
    if (r->fan) {
        struct FastFan *f = r->fan;
        int idx = r->fan_idx;
        req_free(w, r);
        fan_sub_done(w, f, idx, data, len, failed);
        return;
    }
    if (r->sub) {
        FanoutSub *sub = r->sub;
        req_free(w, r);
        sub_deliver(w, sub, data, len, failed);
        return;
    }
    ClientConn *c = r->client;
    if (!c) {
        if (r->internal && len > 0 && data[0] == '-')
            fprintf(stderr, "[worker %d] backend rejected connection setup: %.*s\n", w->thread_id,
                    len > 2 ? len - 2 : len, data);
        req_free(w, r);
        return;
    }
    if (c->rq_head != r) {
        r->reply = malloc((size_t)len);
        if (!r->reply) {
            c->close_asap = 1;
            pw_add(w, c);
            r->done = 1;
            return;
        }
        memcpy(r->reply, data, (size_t)len);
        r->reply_len = len;
        r->done = 1;
        return;
    }
    client_out_append(w, c, data, len);
    client_rq_pop(c);
    req_free(w, r);
    while ((r = c->rq_head) && r->done) {
        client_out_append(w, c, r->reply, r->reply_len);
        client_rq_pop(c);
        req_free(w, r);
    }
}

static void req_deliver(Worker *w, Req *r, const char *data, int len) {
    req_deliver_ex(w, r, data, len, 0);
}

/* Proxy-generated reply that must still respect the client's reply order
 * (e.g. "slot not mapped" for the 3rd command of a pipeline whose first two
 * are still in flight). */
static void client_reply_ordered(Worker *w, ClientConn *c, const char *data, int len) {
    if (!c->rq_head) {
        client_out_append(w, c, data, len);
        return;
    }
    Req *r = req_new(w);
    if (!r) {
        c->close_asap = 1;
        pw_add(w, c);
        return;
    }
    r->client = c;
    if (c->rq_tail)
        c->rq_tail->cnext = r;
    else
        c->rq_head = r;
    c->rq_tail = r;
    c->rq_count++;
    req_deliver(w, r, data, len);
}

static void client_reply_error(Worker *w, ClientConn *c, const char *msg) {
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "-ERR %s\r\n", msg);
    client_reply_ordered(w, c, buf, n);
}

/* Client is going away: requests still in flight on a mux are orphaned (the
 * mux frees them when their reply arrives), parked replies are dropped. */
void client_detach_requests(Worker *w, ClientConn *c) {
    Req *r = c->rq_head;
    while (r) {
        Req *next = r->cnext;
        r->cnext = NULL;
        if (r->done)
            req_free(w, r);
        else
            r->client = NULL;
        r = next;
    }
    c->rq_head = c->rq_tail = NULL;
    c->rq_count = 0;
}

/* ── mux connections ────────────────────────────────────────────────── */
static void tx_reset(ClientConn *c);

static void mux_destroy(Worker *w, MuxConn *m) {
    pf_remove(w, m);
    ct_remove(w, m);
    if (m->owner) {
        for (int i = 0; i < 2; i++) {
            if (m->owner->mux[i] == m) m->owner->mux[i] = NULL;
            for (MuxConn **pp = &m->owner->tx_idle[i]; *pp; pp = &(*pp)->idle_next)
                if (*pp == m) {
                    *pp = m->idle_next;
                    break;
                }
        }
    }
    if (m->pin_client && m->pin_client->pin == m) {
        /* Pinned connection died mid-WATCH/MULTI: the backend's transaction
         * state is gone, so the client's is too (as with a lost server
         * connection). */
        m->pin_client->pin = NULL;
        tx_reset(m->pin_client);
    }
    if (m->fd >= 0) {
        fd_unwatch(w, m->fd, EL_READABLE | EL_WRITABLE);
        if (m->fd < g_config.max_connection) w->mux_map[m->fd] = NULL;
#ifdef USE_TLS
        tls_free(m->ssl);
#endif
        close(m->fd);
    }
    free(m->obuf);
    free(m->rbuf);
    free(m);
}

/* Backend connection lost (or node gone): every request still waiting on it
 * gets an error reply, in order, and the mux is freed. */
void mux_fail(Worker *w, MuxConn *m, const char *msg) {
    const ClusterNode *nd = &w->topo.nodes[m->node_idx];
    /* A node that stopped answering may have failed over: a dead master
     * never sends MOVED, so without this the proxy would only notice at the
     * next periodic refresh (rate-limited, so storms are fine). */
    topology_request_refresh();
    if (m->inflight > 0)
        fprintf(stderr, "[worker %d] backend %s:%d: %s (%d request(s) failed)\n", w->thread_id, nd->ip, nd->port, msg,
                m->inflight);
    char err[256];
    int n = snprintf(err, sizeof(err), "-ERR %s\r\n", msg);
    Req *r = m->head;
    m->head = m->tail = NULL;
    m->inflight = 0;
    while (r) {
        Req *next = r->mnext;
        req_deliver_ex(w, r, err, n, 1);
        r = next;
    }
    mux_destroy(w, m);
}

/* Room for len more bytes of output on m; -1 on OOM. After a successful
 * reserve, the next mux_enqueue() of up to len bytes can't fail. */
static int mux_reserve(MuxConn *m, int len) {
    if (m->obuf_off == m->obuf_len) m->obuf_off = m->obuf_len = 0;
    return buf_reserve(&m->obuf, &m->obuf_len, &m->obuf_off, &m->obuf_cap, len);
}

static void mux_enqueue(Worker *w, MuxConn *m, Req *r, const char *data, int len) {
    if (mux_reserve(m, len) < 0) {
        /* Can't buffer the command: fail just this request. */
        req_deliver(w, r, "-ERR out of memory\r\n", 20);
        return;
    }
    memcpy(m->obuf + m->obuf_len, data, (size_t)len);
    m->obuf_len += len;
    r->mnext = NULL;
    if (m->tail)
        m->tail->mnext = r;
    else
        m->head = r;
    m->tail = r;
    m->inflight++;
    pf_add(w, m);
}

/* A draining mux just went idle: a released transaction connection goes back
 * to its node's idle list for reuse, anything else is closed. */
static void mux_drained(Worker *w, MuxConn *m) {
    if (m->reusable && m->owner && m->owner->gen == m->gen) {
        int ri = m->resp == 3;
        m->draining = 0;
        m->idle_next = m->owner->tx_idle[ri];
        m->owner->tx_idle[ri] = m;
        return;
    }
    mux_destroy(w, m);
}

/* Queues a command whose reply the proxy consumes itself. setup: part of
 * establishing the connection (HELLO 3, SELECT, AUTH) -- if the backend
 * rejects it the connection is unusable (wrong db / protocol / user), so it
 * fails instead (see mux_parse_replies()). If the command can't even be
 * queued, m fails right here (it must not carry on without it -- e.g. a
 * transaction without its MULTI) and -1 is returned: m is gone. */
static int mux_internal_cmd(Worker *w, MuxConn *m, const char *cmd, int len, int setup) {
    Req *r = req_new(w);
    if (!r || mux_reserve(m, len) < 0) {
        if (r) req_free(w, r);
        mux_fail(w, m, "out of memory");
        return -1;
    }
    r->internal = 1;
    r->setup = setup;
    mux_enqueue(w, m, r, cmd, len);
    return 0;
}

static MuxConn *mux_create(Worker *w, NodePools *np, int db, int resp) {
    const ClusterNode *nd = &w->topo.nodes[np->node_idx];
    if (nd->salen == 0) return NULL; /* resolved off-thread by discovery; never DNS here */
    int fd = socket(nd->sa.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    if (fd >= g_config.max_connection) {
        close(fd);
        return NULL;
    }
    set_nonblocking(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    set_tcp_keepalive(fd);
    fd_reset(w, fd);
    int rc = connect(fd, (const struct sockaddr *)&nd->sa, nd->salen);
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return NULL;
    }
    MuxConn *m = calloc(1, sizeof(MuxConn));
    if (!m) {
        close(fd);
        return NULL;
    }
    m->fd = fd;
    m->node_idx = np->node_idx;
    m->db = db;
    m->resp = resp;
    m->connecting = rc < 0;
    m->owner = np;
    m->gen = np->gen;
#ifdef USE_TLS
    if (g_config.tls_backend) {
        m->ssl = tls_new(fd, 0, nd->hostname[0] ? nd->hostname : nd->ip);
        if (!m->ssl) {
            close(fd);
            free(m);
            return NULL;
        }
        m->tls_hs = 1;
    }
#endif
    w->mux_map[fd] = m;
    /* Writable fires once connect() completes; the TLS handshake (if any)
     * starts from there, and queued commands are flushed after it. */
        fd_watch(w, fd, EL_READABLE | (m->connecting || m->tls_hs ? EL_WRITABLE : 0));
    if (m->connecting || m->tls_hs) {
        m->connect_deadline = mono_ms() + g_config.backend_connect_timeout_ms;
        ct_add(w, m);
    }

    /* Connection setup rides the same pipeline as the first real commands;
     * these replies are swallowed (see req_deliver()). */
    if (resp == 3) {
        static const char HELLO3[] = "*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n";
        if (mux_internal_cmd(w, m, HELLO3, (int)sizeof(HELLO3) - 1, 1) < 0) return NULL;
    }
    if (db != 0) {
        char dbs[16], sel[64];
        int dl = snprintf(dbs, sizeof(dbs), "%d", db);
        int n = snprintf(sel, sizeof(sel), "*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n", dl, dbs);
        if (mux_internal_cmd(w, m, sel, n, 1) < 0) return NULL;
    }
    LOG_VERBOSE("[worker %d] [mux] connect fd=%d node=%s:%d db=%d resp=%d\n", w->thread_id, fd, nd->ip, nd->port, db,
                resp);
    return m;
}

static NodePools *client_np(Worker *w, ClientConn *c, int node_idx) {
    if (!c->fast_np || c->fast_db != c->db) {
        DbGroup *grp = db_group_get(w, c->db);
        if (!grp) return NULL;
        c->fast_np = grp->node_pools;
        c->fast_db = c->db;
    }
    return &c->fast_np[node_idx];
}

static MuxConn *mux_for(Worker *w, ClientConn *c, int node_idx) {
    NodePools *np = client_np(w, c, node_idx);
    if (!np) return NULL;
    int ri = c->resp == 3;
    MuxConn *m = np->mux[ri];
    if (!m) m = np->mux[ri] = mux_create(w, np, c->db, c->resp == 3 ? 3 : 2);
    return m;
}

static void mux_flush(Worker *w, MuxConn *m) {
    if (m->connecting || m->tls_hs) return; /* handle_mux_writable() flushes once connected */
    while (m->obuf_off < m->obuf_len) {
        int want;
        ssize_t n = net_write(m->fd, m->ssl, m->obuf + m->obuf_off, (size_t)(m->obuf_len - m->obuf_off), &want);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                /* want == EL_READABLE: TLS needs input first; handle_mux_readable()
                 * re-queues the flush. */
                if (want != EL_READABLE && !(w->fd_mask[m->fd] & EL_WRITABLE)) fd_watch(w, m->fd, EL_WRITABLE);
                return;
            }
            mux_fail(w, m, "backend connection error");
            return;
        }
        m->obuf_off += (int)n;
    }
    m->obuf_off = m->obuf_len = 0;
    if ((w->fd_mask[m->fd] & EL_WRITABLE) && !m->ssl_read_wants_write) fd_unwatch(w, m->fd, EL_WRITABLE);
}

/* Advances the backend TLS handshake. Returns -1 if it failed (m is gone). */
static int mux_tls_step(Worker *w, MuxConn *m) {
#ifdef USE_TLS
    int want;
    int rc = tls_handshake(m->ssl, &want);
    if (rc < 0) {
        mux_fail(w, m, "backend TLS handshake failed");
        return -1;
    }
    if (rc == 0) {
        if (want == EL_WRITABLE) {
            if (!(w->fd_mask[m->fd] & EL_WRITABLE)) fd_watch(w, m->fd, EL_WRITABLE);
        } else if (w->fd_mask[m->fd] & EL_WRITABLE) {
            fd_unwatch(w, m->fd, EL_WRITABLE);
        }
        return 0;
    }
    m->tls_hs = 0;
    ct_remove(w, m);
    if (g_config.verbose) {
        char d[128];
        printf("[worker %d] [mux] fd=%d TLS %s\n", w->thread_id, m->fd, tls_describe(m->ssl, d, sizeof(d)));
    }
    pf_add(w, m); /* commands queued during the handshake */
#else
    (void)w;
    (void)m;
#endif
    return 0;
}

void handle_mux_writable(Worker *w, MuxConn *m) {
    if (m->connecting) {
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(m->fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) {
            mux_fail(w, m, "backend connection refused");
            return;
        }
        m->connecting = 0;
        if (!m->tls_hs) ct_remove(w, m);
    }
    if (m->tls_hs) {
        if (mux_tls_step(w, m) < 0 || m->tls_hs) return;
    }
    if (m->ssl_read_wants_write) {
        int fd = m->fd;
        m->ssl_read_wants_write = 0;
        handle_mux_readable(w, m);
        if (w->mux_map[fd] != m) return;
    }
    mux_flush(w, m);
}

static MuxConn *mux_for_db(Worker *w, int db, int node_idx, int resp) {
    DbGroup *grp = db_group_get(w, db);
    if (!grp) return NULL;
    NodePools *np = &grp->node_pools[node_idx];
    int ri = resp == 3;
    if (!np->mux[ri]) np->mux[ri] = mux_create(w, np, db, resp);
    return np->mux[ri];
}

/* "-MOVED <slot> <host>:<port>" / "-ASK <slot> <host>:<port>" for a request
 * on a shared mux: resend it to the node named in the reply (behind ASKING
 * for ASK) instead of handing the redirect to a client that can't act on
 * it. MOVED also patches this worker's slot map at once and asks for a full
 * topology refresh. Returns 1 if r was re-queued. */
static int mux_try_redirect(Worker *w, MuxConn *m, Req *r, const char *d, int len) {
    int ask;
    const char *p;
    if (len > 7 && !memcmp(d, "-MOVED ", 7)) {
        ask = 0;
        p = d + 7;
    } else if (len > 5 && !memcmp(d, "-ASK ", 5)) {
        ask = 1;
        p = d + 5;
    } else {
        return 0;
    }
    if (!ask) topology_request_refresh();
    if (!r->cmd || r->redirects >= MAX_REDIRECTS || (!r->client && !r->sub && !r->fan)) return 0;

    const char *end = d + len;
    int slot = 0;
    while (p < end && *p >= '0' && *p <= '9') slot = slot * 10 + (*p++ - '0');
    if (p >= end || *p != ' ' || slot >= CLUSTER_SLOTS) return 0;
    const char *host = ++p;
    const char *eol = memchr(host, '\r', (size_t)(end - host));
    if (!eol) return 0;
    const char *colon = eol;
    while (colon > host && *colon != ':') colon--;
    if (colon == host) return 0;
    int hlen = (int)(colon - host), port = atoi(colon + 1);

    int idx = -1;
    /* The redirect names the node by IP or, with cluster-preferred-endpoint-
     * type hostname, by its announced hostname. */
    for (int i = 0; i < w->topo.node_count; i++) {
        const ClusterNode *nd = &w->topo.nodes[i];
        if (nd->port != port) continue;
        if (((int)strlen(nd->ip) == hlen && !memcmp(nd->ip, host, (size_t)hlen)) ||
            (nd->hostname[0] && (int)strlen(nd->hostname) == hlen && !memcmp(nd->hostname, host, (size_t)hlen))) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return 0; /* unknown node: let the refresh find it, pass the error on */
    if (!ask) w->topo.slot_map[slot] = idx;

    MuxConn *t = mux_for_db(w, m->db, idx, m->resp);
    if (!t) return 0;
    if (ask) {
        static const char ASKING[] = "*1\r\n$6\r\nASKING\r\n";
        if (mux_internal_cmd(w, t, ASKING, (int)sizeof(ASKING) - 1, 0) < 0) return 0;
    }
    r->redirects++;
    LOG_VERBOSE("[worker %d] %s slot %d -> %s:%d\n", w->thread_id, ask ? "ASK" : "MOVED", slot,
                w->topo.nodes[idx].ip, port);
    mux_enqueue(w, t, r, r->cmd, r->cmd_len);
    return 1;
}

/* Routes every complete reply in m->rbuf to its request. Returns -1 if m
 * failed (and is gone). */
static int mux_parse_replies(Worker *w, MuxConn *m) {
    while (m->rbuf_off < m->rbuf_len) {
        int rl = resp_response_len(m->rbuf + m->rbuf_off, m->rbuf_len - m->rbuf_off);
        if (rl == 0) {
            if (m->rbuf_len - m->rbuf_off > MAX_RESP_SIZE) {
                mux_fail(w, m, "response too large");
                return -1;
            }
            break;
        }
        Req *r = m->head;
        if (rl < 0 || !r) {
            mux_fail(w, m, "bad backend response");
            return -1;
        }
        m->head = r->mnext;
        if (!m->head) m->tail = NULL;
        m->inflight--;
        r->mnext = NULL;
        const char *reply = m->rbuf + m->rbuf_off;
        m->rbuf_off += rl;
        if (reply[0] == '-' && r->setup) {
            char msg[200];
            snprintf(msg, sizeof(msg), "backend rejected connection setup: %.*s", rl > 2 ? rl - 3 : 0, reply + 1);
            req_free(w, r);
            mux_fail(w, m, msg);
            return -1;
        }
        if (reply[0] == '-' && !r->internal && !m->pin_client && mux_try_redirect(w, m, r, reply, rl)) continue;
        req_deliver(w, r, reply, rl);
    }
    return 0;
}


void handle_mux_readable(Worker *w, MuxConn *m) {
    if (m->connecting) return; /* refused/reset connects are reported via handle_mux_writable() */
    if (m->tls_hs) {
        if (mux_tls_step(w, m) < 0 || m->tls_hs) return;
    }
    for (;;) {
        if (m->rbuf_off == m->rbuf_len) m->rbuf_off = m->rbuf_len = 0;
        if (buf_reserve(&m->rbuf, &m->rbuf_len, &m->rbuf_off, &m->rbuf_cap, IO_CHUNK) < 0) {
            mux_fail(w, m, "out of memory");
            return;
        }
        int space = m->rbuf_cap - m->rbuf_len, want;
        ssize_t n = net_read(m->fd, m->ssl, m->rbuf + m->rbuf_len, (size_t)space, &want);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                if (want == EL_WRITABLE) {
                    m->ssl_read_wants_write = 1;
                    if (!(w->fd_mask[m->fd] & EL_WRITABLE)) fd_watch(w, m->fd, EL_WRITABLE);
                }
                break;
            }
            mux_fail(w, m, "backend connection error");
            return;
        }
        if (n == 0) {
            mux_fail(w, m, "backend connection closed");
            return;
        }
        m->rbuf_len += (int)n;
        if (mux_parse_replies(w, m) < 0) return;
        /* Plain TCP: a short read means the socket is drained (edge-
         * triggered, so nothing more until the next edge) -- unless the peer
         * hung up, whose EOF then has to be read now. */
        if (n < space && net_short_read_drained(m->ssl) && !m->peer_closed) break;
    }
    if (m->obuf_off < m->obuf_len) pf_add(w, m); /* a TLS write may have been waiting on this read */
    if (m->draining && m->inflight == 0) mux_drained(w, m);
}

/* Topology moved node np->node_idx to a new identity (failover / eviction --
 * see worker_sync_topology()). Its muxes stop taking new requests; if the
 * node still owns slots the in-flight ones are allowed to finish, otherwise
 * nothing will ever answer them, so they fail now. */
void mux_node_changed(Worker *w, NodePools *np, int still_owns_slots) {
    for (int i = 0; i < 2; i++) {
        MuxConn *idle;
        while ((idle = np->tx_idle[i])) mux_destroy(w, idle); /* unlinks itself */
    }
    for (int i = 0; i < 2; i++) {
        MuxConn *m = np->mux[i];
        if (!m) continue;
        np->mux[i] = NULL;
        m->owner = NULL;
        if (!still_owns_slots)
            mux_fail(w, m, "backend node unavailable");
        else if (m->inflight == 0)
            mux_destroy(w, m);
        else
            m->draining = 1;
    }
}

/* ── fan-out sub-requests ───────────────────────────────────────────── */
void fanout_send_sub(Worker *w, FanoutSub *sub, const char *cmd, int len) {
    sub->conn = NULL;
    sub->req = NULL;
    /* Always RESP2: every fanout_agg_*() parses RESP2 sub-replies. */
    MuxConn *m = (sub->node_idx >= 0 && sub->node_idx < w->topo.node_count)
                     ? mux_for_db(w, sub->ctx->client->db, sub->node_idx, 2)
                     : NULL;
    /* Reserve first so mux_enqueue() can't fail: its failure path would
     * complete (and possibly aggregate) the sub synchronously. */
    Req *r = (m && mux_reserve(m, len) == 0) ? req_new(w) : NULL;
    if (!r) {
        /* Not sub_deliver(): callers are still looping over ctx->subs and
         * aggregate themselves once ndone == nsubs after the loop. */
        sub->error = sub->done = 1;
        sub->ctx->had_error = 1;
        sub->ctx->ndone++;
        return;
    }
    r->sub = sub;
    sub->req = r;
    req_keep_cmd(r, cmd, len);
    mux_enqueue(w, m, r, cmd, len);
}

/* ── client input ───────────────────────────────────────────────────── */
static int parse_len(const char *p, const char *end, long long *out) {
    long long v = 0;
    int neg = 0;
    if (p < end && *p == '-') {
        neg = 1;
        p++;
    }
    if (p >= end) return -1;
    for (; p < end; p++) {
        if (*p < '0' || *p > '9') return -1;
        v = v * 10 + (*p - '0');
        if (v > INT32_MAX) return -1;
    }
    *out = neg ? -v : v;
    return 0;
}

/* Frames one RESP multibulk command at buf[0..len). Returns 1 when it's all
 * there (cmd/key point into buf, *total = its full size), 0 if more bytes
 * are needed (*need = a lower bound on the total), -1 on a protocol error. */
int scan_command(const char *buf, int len, const char **cmd, int *cmdlen, const char **key, int *keylen, int *argc_out,
                 long long *total, long long *need) {
    *need = len + 1;
    if (buf[0] != '*') return -1;
    const char *nl = memchr(buf, '\n', (size_t)len);
    if (!nl) return len > 64 ? -1 : 0;
    long long argc;
    if (nl == buf || nl[-1] != '\r' || parse_len(buf + 1, nl - 1, &argc) < 0 || argc <= 0 || argc > 1024 * 1024)
        return -1;
    long long off = (nl - buf) + 1;
    *cmd = *key = NULL;
    *cmdlen = *keylen = 0;
    for (long long i = 0; i < argc; i++) {
        if (off >= len) {
            *need = off + 4;
            return 0;
        }
        if (buf[off] != '$') return -1;
        nl = memchr(buf + off, '\n', (size_t)(len - off));
        if (!nl) {
            if (len - off > 32) return -1;
            *need = len + 1;
            return 0;
        }
        long long al;
        if (nl[-1] != '\r' || parse_len(buf + off + 1, nl - 1, &al) < 0 || al < 0) return -1;
        long long data = (nl - buf) + 1;
        long long end = data + al + 2;
        if (end > len) {
            *need = end;
            return 0;
        }
        if (buf[end - 2] != '\r' || buf[end - 1] != '\n') return -1;
        if (i == 0) {
            *cmd = buf + data;
            *cmdlen = (int)al;
        } else if (i == 1) {
            *key = buf + data;
            *keylen = (int)al;
        }
        off = end;
    }
    *argc_out = (int)argc;
    *total = off;
    return 1;
}

static void client_protocol_error(Worker *w, ClientConn *c, const char *msg) {
    client_reply_error(w, c, msg);
    c->close_after_write = 1;
    c->ibuf_off = c->ibuf_len = 0;
    pw_add(w, c);
}

/* Appends a new request to the end of c's reply order. */
static Req *client_req_new(Worker *w, ClientConn *c) {
    Req *r = req_new(w);
    if (!r) {
        c->close_asap = 1;
        pw_add(w, c);
        return NULL;
    }
    r->client = c;
    if (c->rq_tail)
        c->rq_tail->cnext = r;
    else
        c->rq_head = r;
    c->rq_tail = r;
    c->rq_count++;
    return r;
}

static void client_reply_str(Worker *w, ClientConn *c, const char *s) {
    client_reply_ordered(w, c, s, (int)strlen(s));
}

/* ── inline commands ────────────────────────────────────────────────── */
static int hexval(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Converts one inline command line (telnet-style "SET k v") into RESP in
 * c->conv, splitting on whitespace with Valkey's quoting rules ("..." with
 * \n \r \t \b \a \\ \" \xHH escapes, '...' with \' only). Returns the RESP
 * length, 0 for a blank line, or -1 on unbalanced quotes / OOM. */
int inline_to_resp(ClientConn *c, const char *line, int len) {
    char *args = malloc((size_t)len + 1); /* unescaped args are never longer than the line */
    if (!args) return -1;
    int arg_off[1024], arg_len[1024], argc = 0, alen = 0;
    const char *p = line, *end = line + len;
    for (;;) {
        while (p < end && (*p == ' ' || *p == '\t')) p++;
        if (p >= end) break;
        if (argc == 1024) goto bad;
        int start = alen;
        char q = *p;
        if (q == '"' || q == '\'') {
            p++;
            for (;;) {
                if (p >= end) goto bad;
                if (*p == q) {
                    p++;
                    break;
                }
                char ch = *p++;
                if (ch == '\\' && p < end) {
                    if (q == '\'') {
                        if (*p == '\'') ch = *p++;
                    } else {
                        ch = *p++;
                        if (ch == 'x' && p + 1 < end && hexval(p[0]) >= 0 && hexval(p[1]) >= 0) {
                            ch = (char)(hexval(p[0]) * 16 + hexval(p[1]));
                            p += 2;
                        } else if (ch == 'n') {
                            ch = '\n';
                        } else if (ch == 'r') {
                            ch = '\r';
                        } else if (ch == 't') {
                            ch = '\t';
                        } else if (ch == 'b') {
                            ch = '\b';
                        } else if (ch == 'a') {
                            ch = '\a';
                        }
                    }
                }
                args[alen++] = ch;
            }
            if (p < end && *p != ' ' && *p != '\t') goto bad; /* closing quote must end the arg */
        } else {
            while (p < end && *p != ' ' && *p != '\t') args[alen++] = *p++;
        }
        arg_off[argc] = start;
        arg_len[argc] = alen - start;
        argc++;
    }
    if (argc == 0) {
        free(args);
        return 0;
    }
    int need = 16 + argc * 16 + alen;
    if (c->conv_cap < need) {
        char *tmp = realloc(c->conv, (size_t)need);
        if (!tmp) goto bad;
        c->conv = tmp;
        c->conv_cap = need;
    }
    int o = snprintf(c->conv, (size_t)c->conv_cap, "*%d\r\n", argc);
    for (int i = 0; i < argc; i++) {
        o += snprintf(c->conv + o, (size_t)(c->conv_cap - o), "$%d\r\n", arg_len[i]);
        memcpy(c->conv + o, args + arg_off[i], (size_t)arg_len[i]);
        o += arg_len[i];
        c->conv[o++] = '\r';
        c->conv[o++] = '\n';
    }
    free(args);
    return o;
bad:
    free(args);
    return -1;
}

/* ── transactions ───────────────────────────────────────────────────────
 * WATCH and MULTI pin the client to a private backend connection (taken
 * from the node's tx_idle list when possible) so the backend sees the whole
 * WATCH ... MULTI ... EXEC sequence on one connection and applies its own
 * rules (CROSSSLOT, EXECABORT, watched-key invalidation). MULTI is answered
 * locally and the node is picked by the transaction's first keyed command;
 * keyless commands before that are answered +QUEUED locally and replayed
 * once the node is known. */
static void tx_reset(ClientConn *c) {
    c->tx_state = 0;
    c->tx_dirty = 0;
    c->txq_len = 0;
    c->in_transaction = 0;
    c->multi_count = -1;
    c->watch_count = 0;
}

static void tx_release(Worker *w, ClientConn *c, int reusable) {
    MuxConn *m = c->pin;
    if (!m) return;
    c->pin = NULL;
    m->pin_client = NULL;
    m->reusable = m->reusable && reusable;
    m->draining = 1;
    if (m->inflight == 0) mux_drained(w, m);
}

static void tx_end(Worker *w, ClientConn *c) {
    tx_release(w, c, 1);
    tx_reset(c);
}

/* Client closing: its pinned connection may hold WATCH/MULTI state, so it's
 * never reused. */
void client_release_tx(Worker *w, ClientConn *c) {
    tx_release(w, c, 0);
    free(c->txq);
    c->txq = NULL;
    c->txq_cap = 0;
    free(c->conv);
    c->conv = NULL;
}

static MuxConn *tx_pin(Worker *w, ClientConn *c, int node_idx) {
    NodePools *np = client_np(w, c, node_idx);
    if (!np) return NULL;
    int ri = c->resp == 3;
    MuxConn *m = NULL;
    if (!c->acl_authenticated && (m = np->tx_idle[ri])) {
        np->tx_idle[ri] = m->idle_next;
        m->idle_next = NULL;
    } else {
        m = mux_create(w, np, c->db, c->resp == 3 ? 3 : 2);
        if (!m) return NULL;
        if (c->acl_authenticated) {
            const char *a[3] = {"AUTH", c->acl_user, c->acl_pass};
            int al[3] = {4, c->acl_userlen, c->acl_passlen};
            int n;
            char *auth = build_resp_cmd(a[0], al[0], a + 1, al + 1, 2, &n);
            int rc = auth ? mux_internal_cmd(w, m, auth, n, 1) : (mux_fail(w, m, "out of memory"), -1);
            free(auth);
            if (rc < 0) return NULL;
        }
    }
    m->pin_client = c;
    m->reusable = !c->acl_authenticated;
    m->draining = 0;
    c->pin = m;
    return m;
}

static void tx_forward(Worker *w, ClientConn *c, const char *p, int len) {
    if (!c->pin) { /* pinned connection failed while setting up (see mux_internal_cmd()) */
        client_reply_error(w, c, "backend connection error");
        return;
    }
    Req *r = client_req_new(w, c);
    if (!r) return;
    r->inflight_kind = 2;
    c->pin_inflight++;
    mux_enqueue(w, c->pin, r, p, len);
}

/* Node owning the command's first key, -1 if it has none, -2 if the slot is
 * unmapped. */
static int cmd_first_key_node(Worker *w, const CmdInfo *ci, const char *cmd, const char *p, int len, const char *kp,
                              int kl) {
    const char *k = NULL;
    int klen = 0;
    if (ci->cls == CMD_CLASS_SINGLE_KEY && !ci->container && kl > 0) {
        k = kp;
        klen = kl;
    } else if (ci->cls == CMD_CLASS_MULTI_KEY) {
        if (resp_extract_keys(p, len, cmd, &k, &klen, 1) < 1) k = NULL;
    } else if (ci->cls == CMD_CLASS_BLOCKING) {
        if (resp_extract_blocking_keys(p, len, cmd, &k, &klen, 1) < 1) k = NULL;
    }
    if (!k) return -1;
    int ni = w->topo.slot_map[key_slot(k, klen)];
    return (ni < 0 || ni >= w->topo.node_count) ? -2 : ni;
}

/* Commands the proxy can't run on a pinned transaction connection: they
 * change connection-level state the proxy tracks itself, or are answered by
 * the proxy rather than a backend. */
static int tx_denied(const CmdInfo *ci, const char *cmd) {
    if (!ci) return 1;
    if (ci->cls == CMD_CLASS_PUBSUB || ci->cls == CMD_CLASS_ACL) return 1;
    static const char *DENY[] = {"HELLO", "SELECT", "CLIENT", "ACL", "AUTH", "RESET", "MODULE", NULL};
    for (int i = 0; DENY[i]; i++)
        if (!strcmp(cmd, DENY[i])) return 1;
    return 0;
}

/* Handles c's command if it belongs to a transaction: returns 1 if handled,
 * 0 to let the normal routing take it, 2 if it must wait for c's in-flight
 * shared-connection requests first (see ClientConn.shared_inflight). */
static int tx_handle(Worker *w, ClientConn *c, const char *cmd, const CmdInfo *ci, const char *p, int len,
                     const char *kp, int kl, int argc) {
    int is_multi = !strcmp(cmd, "MULTI"), is_exec = !strcmp(cmd, "EXEC"), is_discard = !strcmp(cmd, "DISCARD"),
        is_watch = !strcmp(cmd, "WATCH"), is_unwatch = !strcmp(cmd, "UNWATCH");
    int txn_cmd = is_multi || is_exec || is_discard || is_watch || is_unwatch;
    if (c->tx_state == 1 && (!strcmp(cmd, "SELECT") || !strcmp(cmd, "AUTH") || !strcmp(cmd, "HELLO"))) {
        /* WATCH pinned a connection with the current db / protocol / user;
         * changing them now would run the transaction with the old ones. */
        char e[160];
        snprintf(e, sizeof(e), "-ERR '%.16s' is not supported while WATCH is active by the proxy (UNWATCH first)\r\n",
                 cmd);
        client_reply_str(w, c, e);
        return 1;
    }
    if (c->tx_state < 2 && !txn_cmd) return 0; /* between WATCH and MULTI: route normally */
    if (c->shared_inflight > 0) return 2;

    c->last_interaction = w->now;
    record_last_cmd(c, cmd, kp, kl);

    if (c->tx_state == 2 && !is_multi && !is_exec && !is_discard && !is_watch) {
        /* Queued command (UNWATCH included: inside MULTI it's just queued). */
        if (tx_denied(ci, cmd)) {
            char e[160];
            snprintf(e, sizeof(e), "-ERR '%.40s' is not supported inside a transaction by the proxy\r\n", cmd);
            client_reply_str(w, c, e);
            c->tx_dirty = 1;
            return 1;
        }
        c->multi_count++;
        if (c->pin) {
            tx_forward(w, c, p, len);
            return 1;
        }
        int ni = cmd_first_key_node(w, ci, cmd, p, len, kp, kl);
        if (ni == -2) {
            client_reply_error(w, c, "slot not mapped");
            c->tx_dirty = 1;
            return 1;
        }
        if (ni == -1) {
            if (buf_reserve(&c->txq, &c->txq_len, NULL, &c->txq_cap, len) < 0) {
                c->close_asap = 1;
                pw_add(w, c);
                return 1;
            }
            memcpy(c->txq + c->txq_len, p, (size_t)len);
            c->txq_len += len;
            client_reply_str(w, c, "+QUEUED\r\n");
            return 1;
        }
        if (!tx_pin(w, c, ni)) {
            client_reply_error(w, c, "backend connection error");
            c->tx_dirty = 1;
            return 1;
        }
        goto send_multi_and_queue;
    }

    if (is_watch) {
        if (c->tx_state == 2) {
            client_reply_str(w, c, "-ERR WATCH inside MULTI is not allowed\r\n");
            return 1;
        }
        if (argc < 2) {
            client_reply_str(w, c, "-ERR wrong number of arguments for 'watch' command\r\n");
            return 1;
        }
        if (!c->pin) {
            int ni = w->topo.slot_map[key_slot(kp, kl)];
            if (ni < 0 || ni >= w->topo.node_count) {
                client_reply_error(w, c, "slot not mapped");
                return 1;
            }
            if (!tx_pin(w, c, ni)) {
                client_reply_error(w, c, "backend connection error");
                return 1;
            }
        }
        c->tx_state = 1;
        c->watch_count += argc - 1;
        tx_forward(w, c, p, len);
        return 1;
    }
    if (is_multi) {
        if (c->tx_state == 2) {
            client_reply_str(w, c, "-ERR MULTI calls can not be nested\r\n");
            return 1;
        }
        c->tx_state = 2;
        c->tx_dirty = 0;
        c->txq_len = 0;
        c->in_transaction = 1;
        c->multi_count = 0;
        if (c->pin)
            tx_forward(w, c, p, len);
        else
            client_reply_str(w, c, "+OK\r\n");
        return 1;
    }
    if (is_unwatch) { /* tx_state < 2 */
        if (c->pin)
            tx_forward(w, c, p, len);
        else
            client_reply_str(w, c, "+OK\r\n");
        tx_end(w, c);
        return 1;
    }
    if (is_discard) {
        if (c->tx_state != 2) {
            client_reply_str(w, c, "-ERR DISCARD without MULTI\r\n");
            return 1;
        }
        if (c->pin)
            tx_forward(w, c, p, len);
        else
            client_reply_str(w, c, "+OK\r\n");
        tx_end(w, c);
        return 1;
    }
    /* EXEC */
    if (c->tx_state != 2) {
        client_reply_str(w, c, "-ERR EXEC without MULTI\r\n");
        return 1;
    }
    if (c->tx_dirty) {
        if (c->pin) mux_internal_cmd(w, c->pin, "*1\r\n$7\r\nDISCARD\r\n", 17, 0); /* failure drops the pin */
        client_reply_str(w, c, "-EXECABORT Transaction discarded because of previous errors.\r\n");
        tx_end(w, c);
        return 1;
    }
    if (!c->pin) {
        if (c->txq_len == 0) {
            client_reply_str(w, c, "*0\r\n");
            tx_end(w, c);
            return 1;
        }
        if (!tx_pin(w, c, topo_first_master(w))) {
            client_reply_error(w, c, "backend connection error");
            tx_end(w, c);
            return 1;
        }
        /* fallthrough with p = EXEC: send MULTI + queued, then EXEC below */
    } else {
        tx_forward(w, c, p, len);
        tx_end(w, c);
        return 1;
    }

send_multi_and_queue:
    /* c->pin was just chosen: replay MULTI and the locally-answered keyless
     * commands (their replies were already sent, so they're swallowed), then
     * forward the current command. */
    int ok = mux_internal_cmd(w, c->pin, "*1\r\n$5\r\nMULTI\r\n", 15, 0) == 0;
    for (int off = 0; ok && off < c->txq_len;) {
        const char *q = c->txq + off;
        const char *cp2, *kp2;
        int cl2, kl2, argc2;
        long long tot2, need2;
        if (scan_command(q, c->txq_len - off, &cp2, &cl2, &kp2, &kl2, &argc2, &tot2, &need2) != 1) break;
        ok = mux_internal_cmd(w, c->pin, q, (int)tot2, 0) == 0;
        off += (int)tot2;
    }
    c->txq_len = 0;
    if (!ok) {
        /* The pinned connection failed (which ended the transaction): this
         * command can't run as part of it. */
        client_reply_error(w, c, "backend connection error");
        return 1;
    }
    tx_forward(w, c, p, len);
    if (is_exec) tx_end(w, c);
    return 1;
}

/* ── pipelined fan-out ──────────────────────────────────────────────────
 * MGET / MSET / DEL / EXISTS / TOUCH / UNLINK without waiting in line like
 * the legacy fan-out (fanout.c), which needs the client's earlier replies
 * flushed and handles one command at a time. All keys in one slot (hash
 * tags): forwarded as one ordinary fast-path request. Otherwise one sub-
 * request per slot goes over the shared muxes, in the client's own RESP
 * version, and a placeholder Req (creq) holds the client's reply position
 * until every sub has answered. */
enum { FAN_MGET, FAN_MSET, FAN_SUM };

struct FastFan {
    Req *creq;
    int kind, nsubs, ndone, nkeys;
    int dispatching; /* sub completions can't finish the fan while it's being built */
    long long sum;
    char *err;
    int err_len;
    int *key_sub, *key_pos; /* MGET: which sub, and which element of its reply */
    char **rep;             /* MGET: each sub's reply */
    int *rep_len;
};

static void fan_finish(Worker *w, struct FastFan *f) {
    char small[32];
    char *out = small;
    int len = 0;
    if (f->err) {
        out = f->err;
        len = f->err_len;
    } else if (f->kind == FAN_SUM) {
        len = snprintf(small, sizeof(small), ":%lld\r\n", f->sum);
    } else if (f->kind == FAN_MSET) {
        len = snprintf(small, sizeof(small), "+OK\r\n");
    } else {
        /* Element offsets within each sub reply, then splice in key order. */
        int **elem = calloc((size_t)f->nsubs, sizeof(int *));
        int total = 16, ok = elem != NULL;
        for (int s = 0; ok && s < f->nsubs; s++) {
            const char *b = f->rep[s];
            int bl = f->rep_len[s];
            const char *nl = (b && bl > 1 && b[0] == '*') ? memchr(b, '\n', (size_t)bl) : NULL;
            int n = nl ? atoi(b + 1) : -1;
            if (n < 0 || !(elem[s] = malloc(sizeof(int) * (size_t)(n + 1)))) {
                ok = 0;
                break;
            }
            int off = (int)(nl - b) + 1;
            for (int i = 0; i < n; i++) {
                int el = resp_response_len(b + off, bl - off);
                if (el <= 0) {
                    ok = 0;
                    break;
                }
                elem[s][i] = off;
                off += el;
            }
            elem[s][n] = off;
            total += off;
        }
        if (ok && (out = malloc((size_t)total))) {
            len = snprintf(out, 16, "*%d\r\n", f->nkeys);
            for (int k = 0; k < f->nkeys; k++) {
                int s = f->key_sub[k], i = f->key_pos[k];
                int el = elem[s][i + 1] - elem[s][i];
                memcpy(out + len, f->rep[s] + elem[s][i], (size_t)el);
                len += el;
            }
        } else {
            out = small;
            len = snprintf(small, sizeof(small), "-ERR bad backend response\r\n");
        }
        for (int s = 0; elem && s < f->nsubs; s++) free(elem[s]);
        free(elem);
    }
    req_deliver(w, f->creq, out, len);
    if (out != small && out != f->err) free(out);
    for (int s = 0; f->rep && s < f->nsubs; s++) free(f->rep[s]);
    free(f->err);
    free(f);
}

static void fan_sub_done(Worker *w, struct FastFan *f, int idx, const char *data, int len, int failed) {
    if (failed || (len > 0 && data[0] == '-')) {
        if (!f->err && (f->err = malloc((size_t)len))) {
            memcpy(f->err, data, (size_t)len);
            f->err_len = len;
        }
    } else if (f->kind == FAN_SUM) {
        if (len > 1 && data[0] == ':') f->sum += strtoll(data + 1, NULL, 10);
    } else if (f->kind == FAN_MGET) {
        if ((f->rep[idx] = malloc((size_t)len))) {
            memcpy(f->rep[idx], data, (size_t)len);
            f->rep_len[idx] = len;
        }
    }
    if (++f->ndone == f->nsubs && !f->dispatching) fan_finish(w, f);
}

/* Starts a fan-out command (or answers it with an error, in order). */
static void fan_dispatch(Worker *w, ClientConn *c, const char *cmd, const char *p, int total, int argc) {
    int kind = !strcmp(cmd, "MGET") ? FAN_MGET : !strcmp(cmd, "MSET") ? FAN_MSET : FAN_SUM;
    int stride = kind == FAN_MSET ? 2 : 1;
    if (argc < 1 + stride || (argc - 1) % stride) {
        char e[96], lc[24];
        int n = 0;
        for (; cmd[n] && n < 23; n++) lc[n] = (char)tolower((unsigned char)cmd[n]);
        lc[n] = '\0';
        snprintf(e, sizeof(e), "-ERR wrong number of arguments for '%s' command\r\n", lc);
        client_reply_ordered(w, c, e, (int)strlen(e));
        return;
    }
    int nargs = argc - 1, nkeys = nargs / stride;
    const char **ap = malloc(sizeof(char *) * (size_t)nargs);
    int *al = malloc(sizeof(int) * (size_t)nargs), *slot = malloc(sizeof(int) * (size_t)nkeys);
    if (!ap || !al || !slot) goto oom;
    /* Walk the (already validated) multibulk: skip "*N" and the command. */
    const char *q = memchr(p, '\n', (size_t)total) + 1;
    for (int i = -1; i < nargs; i++) {
        int l = atoi(q + 1);
        q = memchr(q, '\n', (size_t)(p + total - q)) + 1;
        if (i >= 0) {
            ap[i] = q;
            al[i] = l;
        }
        q += l + 2;
    }
    int one_slot = 1;
    for (int k = 0; k < nkeys; k++) {
        slot[k] = key_slot(ap[k * stride], al[k * stride]);
        int ni = w->topo.slot_map[slot[k]];
        if (ni < 0 || ni >= w->topo.node_count) {
            client_reply_error(w, c, "slot not mapped");
            goto done;
        }
        if (slot[k] != slot[0]) one_slot = 0;
    }

    if (one_slot) { /* the whole command can go to one node as-is */
        MuxConn *m = mux_for(w, c, w->topo.slot_map[slot[0]]);
        Req *r = m ? client_req_new(w, c) : NULL;
        if (!m) client_reply_error(w, c, "backend connection error");
        if (r) {
            req_keep_cmd(r, p, total);
            r->inflight_kind = 1;
            c->shared_inflight++;
            mux_enqueue(w, m, r, p, total);
        }
        goto done;
    }

    if (!w->fan_slot_sub) {
        w->fan_slot_sub = malloc(sizeof(int) * CLUSTER_SLOTS);
        w->fan_slot_gen = calloc(CLUSTER_SLOTS, sizeof(unsigned));
        if (!w->fan_slot_sub || !w->fan_slot_gen) goto oom;
    }
    if (++w->fan_gen == 0) { /* wrapped: stale stamps could look current */
        memset(w->fan_slot_gen, 0, sizeof(unsigned) * CLUSTER_SLOTS);
        w->fan_gen = 1;
    }
    int nsubs = 0;
    for (int k = 0; k < nkeys; k++) {
        int s = slot[k];
        if (w->fan_slot_gen[s] != w->fan_gen) {
            w->fan_slot_gen[s] = w->fan_gen;
            w->fan_slot_sub[s] = nsubs++;
        }
    }
    struct FastFan *f = calloc(1, sizeof(*f) + sizeof(int) * 2 * (size_t)nkeys + (sizeof(char *) + sizeof(int)) * (size_t)nsubs);
    if (!f) goto oom;
    f->kind = kind;
    f->nkeys = nkeys;
    f->nsubs = nsubs;
    f->key_sub = (int *)(f + 1);
    f->key_pos = f->key_sub + nkeys;
    f->rep = (char **)(f->key_pos + nkeys);
    f->rep_len = (int *)(f->rep + nsubs);
    if (!(f->creq = client_req_new(w, c))) {
        free(f);
        goto done;
    }
    f->creq->inflight_kind = 1;
    c->shared_inflight++;

    int *cnt = calloc((size_t)nsubs, sizeof(int));
    int *sub_node = malloc(sizeof(int) * (size_t)nsubs);
    if (!cnt || !sub_node) {
        free(cnt);
        free(sub_node);
        static const char OOM[] = "-ERR out of memory\r\n";
        if ((f->err = malloc(sizeof(OOM) - 1))) {
            memcpy(f->err, OOM, sizeof(OOM) - 1);
            f->err_len = (int)sizeof(OOM) - 1;
        }
        fan_finish(w, f); /* nothing was sent: answer the placeholder now */
        goto done;
    }
    for (int k = 0; k < nkeys; k++) {
        int s = w->fan_slot_sub[slot[k]];
        f->key_sub[k] = s;
        f->key_pos[k] = cnt[s]++;
        sub_node[s] = w->topo.slot_map[slot[k]];
    }

    f->dispatching = 1;
    int cl = (int)strlen(cmd);
    for (int s = 0; s < nsubs; s++) {
        /* "*<1+n>\r\n$<cl>\r\n<CMD>\r\n" + this slot's args */
        int need = 48 + cl;
        for (int k = 0; k < nkeys; k++)
            if (f->key_sub[k] == s)
                for (int j = 0; j < stride; j++) need += al[k * stride + j] + 16;
        char *buf = malloc((size_t)need);
        MuxConn *m = buf ? mux_for(w, c, sub_node[s]) : NULL;
        Req *r = m ? req_new(w) : NULL;
        if (!r) {
            free(buf);
            fan_sub_done(w, f, s, "-ERR backend connection error\r\n", 31, 1);
            continue;
        }
        int o = snprintf(buf, (size_t)need, "*%d\r\n$%d\r\n%s\r\n", 1 + cnt[s] * stride, cl, cmd);
        for (int k = 0; k < nkeys; k++) {
            if (f->key_sub[k] != s) continue;
            for (int j = 0; j < stride; j++) {
                int a = k * stride + j;
                o += snprintf(buf + o, (size_t)(need - o), "$%d\r\n", al[a]);
                memcpy(buf + o, ap[a], (size_t)al[a]);
                o += al[a];
                buf[o++] = '\r';
                buf[o++] = '\n';
            }
        }
        r->fan = f;
        r->fan_idx = s;
        req_keep_cmd(r, buf, o);
        mux_enqueue(w, m, r, buf, o);
        free(buf);
    }
    f->dispatching = 0;
    if (f->ndone == f->nsubs) fan_finish(w, f);
    free(cnt);
    free(sub_node);
    goto done;
oom:
    c->close_asap = 1;
    pw_add(w, c);
done:
    free(ap);
    free(al);
    free(slot);
}

/* PING / ECHO: answered locally, in order. */
static void local_reply(Worker *w, ClientConn *c, const char *cmd, const char *p, int total, int argc) {
    const char *a = NULL;
    int alen = 0;
    if (argc == 2 && !resp_get_nth_arg(p, total, 1, &a, &alen)) argc = -1;
    int is_ping = !strcmp(cmd, "PING");
    if (is_ping ? argc > 2 || argc < 1 : argc != 2) {
        char e[80];
        snprintf(e, sizeof(e), "-ERR wrong number of arguments for '%s' command\r\n", is_ping ? "ping" : "echo");
        client_reply_str(w, c, e);
        return;
    }
    if (argc == 1) {
        client_reply_str(w, c, "+PONG\r\n");
        return;
    }
    char hdr[24];
    int hl = snprintf(hdr, sizeof(hdr), "$%d\r\n", alen);
    char *out = malloc((size_t)(hl + alen + 2));
    if (!out) {
        c->close_asap = 1;
        pw_add(w, c);
        return;
    }
    memcpy(out, hdr, (size_t)hl);
    memcpy(out + hl, a, (size_t)alen);
    memcpy(out + hl + alen, "\r\n", 2);
    client_reply_ordered(w, c, out, hl + alen + 2);
    free(out);
}

/* Parses and dispatches as many complete commands from c->ibuf as can be
 * started right now. Stops at an incomplete command, at a legacy command
 * that has to wait for earlier fast-path replies, while a legacy command is
 * in progress, or under backpressure. */
void client_process_input(Worker *w, ClientConn *c) {
    int fd = c->fd;
    int incomplete = 0;
    while (!c->close_asap && !c->close_after_write && !client_legacy_busy(c)) {
        int avail = c->ibuf_len - c->ibuf_off;
        if (avail <= 0) break;
        const char *p = c->ibuf + c->ibuf_off;
        long long consume;

        if (p[0] != '*') {
            /* Inline command: one line, converted to RESP in c->conv. */
            const char *nl = memchr(p, '\n', (size_t)avail);
            if (!nl) {
                if (avail > MAX_INLINE_LINE) {
                    client_protocol_error(w, c, "Protocol error: too big inline request");
                    break;
                }
                c->ibuf_need = avail + 1;
                incomplete = 1;
                break;
            }
            int linelen = (int)(nl - p);
            consume = linelen + 1;
            if (linelen > 0 && p[linelen - 1] == '\r') linelen--;
            int rl = inline_to_resp(c, p, linelen);
            if (rl < 0) {
                client_protocol_error(w, c, "Protocol error: unbalanced quotes in request");
                break;
            }
            if (rl == 0) {
                c->ibuf_off += (int)consume;
                continue;
            }
            p = c->conv;
            avail = rl;
        } else {
            consume = 0;
        }

        const char *cp, *kp;
        int cl, kl, argc;
        long long total, need;
        int rc = scan_command(p, avail, &cp, &cl, &kp, &kl, &argc, &total, &need);
        if (rc < 0) {
            client_protocol_error(w, c, "protocol error");
            break;
        }
        if (rc == 0) {
            if (need > g_config.max_command_size) {
                client_protocol_error(w, c, "command too large");
                break;
            }
            c->ibuf_need = (int)need;
            incomplete = 1;
            break;
        }
        if (total > g_config.max_command_size) {
            client_protocol_error(w, c, "command too large");
            break;
        }
        if (!consume) consume = total;

        char cmd[64];
        int n = cl < 63 ? cl : 63;
        for (int i = 0; i < n; i++) cmd[i] = (char)toupper((unsigned char)cp[i]);
        cmd[n] = '\0';
        const CmdInfo *ci = cmd_info(cmd);

        /* WATCH/MULTI/EXEC/... and everything inside MULTI. Ordered through
         * the request queue like the fast path, so no need to wait. */
        if (!c->in_subscribe && !c->sub_conn && (ci || c->tx_state == 2)) {
            int tr = tx_handle(w, c, cmd, ci, p, (int)total, kp, kl, argc);
            if (tr == 2) break;
            if (tr == 1) {
                c->ibuf_off += (int)consume;
                continue;
            }
        }

        if (ci && (ci->fanout || ci->local) && !c->in_subscribe && !c->acl_authenticated && !c->sub_conn) {
            if (c->rq_count >= CLIENT_MAX_INFLIGHT || client_out_bytes(c) >= CLIENT_MAX_PENDING_OUT ||
                (ci->fanout && c->pin_inflight > 0))
                break;
            c->last_interaction = w->now;
            record_last_cmd(c, cmd, kp, kl);
            if (ci->local)
                local_reply(w, c, cmd, p, (int)total, argc);
            else
                fan_dispatch(w, c, cmd, p, (int)total, argc);
            c->ibuf_off += (int)consume;
            continue;
        }

        if (ci && ci->fast && kl > 0 && !c->in_subscribe && !c->acl_authenticated && !c->sub_conn) {
            if (c->rq_count >= CLIENT_MAX_INFLIGHT || client_out_bytes(c) >= CLIENT_MAX_PENDING_OUT ||
                c->pin_inflight > 0)
                break;
            c->last_interaction = w->now;
            int ln = n < (int)sizeof(c->last_cmd) - 1 ? n : (int)sizeof(c->last_cmd) - 1;
            for (int i = 0; i < ln; i++) c->last_cmd[i] = (char)tolower((unsigned char)cmd[i]);
            c->last_cmd[ln] = '\0';

            int node_idx = w->topo.slot_map[key_slot(kp, kl)];
            MuxConn *m = NULL;
            if (node_idx < 0 || node_idx >= w->topo.node_count)
                client_reply_error(w, c, "slot not mapped");
            else if (!(m = mux_for(w, c, node_idx)))
                client_reply_error(w, c, "backend connection error");
            else {
                Req *r = client_req_new(w, c);
                if (!r) break;
                req_keep_cmd(r, p, (int)total);
                r->inflight_kind = 1;
                c->shared_inflight++;
                mux_enqueue(w, m, r, p, (int)total);
            }
            c->ibuf_off += (int)consume;
            continue;
        }

        /* Legacy command: everything before it must be answered first. */
        if (c->rq_head || client_out_bytes(c) > 0) break;

        if (c->hbuf_cap < total) {
            char *tmp = realloc(c->hbuf, (size_t)total);
            if (!tmp) {
                c->close_asap = 1;
                pw_add(w, c);
                break;
            }
            c->hbuf = tmp;
            c->hbuf_cap = (int)total;
        }
        memcpy(c->hbuf, p, (size_t)total);
        c->hbuf_len = (int)total;
        c->ibuf_off += (int)consume;
        c->wbuf_off = c->wbuf_len = 0; /* legacy handlers write replies at wbuf[0] */

        char lcmd[64] = "", lkey[512] = "";
        int lcmdlen = 0, lkeylen = 0, largc = 0, ltotal = 0;
        resp_parse_header(c->hbuf, c->hbuf_len, lcmd, &lcmdlen, lkey, &lkeylen, &largc, &ltotal);
        str_toupper(lcmd);
        legacy_dispatch(w, c, lcmd, lcmdlen, lkey, lkeylen, largc, (int)total);
        if (fd >= g_config.max_connection || w->client_map[fd] != c) return; /* closed */
    }

    if (c->ibuf_off == c->ibuf_len) c->ibuf_off = c->ibuf_len = 0;
    if (!incomplete) c->ibuf_need = 0;
    if (c->eof && !c->close_after_write && !c->close_asap) {
        if (client_parked(c)) {
            c->close_asap = 1; /* nothing it waits for is worth keeping it */
            pw_add(w, c);
        } else if (c->ibuf_len == c->ibuf_off || incomplete) {
            /* Everything the client sent before hanging up has been started
             * (a trailing partial command can never complete): close once
             * the replies in flight are done -- or fail to write. */
            c->close_after_write = 1;
            c->read_paused = 0;
            pw_add(w, c);
        }
    }
    if ((c->ibuf_len > c->ibuf_off && !incomplete) || c->read_paused)
        bl_add(w, c);
    else
        bl_remove(w, c);
}

/* Advances a client's server-side TLS handshake; once done, carries on with
 * whatever the client already sent behind it. */
void client_tls_continue(Worker *w, ClientConn *c) {
#ifdef USE_TLS
    int want;
    int rc = tls_handshake(c->ssl, &want);
    if (rc < 0) {
        LOG_VERBOSE("[worker %d] TLS handshake failed for %s\n", w->thread_id, c->addr);
        close_client(w, c);
        return;
    }
    if (rc == 0) {
        if (want == EL_WRITABLE) {
            if (!(w->fd_mask[c->fd] & EL_WRITABLE)) fd_watch(w, c->fd, EL_WRITABLE);
        } else if (w->fd_mask[c->fd] & EL_WRITABLE) {
            fd_unwatch(w, c->fd, EL_WRITABLE);
        }
        return;
    }
    c->tls_hs = 0;
    if (w->fd_mask[c->fd] & EL_WRITABLE) fd_unwatch(w, c->fd, EL_WRITABLE);
    if (g_config.verbose) {
        char d[128];
        printf("[worker %d] client %s TLS %s\n", w->thread_id, c->addr, tls_describe(c->ssl, d, sizeof(d)));
    }
    handle_client_readable(w, c);
#else
    (void)w;
    (void)c;
#endif
}


void handle_client_readable(Worker *w, ClientConn *c) {
    int fd = c->fd;
    if (c->tls_hs) {
        client_tls_continue(w, c);
        return;
    }
    if (c->ssl_write_wants_read) {
        c->ssl_write_wants_read = 0;
        pw_add(w, c);
    }
    for (;;) {
        int unparsed = c->ibuf_len - c->ibuf_off;
        if (unparsed >= CLIENT_READ_PAUSE && unparsed >= c->ibuf_need) {
            client_process_input(w, c);
            if (fd >= g_config.max_connection || w->client_map[fd] != c) return;
            unparsed = c->ibuf_len - c->ibuf_off;
            if (unparsed >= CLIENT_READ_PAUSE && unparsed >= c->ibuf_need) {
                /* Edge-triggered: nothing re-reports what's left in the
                 * socket, so the backlog pass resumes reading for us. */
                c->read_paused = 1;
                bl_add(w, c);
                return;
            }
        }
        int want = IO_CHUNK;
        if (c->ibuf_need > c->ibuf_len - c->ibuf_off) {
            int missing = c->ibuf_need - (c->ibuf_len - c->ibuf_off);
            if (missing > want) want = missing;
        }
        if (buf_reserve(&c->ibuf, &c->ibuf_len, &c->ibuf_off, &c->ibuf_cap, want) < 0) {
            close_client(w, c);
            return;
        }
        int space = c->ibuf_cap - c->ibuf_len, tls_want;
        ssize_t n = net_read(fd, c->ssl, c->ibuf + c->ibuf_len, (size_t)space, &tls_want);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                if (tls_want == EL_WRITABLE) {
                    c->ssl_read_wants_write = 1;
                    if (!(w->fd_mask[fd] & EL_WRITABLE)) fd_watch(w, fd, EL_WRITABLE);
                }
                break;
            }
            close_client(w, c);
            return;
        }
        if (n == 0) {
            /* Like Valkey: commands that arrived with the hang-up still
             * run; client_process_input() closes once nothing's left. */
            c->eof = 1;
            break;
        }
        c->ibuf_len += (int)n;
        c->last_interaction = w->now;
        /* A short read means drained, unless the peer has hung up: then the
         * EOF behind the data gets no event of its own. */
        if (n < space && net_short_read_drained(c->ssl) && !c->peer_closed) break;
    }
    c->read_paused = 0;
    client_process_input(w, c);
}

/* ── client output ──────────────────────────────────────────────────── */
/* Writes as much of c->wbuf as the socket takes. Returns -1 if c was closed. */
/* All output is on the wire: deferred close, or the end of a legacy reply.
 * Returns -1 if c was closed. */
int client_output_drained(Worker *w, ClientConn *c) {
    if (c->state == CS_WRITING_RESP) {
        /* A legacy reply just finished going out. */
        c->state = CS_READING_HDR;
        c->hbuf_len = 0;
        c->using_pbuf = 0;
        c->pbuf_len = 0;
        fd_watch(w, c->fd, EL_READABLE);
    }
    /* Deferred close (protocol error, or the client hung up): only once
     * every reply it's owed has gone out -- the error reply may still be
     * queued behind in-flight ones, and a legacy command may still be
     * running (unless it's one that can wait forever). */
    if (c->close_after_write && !c->rq_head && (!client_legacy_busy(c) || client_parked(c))) {
        close_client(w, c);
        return -1;
    }
    return 0;
}

int client_flush(Worker *w, ClientConn *c) {
    if (c->close_asap) {
        close_client(w, c);
        return -1;
    }
    if (c->tls_hs) return 0; /* replies wait for the handshake (can't happen in practice) */
    while (c->wbuf_off < c->wbuf_len) {
        int want;
        ssize_t n = net_write(c->fd, c->ssl, c->wbuf + c->wbuf_off, (size_t)(c->wbuf_len - c->wbuf_off), &want);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                if (want == EL_READABLE)
                    c->ssl_write_wants_read = 1; /* handle_client_readable() retries */
                else if (!(w->fd_mask[c->fd] & EL_WRITABLE))
                    fd_watch(w, c->fd, EL_WRITABLE);
                return 0;
            }
            close_client(w, c);
            return -1;
        }
        c->wbuf_off += (int)n;
        c->last_interaction = w->now; /* replies count as activity, as in Valkey */
    }
    c->wbuf_off = c->wbuf_len = 0;
    if ((w->fd_mask[c->fd] & EL_WRITABLE) && !c->ssl_read_wants_write) fd_unwatch(w, c->fd, EL_WRITABLE);
    return client_output_drained(w, c);
}

/* ── per-iteration work ─────────────────────────────────────────────── */
static int client_input_ready(ClientConn *c) {
    if (c->close_asap || c->close_after_write) return 0;
    if (c->read_paused) return c->ibuf_len - c->ibuf_off < CLIENT_READ_PAUSE;
    return !client_legacy_busy(c) && !c->rq_head && client_out_bytes(c) == 0;
}

static void process_backlog(Worker *w) {
    ClientConn *c = w->bl_head;
    while (c) {
        ClientConn *next = c->bl_next;
        unsigned seq = w->close_seq;
        if (c->read_paused) {
            if (c->ibuf_len - c->ibuf_off < CLIENT_READ_PAUSE) handle_client_readable(w, c);
        } else if (c->state == CS_READING_HDR && !c->close_asap && !c->close_after_write) {
            client_process_input(w, c);
        }
        /* Processing one client can, rarely, close another (legacy pool
         * hand-off paths), so `next` can't be trusted after any close; the
         * rest wait for the next iteration (worker_has_ready_backlog() keeps
         * that from blocking). */
        if (seq != w->close_seq) break;
        c = next;
    }
}

void worker_after_events(Worker *w) {
    process_backlog(w);
    MuxConn *m;
    while ((m = w->pf_head)) {
        pf_remove(w, m);
        mux_flush(w, m);
    }
    ClientConn *c;
    while ((c = w->pw_head)) {
        pw_remove(w, c);
        client_flush(w, c);
    }
}

/* ── timeouts ─────────────────────────────────────────────────────────── */
void mux_check_connect_timeouts(Worker *w) {
    if (!w->ct_head) return;
    long long now = mono_ms();
    for (MuxConn *m = w->ct_head; m;) {
        if (now < m->connect_deadline) {
            m = m->ct_next;
            continue;
        }
        /* Failing m replies to its requests, which can close clients and,
         * through them, other muxes: restart from the head. */
        mux_fail(w, m, m->connecting ? "backend connect timeout" : "backend TLS handshake timeout");
        m = w->ct_head;
    }
}

int worker_sweep_interval_ms(Worker *w) {
    if (w->ct_head) return 100; /* connect deadlines pending */
    if (atomic_load_explicit(&g_shutdown, memory_order_relaxed)) return 100;
    return (g_config.client_timeout > 0 || (g_config.tls_enabled && g_config.tls_handshake_timeout > 0)) ? 1000 : -1;
}

/* Like Valkey's "timeout": idle clients are closed, except ones that are
 * legitimately waiting -- blocked in a legacy command (BLPOP etc.), with
 * replies still in flight, or subscribed. Clients that never finished their
 * TLS handshake get tls-handshake-timeout seconds. */
void worker_sweep_clients(Worker *w) {
    if (w->now == w->last_sweep) return;
    w->last_sweep = w->now;
    int idle = g_config.client_timeout, hs = g_config.tls_handshake_timeout;
    for (int fd = 0; fd < g_config.max_connection; fd++) {
        ClientConn *c = w->client_map[fd];
        if (!c) continue;
        if (c->tls_hs) {
            if (hs > 0 && w->now - c->connect_time >= hs) {
                LOG_VERBOSE("[worker %d] closing %s: TLS handshake timeout\n", w->thread_id, c->addr);
                close_client(w, c);
            }
            continue;
        }
        if (idle <= 0 || w->now - c->last_interaction <= idle) continue; /* Valkey: idle > timeout */
        if (client_legacy_busy(c) || c->rq_head || c->in_subscribe || c->sub_conn || client_out_bytes(c) > 0)
            continue;
        LOG_VERBOSE("[worker %d] closing %s: idle for %lds\n", w->thread_id, c->addr, (long)(w->now - c->last_interaction));
        close_client(w, c);
    }
}

void worker_drain(Worker *w) {
    if (!w->draining) {
        w->draining = 1;
        /* A per-worker listener can simply be closed: new connections go
         * elsewhere (or are refused). A shared one is only unwatched. */
        if (w->listen_fd >= 0) {
            fd_unwatch(w, w->listen_fd, EL_READABLE);
            if (g_listen_per_worker) close(w->listen_fd);
            w->listen_fd = -1;
        }
        if (g_unix_fd >= 0) fd_unwatch(w, g_unix_fd, EL_READABLE);
    }
    for (int fd = 0; fd < g_config.max_connection; fd++) {
        ClientConn *c = w->client_map[fd];
        if (!c || c->tls_hs) {
            if (c) close_client(w, c);
            continue;
        }
        /* Subscribers never go quiet on their own: let them reconnect
         * elsewhere. Everyone else first gets every reply it's owed. */
        int subscribed = c->in_subscribe || c->sub_conn;
        if (!subscribed && (client_legacy_busy(c) || c->rq_head || c->tx_state || c->ibuf_len > c->ibuf_off))
            continue;
        if (client_out_bytes(c) > 0) continue;
        close_client(w, c);
    }
}

int worker_has_ready_backlog(Worker *w) {
    for (ClientConn *c = w->bl_head; c; c = c->bl_next)
        if (client_input_ready(c)) return 1;
    return 0;
}
