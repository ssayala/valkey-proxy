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
static void req_deliver_ex(Worker *w, Req *r, const char *data, int len, int failed) {
    if (r->client && r->inflight_kind) {
        if (r->inflight_kind == 2)
            r->client->pin_inflight--;
        else
            r->client->shared_inflight--;
        r->inflight_kind = 0;
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
        close(m->fd);
    }
    free(m->obuf);
    free(m->rbuf);
    free(m);
}

/* Backend connection lost (or node gone): every request still waiting on it
 * gets an error reply, in order, and the mux is freed. */
static void mux_fail(Worker *w, MuxConn *m, const char *msg) {
    const ClusterNode *nd = &w->topo.nodes[m->node_idx];
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

static void mux_enqueue(Worker *w, MuxConn *m, Req *r, const char *data, int len) {
    if (m->obuf_off == m->obuf_len) m->obuf_off = m->obuf_len = 0;
    if (buf_reserve(&m->obuf, &m->obuf_len, &m->obuf_off, &m->obuf_cap, len) < 0) {
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

static void mux_internal_cmd(Worker *w, MuxConn *m, const char *cmd, int len) {
    Req *r = req_new(w);
    if (!r) return;
    r->internal = 1;
    mux_enqueue(w, m, r, cmd, len);
}

static MuxConn *mux_create(Worker *w, NodePools *np, int db, int resp) {
    const ClusterNode *nd = &w->topo.nodes[np->node_idx];
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)nd->port);
    if (inet_pton(AF_INET, nd->ip, &a.sin_addr) != 1) return NULL;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    if (fd >= g_config.max_connection) {
        close(fd);
        return NULL;
    }
    set_nonblocking(fd);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
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
    w->mux_map[fd] = m;
    fd_watch(w, fd, EL_READABLE | (m->connecting ? EL_WRITABLE : 0));

    /* Connection setup rides the same pipeline as the first real commands;
     * these replies are swallowed (see req_deliver()). */
    if (resp == 3) {
        static const char HELLO3[] = "*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n";
        mux_internal_cmd(w, m, HELLO3, (int)sizeof(HELLO3) - 1);
    }
    if (db != 0) {
        char dbs[16], sel[64];
        int dl = snprintf(dbs, sizeof(dbs), "%d", db);
        int n = snprintf(sel, sizeof(sel), "*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n", dl, dbs);
        mux_internal_cmd(w, m, sel, n);
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
    if (m->connecting) return; /* handle_mux_writable() flushes once connected */
    while (m->obuf_off < m->obuf_len) {
        ssize_t n = write(m->fd, m->obuf + m->obuf_off, (size_t)(m->obuf_len - m->obuf_off));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                if (!(w->fd_mask[m->fd] & EL_WRITABLE)) fd_watch(w, m->fd, EL_WRITABLE);
                return;
            }
            mux_fail(w, m, "backend connection error");
            return;
        }
        m->obuf_off += (int)n;
    }
    m->obuf_off = m->obuf_len = 0;
    if (w->fd_mask[m->fd] & EL_WRITABLE) fd_unwatch(w, m->fd, EL_WRITABLE);
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
    if (!r->cmd || r->redirects >= MAX_REDIRECTS || (!r->client && !r->sub)) return 0;

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
    for (int i = 0; i < w->topo.node_count; i++)
        if (w->topo.nodes[i].port == port && (int)strlen(w->topo.nodes[i].ip) == hlen &&
            !memcmp(w->topo.nodes[i].ip, host, (size_t)hlen)) {
            idx = i;
            break;
        }
    if (idx < 0) return 0; /* unknown node: let the refresh find it, pass the error on */
    if (!ask) w->topo.slot_map[slot] = idx;

    MuxConn *t = mux_for_db(w, m->db, idx, m->resp);
    if (!t) return 0;
    if (ask) {
        static const char ASKING[] = "*1\r\n$6\r\nASKING\r\n";
        mux_internal_cmd(w, t, ASKING, (int)sizeof(ASKING) - 1);
    }
    r->redirects++;
    LOG_VERBOSE("[worker %d] %s slot %d -> %s:%d\n", w->thread_id, ask ? "ASK" : "MOVED", slot,
                w->topo.nodes[idx].ip, port);
    mux_enqueue(w, t, r, r->cmd, r->cmd_len);
    return 1;
}

void handle_mux_readable(Worker *w, MuxConn *m) {
    for (;;) {
        if (m->rbuf_off == m->rbuf_len) m->rbuf_off = m->rbuf_len = 0;
        if (buf_reserve(&m->rbuf, &m->rbuf_len, &m->rbuf_off, &m->rbuf_cap, IO_CHUNK) < 0) {
            mux_fail(w, m, "out of memory");
            return;
        }
        int space = m->rbuf_cap - m->rbuf_len;
        ssize_t n = read(m->fd, m->rbuf + m->rbuf_len, (size_t)space);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) break;
            mux_fail(w, m, "backend connection error");
            return;
        }
        if (n == 0) {
            mux_fail(w, m, "backend connection closed");
            return;
        }
        m->rbuf_len += (int)n;

        while (m->rbuf_off < m->rbuf_len) {
            int rl = resp_response_len(m->rbuf + m->rbuf_off, m->rbuf_len - m->rbuf_off);
            if (rl == 0) {
                if (m->rbuf_len - m->rbuf_off > MAX_RESP_SIZE) {
                    mux_fail(w, m, "response too large");
                    return;
                }
                break;
            }
            Req *r = m->head;
            if (rl < 0 || !r) {
                mux_fail(w, m, "bad backend response");
                return;
            }
            m->head = r->mnext;
            if (!m->head) m->tail = NULL;
            m->inflight--;
            r->mnext = NULL;
            const char *reply = m->rbuf + m->rbuf_off;
            m->rbuf_off += rl;
            if (reply[0] == '-' && !r->internal && !m->pin_client && mux_try_redirect(w, m, r, reply, rl)) continue;
            req_deliver(w, r, reply, rl);
        }
        if (n < space) break; /* socket drained (edge-triggered: no more data until next edge) */
    }
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
    Req *r = m ? req_new(w) : NULL;
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
static int scan_command(const char *buf, int len, const char **cmd, int *cmdlen, const char **key, int *keylen,
                        int *argc_out, long long *total, long long *need) {
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
static int inline_to_resp(ClientConn *c, const char *line, int len) {
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
            if (auth) {
                mux_internal_cmd(w, m, auth, n);
                free(auth);
            }
        }
    }
    m->pin_client = c;
    m->reusable = !c->acl_authenticated;
    m->draining = 0;
    c->pin = m;
    return m;
}

static void tx_forward(Worker *w, ClientConn *c, const char *p, int len) {
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
        if (c->pin) mux_internal_cmd(w, c->pin, "*1\r\n$7\r\nDISCARD\r\n", 17);
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
    mux_internal_cmd(w, c->pin, "*1\r\n$5\r\nMULTI\r\n", 15);
    for (int off = 0; off < c->txq_len;) {
        const char *q = c->txq + off;
        const char *cp2, *kp2;
        int cl2, kl2, argc2;
        long long tot2, need2;
        if (scan_command(q, c->txq_len - off, &cp2, &cl2, &kp2, &kl2, &argc2, &tot2, &need2) != 1) break;
        mux_internal_cmd(w, c->pin, q, (int)tot2);
        off += (int)tot2;
    }
    c->txq_len = 0;
    tx_forward(w, c, p, len);
    if (is_exec) tx_end(w, c);
    return 1;
}

/* Parses and dispatches as many complete commands from c->ibuf as can be
 * started right now. Stops at an incomplete command, at a legacy command
 * that has to wait for earlier fast-path replies, while a legacy command is
 * in progress, or under backpressure. */
void client_process_input(Worker *w, ClientConn *c) {
    int fd = c->fd;
    int incomplete = 0;
    while (!c->close_asap && !c->close_after_write && c->state == CS_READING_HDR) {
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

        if (ci && ci->fast && kl > 0 && !c->in_subscribe && !c->acl_authenticated && !c->sub_conn) {
            if (c->rq_count >= CLIENT_MAX_INFLIGHT || c->wbuf_len - c->wbuf_off >= CLIENT_MAX_PENDING_OUT ||
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
        if (c->rq_head || c->wbuf_len > c->wbuf_off) break;

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
    if ((c->ibuf_len > c->ibuf_off && !incomplete) || c->read_paused)
        bl_add(w, c);
    else
        bl_remove(w, c);
}

void handle_client_readable(Worker *w, ClientConn *c) {
    int fd = c->fd;
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
        int space = c->ibuf_cap - c->ibuf_len;
        ssize_t n = read(fd, c->ibuf + c->ibuf_len, (size_t)space);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) break;
            close_client(w, c);
            return;
        }
        if (n == 0) {
            close_client(w, c);
            return;
        }
        c->ibuf_len += (int)n;
        if (n < space) break;
    }
    c->read_paused = 0;
    client_process_input(w, c);
}

/* ── client output ──────────────────────────────────────────────────── */
/* Writes as much of c->wbuf as the socket takes. Returns -1 if c was closed. */
int client_flush(Worker *w, ClientConn *c) {
    if (c->close_asap) {
        close_client(w, c);
        return -1;
    }
    while (c->wbuf_off < c->wbuf_len) {
        ssize_t n = write(c->fd, c->wbuf + c->wbuf_off, (size_t)(c->wbuf_len - c->wbuf_off));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                if (!(w->fd_mask[c->fd] & EL_WRITABLE)) fd_watch(w, c->fd, EL_WRITABLE);
                return 0;
            }
            close_client(w, c);
            return -1;
        }
        c->wbuf_off += (int)n;
    }
    c->wbuf_off = c->wbuf_len = 0;
    if (c->close_after_write && !c->rq_head) { /* the error reply may still be queued behind in-flight ones */
        close_client(w, c);
        return -1;
    }
    if (w->fd_mask[c->fd] & EL_WRITABLE) fd_unwatch(w, c->fd, EL_WRITABLE);
    if (c->state == CS_WRITING_RESP) {
        /* A legacy reply just finished going out. */
        c->state = CS_READING_HDR;
        c->hbuf_len = 0;
        c->using_pbuf = 0;
        c->pbuf_len = 0;
        fd_watch(w, c->fd, EL_READABLE);
    }
    return 0;
}

/* ── per-iteration work ─────────────────────────────────────────────── */
static int client_input_ready(ClientConn *c) {
    if (c->close_asap || c->close_after_write) return 0;
    if (c->read_paused) return c->ibuf_len - c->ibuf_off < CLIENT_READ_PAUSE;
    return c->state == CS_READING_HDR && !c->rq_head && c->wbuf_len == c->wbuf_off;
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

int worker_has_ready_backlog(Worker *w) {
    for (ClientConn *c = w->bl_head; c; c = c->bl_next)
        if (client_input_ready(c)) return 1;
    return 0;
}
