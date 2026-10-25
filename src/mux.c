#include "proxy.h"
#include <netinet/tcp.h>

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
    memset(r, 0, sizeof(*r));
    return r;
}
static void req_free(Worker *w, Req *r) {
    free(r->reply);
    r->reply = NULL;
    r->mnext = w->req_free;
    w->req_free = r;
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

/* Request r (already off any mux FIFO) has its reply. If it's next in its
 * client's order, write it straight to the client along with any later
 * replies that were held back waiting for it; otherwise park a copy. */
static void req_deliver(Worker *w, Req *r, const char *data, int len) {
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
static void mux_destroy(Worker *w, MuxConn *m) {
    pf_remove(w, m);
    if (m->owner) {
        for (int i = 0; i < 2; i++)
            if (m->owner->mux[i] == m) m->owner->mux[i] = NULL;
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
        req_deliver(w, r, err, n);
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

static MuxConn *mux_for(Worker *w, ClientConn *c, int node_idx) {
    if (!c->fast_np || c->fast_db != c->db) {
        DbGroup *grp = db_group_get(w, c->db);
        if (!grp) return NULL;
        c->fast_np = grp->node_pools;
        c->fast_db = c->db;
    }
    NodePools *np = &c->fast_np[node_idx];
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
            req_deliver(w, r, m->rbuf + m->rbuf_off, rl);
            m->rbuf_off += rl;
        }
        if (n < space) break; /* socket drained (edge-triggered: no more data until next edge) */
    }
    if (m->draining && m->inflight == 0) mux_destroy(w, m);
}

/* Topology moved node np->node_idx to a new identity (failover / eviction --
 * see worker_sync_topology()). Its muxes stop taking new requests; if the
 * node still owns slots the in-flight ones are allowed to finish, otherwise
 * nothing will ever answer them, so they fail now. */
void mux_node_changed(Worker *w, NodePools *np, int still_owns_slots) {
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

        char cmd[64];
        int n = cl < 63 ? cl : 63;
        for (int i = 0; i < n; i++) cmd[i] = (char)toupper((unsigned char)cp[i]);
        cmd[n] = '\0';
        const CmdInfo *ci = cmd_info(cmd);

        if (ci && ci->fast && kl > 0 && !c->in_transaction && !c->in_subscribe && !c->acl_authenticated &&
            !c->sub_conn) {
            if (c->rq_count >= CLIENT_MAX_INFLIGHT || c->wbuf_len - c->wbuf_off >= CLIENT_MAX_PENDING_OUT) break;
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
                Req *r = req_new(w);
                if (!r) {
                    c->close_asap = 1;
                    pw_add(w, c);
                    break;
                }
                r->client = c;
                if (c->rq_tail)
                    c->rq_tail->cnext = r;
                else
                    c->rq_head = r;
                c->rq_tail = r;
                c->rq_count++;
                mux_enqueue(w, m, r, p, (int)total);
            }
            c->ibuf_off += (int)total;
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
        c->ibuf_off += (int)total;
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
