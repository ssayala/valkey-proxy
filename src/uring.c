#include "proxy.h"

/* ── io_uring I/O (USE_IOURING builds, "io-uring yes") ──────────────────
 *
 * With epoll every plain-TCP client and backend socket costs a read() and a
 * write() syscall per event-loop iteration it's active in. Here those
 * sockets switch from readiness to completions instead:
 *
 *   - each keeps one receive posted straight into its input buffer
 *     (ClientConn.ibuf / MuxConn.rbuf), re-posted after every completion;
 *   - output is handed to the kernel as a send of the whole pending buffer,
 *     swapped out of wbuf/obuf so new replies can keep being appended while
 *     it's in flight (the kernel reads from it until the completion);
 *   - all of an iteration's submissions go in with the single
 *     io_uring_enter() that also waits for the next completions.
 *
 * Everything else -- listeners, the wake pipe, TLS connections (OpenSSL
 * drives its own socket I/O), the legacy pool connections -- stays on epoll;
 * the epoll fd itself is polled through the ring so one wait covers both.
 *
 * A buffer the kernel may still be writing into or reading from is never
 * moved or freed: while a receive is posted the input buffer isn't
 * compacted, and when a connection goes away with an op still in flight the
 * op is cancelled and takes ownership of the buffer, freeing it (and
 * itself) when the cancellation completes. */

#ifdef USE_IOURING
#include <liburing.h>
#include <poll.h>

enum { UOP_EPOLL = 1, UOP_CRECV, UOP_CSEND, UOP_MRECV, UOP_MSEND };

#define RING_ENTRIES     4096
#define SPARE_BUF_MAX    (1024 * 1024) /* don't keep larger send buffers around for reuse */

static struct io_uring *ring_of(Worker *w) {
    return (struct io_uring *)w->ring;
}

static struct io_uring_sqe *get_sqe(Worker *w) {
    struct io_uring *r = ring_of(w);
    struct io_uring_sqe *sqe = io_uring_get_sqe(r);
    if (!sqe) {
        io_uring_submit(r); /* SQ full: push this batch out early */
        sqe = io_uring_get_sqe(r);
    }
    return sqe;
}

static UOp *uop_new(int kind, void *owner) {
    UOp *op = calloc(1, sizeof(UOp));
    if (op) {
        op->kind = kind;
        op->owner = owner;
    }
    return op;
}

static void uop_cancel(Worker *w, UOp *op) {
    struct io_uring_sqe *sqe = get_sqe(w);
    if (!sqe) return; /* still completes eventually (peer close / reset) */
    io_uring_prep_cancel(sqe, op, 0);
    io_uring_sqe_set_data(sqe, NULL);
}

/* Connection going away: ops still in the kernel become orphans that own
 * the buffers they point into; idle ones are freed now. */
static void uop_release(Worker *w, UOp *op, char **recv_buf) {
    if (!op) return;
    if (op->active) {
        op->owner = NULL;
        if (recv_buf) {
            op->buf = *recv_buf;
            *recv_buf = NULL;
        }
        uop_cancel(w, op);
    } else {
        if (!recv_buf) free(op->buf); /* send op's spare buffer */
        free(op);
    }
}

/* Moves the pending output buf[off..len) into the send op (giving the op's
 * idle spare buffer back to the connection) and posts it. */
static void uop_send(Worker *w, int fd, UOp *op, char **buf, int *len, int *off, int *cap) {
    char *spare = op->buf;
    int spare_cap = op->cap;
    op->buf = *buf;
    op->cap = *cap;
    op->off = *off;
    op->len = *len;
    *buf = spare;
    *cap = spare ? spare_cap : 0;
    *len = *off = 0;
    struct io_uring_sqe *sqe = get_sqe(w);
    io_uring_prep_send(sqe, fd, op->buf + op->off, (size_t)(op->len - op->off), MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, op);
    op->active = 1;
}

/* After a send op fully completed: keep its buffer as the next spare. */
static void uop_send_done(UOp *op) {
    op->len = op->off = 0;
    if (op->cap > SPARE_BUF_MAX) {
        free(op->buf);
        op->buf = NULL;
        op->cap = 0;
    }
}

static void uop_resend(Worker *w, int fd, UOp *op) {
    struct io_uring_sqe *sqe = get_sqe(w);
    io_uring_prep_send(sqe, fd, op->buf + op->off, (size_t)(op->len - op->off), MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, op);
    op->active = 1;
}

/* ── clients ────────────────────────────────────────────────────────── */
void uring_attach_client(Worker *w, ClientConn *c) {
    c->rop = uop_new(UOP_CRECV, c);
    c->sop = uop_new(UOP_CSEND, c);
    if (!c->rop || !c->sop) {
        free(c->rop);
        free(c->sop);
        c->rop = c->sop = NULL;
        fd_watch(w, c->fd, EL_READABLE); /* fall back to epoll for this one */
        return;
    }
    c->uring = 1;
    w->uring_fd[c->fd] = 1;
    uring_client_recv(w, c);
}

void uring_detach_client(Worker *w, ClientConn *c) {
    if (c->fd >= 0 && c->fd < g_config.max_connection) w->uring_fd[c->fd] = 0;
    uop_release(w, c->rop, &c->ibuf);
    uop_release(w, c->sop, NULL);
    c->rop = c->sop = NULL;
    c->uring = 0;
}

void uring_client_recv(Worker *w, ClientConn *c) {
    if (c->rop->active || c->read_paused || c->close_asap) return;
    if (client_recv_reserve(c) < 0) {
        c->close_asap = 1;
        worker_want_flush(w, c->fd);
        return;
    }
    struct io_uring_sqe *sqe = get_sqe(w);
    io_uring_prep_recv(sqe, c->fd, c->ibuf + c->ibuf_len, (size_t)(c->ibuf_cap - c->ibuf_len), 0);
    io_uring_sqe_set_data(sqe, c->rop);
    c->rop->active = 1;
}

int uring_client_send(Worker *w, ClientConn *c) {
    if (c->sop->active) return 0; /* the completion sends whatever piled up meanwhile */
    if (c->wbuf_len == c->wbuf_off) return client_output_drained(w, c);
    uop_send(w, c->fd, c->sop, &c->wbuf, &c->wbuf_len, &c->wbuf_off, &c->wbuf_cap);
    return 0;
}

static void client_recv_done(Worker *w, ClientConn *c, int res) {
    c->rop->active = 0;
    if (res == -EINTR || res == -EAGAIN || res == -ENOBUFS) {
        uring_client_recv(w, c);
        return;
    }
    if (res <= 0) {
        close_client(w, c);
        return;
    }
    if (client_on_recv(w, c, res) == 1) uring_client_recv(w, c);
}

static void client_send_done(Worker *w, ClientConn *c, int res) {
    UOp *op = c->sop;
    op->active = 0;
    if (res == -EINTR || res == -EAGAIN) {
        uop_resend(w, c->fd, op);
        return;
    }
    if (res < 0) {
        close_client(w, c);
        return;
    }
    op->off += res;
    c->last_interaction = w->now; /* replies count as activity, as in Valkey */
    if (op->off < op->len) {
        uop_resend(w, c->fd, op);
        return;
    }
    uop_send_done(op);
    uring_client_send(w, c);
}

/* ── backend muxes ──────────────────────────────────────────────────── */
static void uring_mux_recv(Worker *w, MuxConn *m) {
    if (m->rop->active) return;
    struct io_uring_sqe *sqe = get_sqe(w);
    io_uring_prep_recv(sqe, m->fd, m->rbuf + m->rbuf_len, (size_t)(m->rbuf_cap - m->rbuf_len), 0);
    io_uring_sqe_set_data(sqe, m->rop);
    m->rop->active = 1;
}

void uring_attach_mux(Worker *w, MuxConn *m) {
    m->rop = uop_new(UOP_MRECV, m);
    m->sop = uop_new(UOP_MSEND, m);
    if (!m->rop || !m->sop) {
        free(m->rop);
        free(m->sop);
        m->rop = m->sop = NULL;
        fd_watch(w, m->fd, EL_READABLE);
        return;
    }
    /* Off epoll (it may have been watched for connect completion). */
    if (w->fd_mask[m->fd]) fd_unwatch(w, m->fd, EL_READABLE | EL_WRITABLE);
    m->uring = 1;
    w->uring_fd[m->fd] = 1;
    if (mux_on_recv(w, m, 0) < 0) return; /* reserves rbuf space */
    uring_mux_recv(w, m);
}

void uring_detach_mux(Worker *w, MuxConn *m) {
    if (m->fd >= 0 && m->fd < g_config.max_connection) w->uring_fd[m->fd] = 0;
    uop_release(w, m->rop, &m->rbuf);
    uop_release(w, m->sop, NULL);
    m->rop = m->sop = NULL;
    m->uring = 0;
}

void uring_mux_send(Worker *w, MuxConn *m) {
    if (m->sop->active || m->obuf_len == m->obuf_off) return;
    uop_send(w, m->fd, m->sop, &m->obuf, &m->obuf_len, &m->obuf_off, &m->obuf_cap);
}

static void mux_recv_done(Worker *w, MuxConn *m, int res) {
    m->rop->active = 0;
    if (res == -EINTR || res == -EAGAIN || res == -ENOBUFS) {
        uring_mux_recv(w, m);
        return;
    }
    if (res <= 0) {
        mux_fail(w, m, res == 0 ? "backend connection closed" : "backend connection error");
        return;
    }
    if (mux_on_recv(w, m, res) == 0) uring_mux_recv(w, m);
}

static void mux_send_done(Worker *w, MuxConn *m, int res) {
    UOp *op = m->sop;
    op->active = 0;
    if (res == -EINTR || res == -EAGAIN) {
        uop_resend(w, m->fd, op);
        return;
    }
    if (res < 0) {
        mux_fail(w, m, "backend connection error");
        return;
    }
    op->off += res;
    if (op->off < op->len) {
        uop_resend(w, m->fd, op);
        return;
    }
    uop_send_done(op);
    uring_mux_send(w, m);
}

/* ── loop ───────────────────────────────────────────────────────────── */
static UOp epoll_op_storage[MAX_WORKERS];

static void arm_epoll(Worker *w) {
    UOp *op = &epoll_op_storage[w->thread_id];
    op->kind = UOP_EPOLL;
    struct io_uring_sqe *sqe = get_sqe(w);
    io_uring_prep_poll_multishot(sqe, el_pollable_fd(w->el), POLLIN);
    io_uring_sqe_set_data(sqe, op);
}

int uring_worker_init(Worker *w) {
    if (!g_config.io_uring || el_pollable_fd(w->el) < 0) return -1;
    struct io_uring *r = calloc(1, sizeof(*r));
    w->uring_fd = calloc((size_t)g_config.max_connection, 1);
    if (!r || !w->uring_fd) goto fail;
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));
    /* Only this worker thread ever submits, and completions are only needed
     * when it asks for them: lets the kernel skip cross-thread task work. */
    p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE;
    p.cq_entries = RING_ENTRIES * 4;
    int rc = io_uring_queue_init_params(RING_ENTRIES, r, &p);
    if (rc < 0) {
        memset(&p, 0, sizeof(p));
        p.flags = IORING_SETUP_CQSIZE;
        p.cq_entries = RING_ENTRIES * 4;
        rc = io_uring_queue_init_params(RING_ENTRIES, r, &p);
    }
    if (rc < 0) {
        fprintf(stderr, "[worker %d] io_uring unavailable (%s), using epoll\n", w->thread_id, strerror(-rc));
        goto fail;
    }
    w->ring = r;
    return 0;
fail:
    free(r);
    free(w->uring_fd);
    w->uring_fd = NULL;
    return -1;
}

void uring_worker_loop(Worker *w) {
    struct io_uring *r = ring_of(w);
    arm_epoll(w);
    w->last_sweep = time(NULL);
    int sweep_ms = worker_sweep_interval_ms();
    for (;;) {
        int rc;
        if (worker_has_ready_backlog(w)) {
            rc = io_uring_submit_and_get_events(r);
        } else if (sweep_ms > 0) {
            struct io_uring_cqe *unused;
            struct __kernel_timespec ts = {sweep_ms / 1000, (long long)(sweep_ms % 1000) * 1000000};
            rc = io_uring_submit_and_wait_timeout(r, &unused, 1, &ts, NULL);
        } else {
            rc = io_uring_submit_and_wait(r, 1);
        }
        if (rc < 0 && rc != -EINTR && rc != -EAGAIN && rc != -EBUSY && rc != -ETIME) {
            fprintf(stderr, "[worker %d] io_uring_enter: %s\n", w->thread_id, strerror(-rc));
            break;
        }
        w->now = time(NULL);
        if (w->topology_version_seen != topology_version_load()) worker_sync_topology(w);

        struct io_uring_cqe *cqe;
        while (io_uring_peek_cqe(r, &cqe) == 0) {
            UOp *op = io_uring_cqe_get_data(cqe);
            int res = cqe->res;
            unsigned flags = cqe->flags;
            io_uring_cqe_seen(r, cqe);
            if (!op) continue; /* cancel request's own completion */
            if (op->kind == UOP_EPOLL) {
                if (!(flags & IORING_CQE_F_MORE)) arm_epoll(w);
                int n;
                do {
                    n = el_poll(w->el, 0);
                    if (n > 0) worker_dispatch_events(w, n);
                } while (n == w->el->max_events);
                continue;
            }
            if (!op->owner) { /* connection closed while this was in flight */
                free(op->buf);
                free(op);
                continue;
            }
            switch (op->kind) {
                case UOP_CRECV: client_recv_done(w, op->owner, res); break;
                case UOP_CSEND: client_send_done(w, op->owner, res); break;
                case UOP_MRECV: mux_recv_done(w, op->owner, res); break;
                case UOP_MSEND: mux_send_done(w, op->owner, res); break;
            }
        }
        worker_after_events(w);
        worker_sweep_clients(w);
        if (atomic_load_explicit(&g_shutdown, memory_order_relaxed)) {
            worker_drain(w);
            sweep_ms = worker_sweep_interval_ms();
        }
    }
}
#endif
