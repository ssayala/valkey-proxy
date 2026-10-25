#include "test_common.h"

/* Pipelining: many commands written before any reply is read. Replies must
 * come back complete and in command order, even when consecutive commands
 * hash to different shards or mix fast-path and legacy (fan-out / no-key)
 * commands. */

typedef struct {
    char *buf;
    int len, cap;
} PBuf;

static void pb_cmd(PBuf *b, int argc, ...) {
    va_list ap;
    va_start(ap, argc);
    if (b->cap - b->len < 4096) {
        b->cap = b->cap ? b->cap * 2 : 65536;
        b->buf = realloc(b->buf, (size_t)b->cap);
    }
    b->len += snprintf(b->buf + b->len, (size_t)(b->cap - b->len), "*%d\r\n", argc);
    for (int i = 0; i < argc; i++) {
        const char *a = va_arg(ap, const char *);
        b->len += snprintf(b->buf + b->len, (size_t)(b->cap - b->len), "$%d\r\n%s\r\n", (int)strlen(a), a);
    }
    va_end(ap);
}

static int write_all(int fd, const char *p, int n, int chunk) {
    for (int off = 0; off < n;) {
        int c = n - off < chunk ? n - off : chunk;
        int w = (int)write(fd, p + off, (size_t)c);
        if (w <= 0) return -1;
        off += w;
    }
    return 0;
}

void run_pipeline_tests(const char *host, int port, int *pass, int *fail) {
    printf("\n=== Pipeline Tests ===\n");

    int fd = proxy_connect(host, port);
    if (fd < 0) {
        printf("  [FAIL] Cannot connect to proxy at %s:%d\n", host, port);
        (*fail)++;
        return;
    }
    char r[512], want[64];
    PBuf b = {0};

    /* ── many keys across all shards, SETs then GETs in one write ──────── */
    enum { N = 1000 };
    for (int i = 0; i < N; i++) {
        char k[32], v[32];
        snprintf(k, sizeof(k), "tc:pl:%d", i);
        snprintf(v, sizeof(v), "v%d", i);
        pb_cmd(&b, 3, "SET", k, v);
    }
    for (int i = 0; i < N; i++) {
        char k[32];
        snprintf(k, sizeof(k), "tc:pl:%d", i);
        pb_cmd(&b, 2, "GET", k);
    }
    write_all(fd, b.buf, b.len, b.len);
    int ok = 1;
    for (int i = 0; i < N && ok; i++) ok = resp_next_str(fd, r, sizeof(r)) && !strcmp(r, "+OK");
    CHECK(ok, "1000 pipelined SETs across shards all +OK", pass, fail);
    ok = 1;
    for (int i = 0; i < N && ok; i++) {
        snprintf(want, sizeof(want), "v%d", i);
        ok = resp_next_str(fd, r, sizeof(r)) && !strcmp(r, want);
    }
    CHECK(ok, "1000 pipelined GETs answered in command order", pass, fail);

    /* ── fast-path and legacy commands interleaved ─────────────────────── */
    b.len = 0;
    pb_cmd(&b, 3, "SET", "tc:pl:a", "1");
    pb_cmd(&b, 1, "PING");
    pb_cmd(&b, 2, "GET", "tc:pl:a");
    pb_cmd(&b, 3, "MGET", "tc:pl:a", "tc:pl:1");
    pb_cmd(&b, 2, "INCR", "tc:pl:a");
    pb_cmd(&b, 2, "ECHO", "hi");
    pb_cmd(&b, 2, "GET", "tc:pl:a");
    write_all(fd, b.buf, b.len, b.len);
    resp_next_str(fd, r, sizeof(r));
    CHECK(!strcmp(r, "+OK"), "mixed: SET", pass, fail);
    resp_next_str(fd, r, sizeof(r));
    CHECK(!strcmp(r, "+PONG"), "mixed: PING after fast-path command", pass, fail);
    resp_next_str(fd, r, sizeof(r));
    CHECK(!strcmp(r, "1"), "mixed: GET after PING", pass, fail);
    resp_next_str(fd, r, sizeof(r));
    ok = !strcmp(r, "*2");
    resp_next_str(fd, r, sizeof(r));
    ok = ok && !strcmp(r, "1");
    resp_next_str(fd, r, sizeof(r));
    ok = ok && !strcmp(r, "v1");
    CHECK(ok, "mixed: cross-slot MGET fan-out in the middle", pass, fail);
    resp_next_str(fd, r, sizeof(r));
    CHECK(!strcmp(r, ":2"), "mixed: INCR after fan-out", pass, fail);
    resp_next_str(fd, r, sizeof(r));
    CHECK(!strcmp(r, "hi"), "mixed: ECHO", pass, fail);
    resp_next_str(fd, r, sizeof(r));
    CHECK(!strcmp(r, "2"), "mixed: final GET", pass, fail);

    /* ── a pipeline dribbled in 3-byte writes ──────────────────────────── */
    b.len = 0;
    pb_cmd(&b, 3, "SET", "tc:pl:split", "abcdefghij");
    pb_cmd(&b, 2, "GET", "tc:pl:split");
    write_all(fd, b.buf, b.len, 3);
    resp_next_str(fd, r, sizeof(r));
    ok = !strcmp(r, "+OK");
    resp_next_str(fd, r, sizeof(r));
    CHECK(ok && !strcmp(r, "abcdefghij"), "commands split across tiny writes", pass, fail);

    /* ── client hangs up with replies in flight; proxy keeps serving ───── */
    for (int c = 0; c < 20; c++) {
        int fd2 = proxy_connect(host, port);
        if (fd2 < 0) break;
        b.len = 0;
        for (int i = 0; i < 500; i++) {
            char k[32];
            snprintf(k, sizeof(k), "tc:pl:%d", i);
            pb_cmd(&b, 2, "GET", k);
        }
        write_all(fd2, b.buf, b.len, b.len);
        close(fd2);
    }
    proxy_cmd(fd, r, sizeof(r), 2, "GET", "tc:pl:7");
    CHECK(!strcmp(r, "v7"), "proxy unaffected by clients closing mid-pipeline", pass, fail);

    /* ── protocol error queued behind an in-flight reply ───────────────── */
    b.len = 0;
    pb_cmd(&b, 2, "GET", "tc:pl:7");
    memcpy(b.buf + b.len, "*1\r\n$x\r\n", 8);
    b.len += 8;
    write_all(fd, b.buf, b.len, b.len);
    resp_next_str(fd, r, sizeof(r));
    ok = !strcmp(r, "v7");
    resp_next_str(fd, r, sizeof(r));
    CHECK(ok && !strncmp(r, "-ERR protocol error", 19), "reply delivered before protocol error", pass, fail);
    close(fd);

    fd = proxy_connect(host, port);
    if (fd >= 0) {
        b.len = 0;
        for (int i = 0; i < N; i++) {
            char k[32];
            snprintf(k, sizeof(k), "tc:pl:%d", i);
            pb_cmd(&b, 2, "DEL", k);
        }
        pb_cmd(&b, 2, "DEL", "tc:pl:a");
        pb_cmd(&b, 2, "DEL", "tc:pl:split");
        write_all(fd, b.buf, b.len, b.len);
        for (int i = 0; i < N + 2; i++) resp_next_str(fd, r, sizeof(r));
        close(fd);
    }
    free(b.buf);
}
