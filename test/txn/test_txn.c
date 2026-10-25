#include "test_common.h"

/* MULTI/EXEC/WATCH through the proxy, inline (telnet-style) commands, and
 * cross-slot fan-out with more keys than the old fixed 256-key limit. */

static int send_str(int fd, const char *s) {
    size_t n = strlen(s);
    return write(fd, s, n) == (ssize_t)n ? 0 : -1;
}

/* Reads `n` replies and checks each against want[i] (resp_next_str() form). */
static int expect_seq(int fd, int n, const char **want) {
    char r[512];
    int ok = 1;
    for (int i = 0; i < n; i++) {
        resp_next_str(fd, r, sizeof(r));
        if (strcmp(r, want[i]) != 0) {
            printf("    reply %d: got '%s', want '%s'\n", i, r, want[i]);
            ok = 0;
        }
    }
    return ok;
}

/* "<cmd> tc:big:0 .. tc:big:<n-1>" as RESP into buf; returns its length. */
static size_t build_keys_cmd(char *buf, size_t cap, const char *cmd, int n) {
    size_t off = (size_t)snprintf(buf, cap, "*%d\r\n$%d\r\n%s\r\n", 1 + n, (int)strlen(cmd), cmd);
    for (int i = 0; i < n; i++) {
        char k[32];
        int kl = snprintf(k, sizeof(k), "tc:big:%d", i);
        off += (size_t)snprintf(buf + off, cap - off, "$%d\r\n%s\r\n", kl, k);
    }
    return off;
}

void run_txn_tests(const char *host, int port, int *pass, int *fail) {
    printf("\n=== Transaction / Inline / Large Fan-out Tests ===\n");

    int fd = proxy_connect(host, port);
    if (fd < 0) {
        printf("  [FAIL] Cannot connect to proxy at %s:%d\n", host, port);
        (*fail)++;
        return;
    }
    char r[512];

    /* ── MULTI / EXEC, pipelined right behind a SET to the same key ────── */
    proxy_cmd(fd, r, sizeof(r), 2, "DEL", "{tc:tx}a");
    send_str(fd, "*3\r\n$3\r\nSET\r\n$8\r\n{tc:tx}a\r\n$1\r\n1\r\n"
                 "*1\r\n$5\r\nMULTI\r\n"
                 "*2\r\n$4\r\nINCR\r\n$8\r\n{tc:tx}a\r\n"
                 "*2\r\n$4\r\nINCR\r\n$8\r\n{tc:tx}a\r\n"
                 "*1\r\n$4\r\nEXEC\r\n"
                 "*2\r\n$3\r\nGET\r\n$8\r\n{tc:tx}a\r\n");
    {
        const char *w[] = {"+OK", "+OK", "+QUEUED", "+QUEUED", "*2", ":2", ":3", "3"};
        CHECK(expect_seq(fd, 8, w), "MULTI/EXEC ordered after a pipelined SET and before a later GET", pass, fail);
    }

    /* ── keyless commands before the first key, and keyless-only ───────── */
    proxy_cmd(fd, r, sizeof(r), 1, "MULTI");
    proxy_cmd(fd, r, sizeof(r), 1, "PING");
    CHECK(!strcmp(r, "+QUEUED"), "MULTI: keyless command queued before any key", pass, fail);
    proxy_cmd(fd, r, sizeof(r), 2, "GET", "{tc:tx}a");
    proxy_cmd(fd, r, sizeof(r), 1, "EXEC");
    {
        int ok = !strcmp(r, "*2");
        resp_next_str(fd, r, sizeof(r));
        ok = ok && !strcmp(r, "+PONG");
        resp_next_str(fd, r, sizeof(r));
        CHECK(ok && !strcmp(r, "3"), "MULTI: keyless + keyed EXEC returns both results", pass, fail);
    }
    proxy_cmd(fd, r, sizeof(r), 1, "MULTI");
    proxy_cmd(fd, r, sizeof(r), 2, "ECHO", "x");
    proxy_cmd(fd, r, sizeof(r), 1, "EXEC");
    resp_next_str(fd, r, sizeof(r));
    CHECK(!strcmp(r, "x"), "MULTI: keyless-only transaction executes", pass, fail);
    proxy_cmd(fd, r, sizeof(r), 1, "MULTI");
    proxy_cmd(fd, r, sizeof(r), 1, "EXEC");
    CHECK(!strcmp(r, "*0"), "MULTI: empty EXEC returns empty array", pass, fail);

    /* ── DISCARD and error replies ─────────────────────────────────────── */
    proxy_cmd(fd, r, sizeof(r), 1, "MULTI");
    proxy_cmd(fd, r, sizeof(r), 3, "SET", "{tc:tx}a", "discarded");
    proxy_cmd(fd, r, sizeof(r), 1, "DISCARD");
    CHECK(!strcmp(r, "+OK"), "DISCARD returns +OK", pass, fail);
    proxy_cmd(fd, r, sizeof(r), 2, "GET", "{tc:tx}a");
    CHECK(!strcmp(r, "3"), "DISCARD: queued write not applied", pass, fail);
    proxy_cmd(fd, r, sizeof(r), 1, "EXEC");
    CHECK(!strncmp(r, "-ERR EXEC without MULTI", 23), "EXEC without MULTI", pass, fail);
    proxy_cmd(fd, r, sizeof(r), 1, "MULTI");
    proxy_cmd(fd, r, sizeof(r), 1, "MULTI");
    CHECK(!strncmp(r, "-ERR MULTI calls can not be nested", 34), "nested MULTI rejected", pass, fail);
    proxy_cmd(fd, r, sizeof(r), 2, "SUBSCRIBE", "ch");
    CHECK(r[0] == '-', "SUBSCRIBE inside MULTI rejected", pass, fail);
    proxy_cmd(fd, r, sizeof(r), 1, "EXEC");
    CHECK(!strncmp(r, "-EXECABORT", 10), "EXEC after a rejected command -> EXECABORT", pass, fail);

    /* ── WATCH ─────────────────────────────────────────────────────────── */
    int fd2 = proxy_connect(host, port);
    if (fd2 >= 0) {
        proxy_cmd(fd, r, sizeof(r), 3, "SET", "{tc:tx}w", "1");
        proxy_cmd(fd, r, sizeof(r), 2, "WATCH", "{tc:tx}w");
        CHECK(!strcmp(r, "+OK"), "WATCH returns +OK", pass, fail);
        proxy_cmd(fd2, r, sizeof(r), 3, "SET", "{tc:tx}w", "other");
        proxy_cmd(fd, r, sizeof(r), 1, "MULTI");
        proxy_cmd(fd, r, sizeof(r), 3, "SET", "{tc:tx}w", "mine");
        proxy_cmd(fd, r, sizeof(r), 1, "EXEC");
        CHECK(!strcmp(r, "*-1") || !strcmp(r, "(nil)"), "WATCH: key changed by another client -> EXEC nil", pass,
              fail);
        proxy_cmd(fd, r, sizeof(r), 2, "WATCH", "{tc:tx}w");
        proxy_cmd(fd, r, sizeof(r), 1, "MULTI");
        proxy_cmd(fd, r, sizeof(r), 3, "SET", "{tc:tx}w", "mine");
        proxy_cmd(fd, r, sizeof(r), 1, "EXEC");
        resp_next_str(fd, r, sizeof(r));
        CHECK(!strcmp(r, "+OK"), "WATCH: untouched key -> EXEC runs", pass, fail);
        proxy_cmd(fd, r, sizeof(r), 2, "GET", "{tc:tx}w");
        CHECK(!strcmp(r, "mine"), "WATCH: EXEC result visible", pass, fail);
        close(fd2);
    }

    /* ── inline commands ───────────────────────────────────────────────── */
    send_str(fd, "SET {tc:tx}inl \"a b\\x41\"\r\nGET {tc:tx}inl\r\n\r\nPING\nECHO 'it\\'s'\r\n");
    {
        const char *w[] = {"+OK", "a bA", "+PONG", "it's"};
        CHECK(expect_seq(fd, 4, w), "inline commands with quoting, blank line, bare \\n", pass, fail);
    }

    /* ── cross-slot fan-out with > 256 keys (used to drop the rest) ────── */
    enum { NK = 600 };
    {
        size_t cap = NK * 64 + 64, off = 0;
        char *buf = malloc(cap);
        off += (size_t)snprintf(buf + off, cap - off, "*%d\r\n$4\r\nMSET\r\n", 1 + 2 * NK);
        for (int i = 0; i < NK; i++) {
            char k[32], v[32];
            int kl = snprintf(k, sizeof(k), "tc:big:%d", i), vl = snprintf(v, sizeof(v), "v%d", i);
            off += (size_t)snprintf(buf + off, cap - off, "$%d\r\n%s\r\n$%d\r\n%s\r\n", kl, k, vl, v);
        }
        write(fd, buf, off);
        resp_next_str(fd, r, sizeof(r));
        CHECK(!strcmp(r, "+OK"), "MSET 600 cross-slot keys", pass, fail);
        proxy_cmd(fd, r, sizeof(r), 2, "GET", "tc:big:599");
        CHECK(!strcmp(r, "v599"), "MSET 600: last key written", pass, fail);

        off = build_keys_cmd(buf, cap, "MGET", NK);
        write(fd, buf, off);
        resp_next_str(fd, r, sizeof(r));
        int ok = !strcmp(r, "*600");
        for (int i = 0; i < NK; i++) {
            char want[32];
            snprintf(want, sizeof(want), "v%d", i);
            resp_next_str(fd, r, sizeof(r));
            if (strcmp(r, want) != 0) ok = 0;
        }
        CHECK(ok, "MGET 600 cross-slot keys: all values, in order", pass, fail);

        off = build_keys_cmd(buf, cap, "DEL", NK);
        write(fd, buf, off);
        resp_next_str(fd, r, sizeof(r));
        CHECK(!strcmp(r, ":600"), "DEL 600 cross-slot keys", pass, fail);
        free(buf);
    }

    proxy_cmd(fd, r, sizeof(r), 4, "DEL", "{tc:tx}a", "{tc:tx}w", "{tc:tx}inl");
    close(fd);
}
