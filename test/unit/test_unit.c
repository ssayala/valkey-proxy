/* Unit tests for the proxy's pure parsing code: no Valkey server, no proxy
 * process, runs in well under a second. Linked against the proxy's own
 * object files (see "unit tests" in the Makefile), so a sanitizer build
 * (make test-unit SANITIZE=address,undefined) checks these paths too.
 *
 * Client input (scan_command, inline_to_resp) is the code that sees bytes
 * straight off the network, so besides the expected-value tests it gets a
 * seeded fuzz pass: random and mutated input must never crash it, and a
 * command fed one byte at a time must frame exactly like the whole thing. */
#include "proxy.h"
#include <sys/wait.h>

static int g_pass, g_fail;

#define CHECK(cond, ...)                                     \
    do {                                                     \
        if (cond) {                                          \
            g_pass++;                                        \
        } else {                                             \
            g_fail++;                                        \
            printf("  [FAIL] %s:%d: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                             \
            printf("\n");                                    \
        }                                                    \
    } while (0)

/* Deterministic PRNG so a failing fuzz case reproduces on every run. */
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint32_t rnd(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 16);
}

/* Builds a RESP multibulk command from NULL-terminated string args. */
static int mk_cmd(char *out, int cap, const char *const *args) {
    int argc = 0, o;
    while (args[argc]) argc++;
    o = snprintf(out, (size_t)cap, "*%d\r\n", argc);
    for (int i = 0; i < argc; i++) {
        int l = (int)strlen(args[i]);
        o += snprintf(out + o, (size_t)(cap - o), "$%d\r\n", l);
        memcpy(out + o, args[i], (size_t)l);
        o += l;
        out[o++] = '\r';
        out[o++] = '\n';
    }
    return o;
}
#define CMD(buf, ...) mk_cmd(buf, (int)sizeof(buf), (const char *const[]){__VA_ARGS__, NULL})

/* ── key_slot ───────────────────────────────────────────────────────── */
/* Expected values are CLUSTER KEYSLOT from a real Valkey node, covering the
 * hash-tag rules: only the first {...} counts, and only when non-empty. */
static void test_key_slot(void) {
    printf("=== key_slot ===\n");
    static const struct {
        const char *key;
        int slot;
    } cases[] = {
        {"123456789", 12739}, {"foo", 12182}, {"bar", 5061}, {"hello", 866},
        {"{user1000}.following", 3443}, {"{user1000}.followers", 3443},
        {"foo{}{bar}", 8363}, {"foo{{bar}}zap", 4015}, {"foo{bar}{zap}", 5061},
        {"{bar", 4015}, {"bar}", 6624}, {"", 0}, {"{}", 15257}, {"a{b}", 3300},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int s = key_slot(cases[i].key, (int)strlen(cases[i].key));
        CHECK(s == cases[i].slot, "key_slot(\"%s\") = %d, want %d", cases[i].key, s, cases[i].slot);
    }
    /* binary keys: a NUL inside the key is hashed like any other byte */
    CHECK(key_slot("a\0b", 3) != key_slot("a", 1), "key with an embedded NUL hashes all 3 bytes");
}

/* ── scan_command (client RESP framing) ─────────────────────────────── */
static int scan(const char *buf, int len, long long *total, long long *need, int *argc) {
    const char *cmd, *key;
    int cl, kl;
    return scan_command(buf, len, &cmd, &cl, &key, &kl, argc, total, need);
}

static void test_scan_command(void) {
    printf("=== scan_command ===\n");
    char buf[4096];
    long long total, need;
    int argc, n;
    const char *cmd, *key;
    int cl, kl;

    n = CMD(buf, "SET", "mykey", "value");
    CHECK(scan_command(buf, n, &cmd, &cl, &key, &kl, &argc, &total, &need) == 1, "complete SET frames");
    CHECK(total == n && argc == 3, "SET: total %lld/%d argc %d", total, n, argc);
    CHECK(cl == 3 && !memcmp(cmd, "SET", 3) && kl == 5 && !memcmp(key, "mykey", 5), "SET: cmd and key point into buf");

    /* every strict prefix needs more bytes, and says so */
    int bad_prefix = -1;
    for (int k = 1; k < n; k++) {
        if (scan(buf, k, &total, &need, &argc) != 0 || need <= k) {
            bad_prefix = k;
            break;
        }
    }
    CHECK(bad_prefix < 0, "prefix of %d bytes not reported as incomplete", bad_prefix);

    /* two pipelined commands: the first frames on its own */
    int n2 = n + mk_cmd(buf + n, (int)sizeof(buf) - n, (const char *const[]){"GET", "mykey", NULL});
    CHECK(scan(buf, n2, &total, &need, &argc) == 1 && total == n, "pipelined: first command ends at %d", n);
    CHECK(scan(buf + n, n2 - n, &total, &need, &argc) == 1 && total == n2 - n, "pipelined: second command frames");

    /* a single-argument command has no key */
    n = CMD(buf, "PING");
    CHECK(scan_command(buf, n, &cmd, &cl, &key, &kl, &argc, &total, &need) == 1 && key == NULL && kl == 0,
          "PING: no key");

    /* empty and binary arguments */
    n = mk_cmd(buf, sizeof(buf), (const char *const[]){"SET", "", "", NULL});
    CHECK(scan(buf, n, &total, &need, &argc) == 1 && total == n, "empty key and value");
    memcpy(buf, "*2\r\n$3\r\nGET\r\n$3\r\na\r\n\r\n", 22);
    CHECK(scan(buf, 22, &total, &need, &argc) == 1 && total == 22, "CRLF inside a bulk argument");

    /* a big bulk header says how much is needed before the data arrives */
    n = snprintf(buf, sizeof(buf), "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1000000\r\n");
    CHECK(scan(buf, n, &total, &need, &argc) == 0 && need == n + 1000000 + 2, "need = whole 1MB value, got %lld",
          need);

    static const char *const bad[] = {
        "$3\r\nGET\r\n",                 /* not a multibulk */
        "*abc\r\n",                      /* non-numeric count */
        "*0\r\n",                        /* empty command */
        "*-1\r\n",                       /* null array */
        "*1\n$4\r\nPING\r\n",            /* LF without CR */
        "*1\r\n$-1\r\n",                 /* null bulk as an argument */
        "*1\r\n$4\r\nPINGX\r\n",         /* data longer than its header */
        "*1\r\n$4\r\nPIN\r\n\r\n",       /* data shorter than its header */
        "*1\r\n+PING\r\n",               /* simple string as an argument */
        "*1\r\n$4x\r\nPING\r\n",         /* junk in a length */
        "*1\r\n$\r\nPING\r\n",           /* empty length */
        "*2000000\r\n",                  /* more than 1M arguments */
        "*1\r\n$2147483648\r\n",         /* length beyond INT32_MAX */
        "*1\r\n$99999999999999999999\r\n", /* length that overflows 64 bits */
        "*99999999999999999999\r\n",     /* count that overflows 64 bits */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int rc = scan(bad[i], (int)strlen(bad[i]), &total, &need, &argc);
        CHECK(rc == -1, "malformed input #%zu (%.20s...) gave %d, want -1", i, bad[i], rc);
    }

    /* a first line that never ends is rejected rather than buffered forever */
    memset(buf, '1', 100);
    buf[0] = '*';
    CHECK(scan(buf, 100, &total, &need, &argc) == -1, "endless count line rejected");
    memcpy(buf, "*1\r\n$", 5);
    memset(buf + 5, '1', 60);
    CHECK(scan(buf, 65, &total, &need, &argc) == -1, "endless length line rejected");
}

/* Random bytes, and valid commands with random corruption, must never crash
 * or read out of bounds (run under ASan to make the latter visible), and a
 * success must stay within the input. */
static void test_scan_command_fuzz(void) {
    printf("=== scan_command fuzz ===\n");
    static char buf[8192];
    long long total, need;
    int argc, oob = 0, iters = 200000;
    for (int it = 0; it < iters; it++) {
        int n;
        if (it & 1) {
            n = 1 + (int)(rnd() % 200);
            for (int i = 0; i < n; i++) buf[i] = "*$\r\n0123456789-x"[rnd() % 16];
            buf[0] = '*';
        } else {
            char k[32];
            snprintf(k, sizeof(k), "key:%u", rnd() % 1000);
            n = CMD(buf, "SET", k, "some-value", "EX", "100");
            for (int m = (int)(rnd() % 4); m >= 0; m--) buf[rnd() % n] = (char)rnd();
            if (rnd() % 3 == 0) n = 1 + (int)(rnd() % n);
        }
        /* copy into an exact-size heap block so ASan sees any overread */
        char *p = malloc((size_t)n);
        memcpy(p, buf, (size_t)n);
        int rc = scan(p, n, &total, &need, &argc);
        if (rc == 1 && (total <= 0 || total > n)) oob++;
        if (rc == 0 && need <= n) oob++;
        free(p);
    }
    CHECK(oob == 0, "%d of %d fuzz inputs gave a total/need outside the input", oob, iters);

    /* valid random pipelines cut at every point: each prefix either frames
     * whole commands or asks for more, never errors */
    int errors = 0;
    for (int it = 0; it < 300; it++) {
        int n = 0, ncmds = 1 + (int)(rnd() % 5);
        for (int c = 0; c < ncmds; c++) {
            char k[32], v[600];
            int vl = (int)(rnd() % (sizeof(v) - 1));
            memset(v, 'a' + (int)(rnd() % 26), (size_t)vl);
            v[vl] = '\0';
            snprintf(k, sizeof(k), "k%u", rnd());
            n += mk_cmd(buf + n, (int)sizeof(buf) - n, (const char *const[]){"SET", k, v, NULL});
        }
        int cut = 1 + (int)(rnd() % n), off = 0;
        while (off < cut) {
            int rc = scan(buf + off, cut - off, &total, &need, &argc);
            if (rc == -1) errors++;
            if (rc != 1) break;
            off += (int)total;
        }
    }
    CHECK(errors == 0, "%d valid pipelines cut short were reported as protocol errors", errors);
}

/* ── inline_to_resp (telnet-style commands) ─────────────────────────── */
static int inl(ClientConn *c, const char *line, const char *want) {
    int rc = inline_to_resp(c, line, (int)strlen(line));
    if (!want) return rc;
    return rc == (int)strlen(want) && !memcmp(c->conv, want, (size_t)rc);
}

static void test_inline(void) {
    printf("=== inline_to_resp ===\n");
    ClientConn *c = calloc(1, sizeof(*c));

    CHECK(inl(c, "PING", "*1\r\n$4\r\nPING\r\n"), "PING");
    CHECK(inl(c, "SET k v", "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"), "SET k v");
    CHECK(inl(c, "  GET \t k  ", "*2\r\n$3\r\nGET\r\n$1\r\nk\r\n"), "extra spaces and tabs");
    CHECK(inl(c, "SET k \"a b\\x41\"", "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$4\r\na bA\r\n"), "double quotes with \\x41");
    CHECK(inl(c, "ECHO \"\\n\\r\\t\\\\\\\"\"", "*2\r\n$4\r\nECHO\r\n$5\r\n\n\r\t\\\"\r\n"), "escape sequences");
    CHECK(inl(c, "ECHO 'it\\'s'", "*2\r\n$4\r\nECHO\r\n$4\r\nit's\r\n"), "single quotes with \\'");
    CHECK(inl(c, "ECHO 'a\\nb'", "*2\r\n$4\r\nECHO\r\n$4\r\na\\nb\r\n"), "single quotes keep \\n literally");
    CHECK(inl(c, "ECHO \"\\xZZ\"", "*2\r\n$4\r\nECHO\r\n$3\r\nxZZ\r\n"), "invalid \\x escape as in Valkey");
    CHECK(inl(c, "ECHO \"\"", "*2\r\n$4\r\nECHO\r\n$0\r\n\r\n"), "empty quoted argument");
    CHECK(inl(c, "", NULL) == 0, "empty line is blank");
    CHECK(inl(c, "   \t ", NULL) == 0, "whitespace-only line is blank");
    CHECK(inl(c, "SET \"oops", NULL) == -1, "unbalanced double quote");
    CHECK(inl(c, "SET 'oops", NULL) == -1, "unbalanced single quote");
    CHECK(inl(c, "SET \"a\"b", NULL) == -1, "text right after a closing quote");
    CHECK(inl(c, "SET \"a\\\"", NULL) == -1, "escaped closing quote leaves it open");

    /* 1024 arguments is the limit */
    static char line[8192];
    int o = 0;
    for (int i = 0; i < 1024; i++) o += snprintf(line + o, sizeof(line) - (size_t)o, "a ");
    CHECK(inline_to_resp(c, line, o) > 0, "1024 arguments accepted");
    o += snprintf(line + o, sizeof(line) - (size_t)o, "a");
    CHECK(inline_to_resp(c, line, o) == -1, "1025 arguments rejected");

    /* fuzz: quotes, escapes and spaces in random order; when it succeeds the
     * result must be a well-formed RESP command */
    int bad = 0;
    for (int it = 0; it < 100000; it++) {
        int n = (int)(rnd() % 120);
        for (int i = 0; i < n; i++) line[i] = " \t\"'\\xa0F\nk"[rnd() % 11];
        char *p = malloc((size_t)n + 1);
        memcpy(p, line, (size_t)n);
        int rc = inline_to_resp(c, p, n);
        if (rc > 0) {
            long long total, need;
            int argc;
            if (scan(c->conv, rc, &total, &need, &argc) != 1 || total != rc) bad++;
        }
        free(p);
    }
    CHECK(bad == 0, "%d fuzzed inline lines produced malformed RESP", bad);

    free(c->conv);
    free(c);
}

/* ── resp_response_len (backend reply framing) ──────────────────────── */
static void test_response_len(void) {
    printf("=== resp_response_len ===\n");
    static const char *const ok[] = {
        "+OK\r\n", "-ERR bad\r\n", ":42\r\n", "$5\r\nhello\r\n", "$0\r\n\r\n", "$-1\r\n", "*-1\r\n", "*0\r\n",
        "*2\r\n$1\r\na\r\n:1\r\n", "*2\r\n*1\r\n+x\r\n*0\r\n",
        /* RESP3 */
        "_\r\n", "#t\r\n", ",3.14\r\n", "(12345678901234567890\r\n", "=8\r\ntxt:abcd\r\n",
        "%1\r\n$1\r\nk\r\n$1\r\nv\r\n", "~2\r\n:1\r\n:2\r\n", ">3\r\n$7\r\nmessage\r\n$2\r\nch\r\n$1\r\nm\r\n",
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        int n = (int)strlen(ok[i]);
        int rc = resp_response_len(ok[i], n);
        CHECK(rc == n, "reply #%zu (%.12s): %d, want %d", i, ok[i], rc, n);
        int bad = -1;
        for (int k = 1; k < n; k++)
            if (resp_response_len(ok[i], k) != 0) {
                bad = k;
                break;
            }
        CHECK(bad < 0, "reply #%zu: %d-byte prefix not incomplete", i, bad);
    }
    CHECK(resp_response_len("+OK\r\n:1\r\n", 9) == 5, "stops after the first reply");
    CHECK(resp_response_len("?what\r\n", 7) == -1, "unknown type is an error");
    CHECK(resp_response_len("*1\r\n?x\r\n", 8) == -1, "unknown type nested in an array is an error");
}

/* ── RESP3 → RESP2 conversion ───────────────────────────────────────── */
static int downgrade_is(const char *in, int depth, const char *want) {
    char *out = NULL;
    int out_len = 0;
    if (resp3_downgrade(in, (int)strlen(in), depth, &out, &out_len) < 0) return want == NULL;
    int ok = want && out_len == (int)strlen(want) && !memcmp(out, want, (size_t)out_len);
    if (!ok) printf("    got %.*s\n", out_len, out);
    free(out);
    return ok;
}

static void test_resp3(void) {
    printf("=== RESP3 to RESP2 ===\n");
    CHECK(downgrade_is("%1\r\n$1\r\nf\r\n$1\r\nv\r\n", -1, "*2\r\n$1\r\nf\r\n$1\r\nv\r\n"), "map to flat array");
    CHECK(downgrade_is("~2\r\n:1\r\n:2\r\n", -1, "*2\r\n:1\r\n:2\r\n"), "set to array");
    CHECK(downgrade_is("_\r\n", -1, "$-1\r\n"), "null to nil bulk");
    CHECK(downgrade_is("_\r\n", 0, "*-1\r\n"), "null to nil array at depth 0");
    CHECK(downgrade_is("*2\r\n_\r\n_\r\n", 1, "*2\r\n*-1\r\n*-1\r\n"), "GEOPOS-style nil arrays at depth 1");
    CHECK(downgrade_is("#t\r\n", -1, ":1\r\n") && downgrade_is("#f\r\n", -1, ":0\r\n"), "booleans to integers");
    CHECK(downgrade_is(",1.5\r\n", -1, "$3\r\n1.5\r\n"), "double to bulk");
    CHECK(downgrade_is("(123\r\n", -1, "$3\r\n123\r\n"), "big number to bulk");
    CHECK(downgrade_is("=7\r\ntxt:abc\r\n", -1, "$3\r\nabc\r\n"), "verbatim string loses its prefix");
    CHECK(downgrade_is(">2\r\n$1\r\na\r\n$1\r\nb\r\n", -1, "*2\r\n$1\r\na\r\n$1\r\nb\r\n"), "push to array");
    CHECK(downgrade_is("+OK\r\n:1\r\n", -1, NULL), "trailing bytes rejected");
    CHECK(downgrade_is("*2\r\n:1\r\n", -1, NULL), "truncated array rejected");

    char *out;
    int out_len;
    const char *pairs = "*2\r\n*2\r\n$1\r\na\r\n$1\r\n1\r\n*2\r\n$1\r\nb\r\n$1\r\n2\r\n";
    const char *flat_want = "*4\r\n$1\r\na\r\n$1\r\n1\r\n$1\r\nb\r\n$1\r\n2\r\n";
    out = NULL;
    CHECK(resp3_flatten_pairs(pairs, (int)strlen(pairs), &out, &out_len) == 0 &&
              out_len == (int)strlen(flat_want) && !memcmp(out, flat_want, (size_t)out_len),
          "flatten WITHSCORES pairs");
    free(out);
    CHECK(resp3_flatten_pairs("*2\r\n$1\r\na\r\n$1\r\nb\r\n", 18, &out, &out_len) == 1, "flat array left alone");

    const char *flat = "*4\r\n$1\r\ns\r\n*0\r\n$1\r\nt\r\n*0\r\n";
    const char *nest_want = "*2\r\n*2\r\n$1\r\ns\r\n*0\r\n*2\r\n$1\r\nt\r\n*0\r\n";
    out = NULL;
    CHECK(resp3_nest_pairs(flat, (int)strlen(flat), &out, &out_len) == 0 && out_len == (int)strlen(nest_want) &&
              !memcmp(out, nest_want, (size_t)out_len),
          "nest XREAD stream pairs");
    free(out);
    CHECK(resp3_nest_pairs("*3\r\n:1\r\n:2\r\n:3\r\n", 16, &out, &out_len) == 1, "odd-length array left alone");
}

/* ── key extraction and command building ────────────────────────────── */
static int keys_are(const char *const *args, const char *const *want) {
    char buf[1024];
    const char *kp[16];
    int kl[16], nw = 0;
    int n = mk_cmd(buf, sizeof(buf), args);
    while (want[nw]) nw++;
    int nk = resp_extract_keys(buf, n, args[0], kp, kl, 16);
    if (nk != nw) return 0;
    for (int i = 0; i < nk; i++)
        if (kl[i] != (int)strlen(want[i]) || memcmp(kp[i], want[i], (size_t)kl[i])) return 0;
    return 1;
}
#define L(...) ((const char *const[]){__VA_ARGS__, NULL})
#define KEYS(args, want) keys_are(args, want)

static void test_keys(void) {
    printf("=== key extraction ===\n");
    CHECK(KEYS(L("MGET", "a", "b", "c"), L("a", "b", "c")), "MGET: every argument");
    CHECK(KEYS(L("DEL", "x"), L("x")), "DEL: one key");
    CHECK(KEYS(L("MSET", "a", "1", "b", "2"), L("a", "b")), "MSET: every other argument");
    CHECK(KEYS(L("MSETEX", "a", "1", "PX", "b", "2", "EX"), L("a", "b")), "MSETEX: every third argument");
    CHECK(KEYS(L("BITOP", "AND", "dst", "s1", "s2"), L("dst", "s1", "s2")), "BITOP: skip the operation");
    CHECK(KEYS(L("RENAME", "old", "new"), L("old", "new")), "RENAME: both names");
    CHECK(KEYS(L("EVAL", "return 1", "2", "k1", "k2", "arg"), L("k1", "k2")), "EVAL: numkeys keys");
    CHECK(KEYS(L("EVAL", "return 1", "5", "k1"), L("k1")), "EVAL: numkeys beyond argc is clamped");
    CHECK(KEYS(L("ZUNIONSTORE", "dst", "2", "z1", "z2", "WEIGHTS", "1", "2"), L("dst", "z1", "z2")),
          "ZUNIONSTORE: destination plus numkeys");
    CHECK(KEYS(L("ZINTER", "2", "z1", "z2", "WITHSCORES"), L("z1", "z2")), "ZINTER: numkeys first");
    CHECK(KEYS(L("XREAD", "COUNT", "2", "STREAMS", "s1", "s2", "0", "0"), L("s1", "s2")), "XREAD: names after STREAMS");
    CHECK(KEYS(L("GEORADIUS", "g", "0", "0", "1", "km", "STORE", "dst"), L("g", "dst")), "GEORADIUS STORE");

    const char *args[] = {"k", "value"};
    int lens[] = {1, 5}, n;
    char *b = build_resp_cmd("SET", 3, args, lens, 2, &n);
    const char *want = "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$5\r\nvalue\r\n";
    CHECK(b && n == (int)strlen(want) && !memcmp(b, want, (size_t)n), "build_resp_cmd SET k value");
    free(b);
}

/* ── CLUSTER NODES parsing ──────────────────────────────────────────── */
static int parse_nodes(const char *text, ClusterNode *nodes, int *slots) {
    int count = 0;
    for (int i = 0; i < CLUSTER_SLOTS; i++) slots[i] = -1;
    parse_cluster_nodes_into(text, "192.0.2.1", nodes, &count, slots, 0);
    return count;
}

static int find_node(ClusterNode *nodes, int count, const char *ip, int port) {
    for (int i = 0; i < count; i++)
        if (!strcmp(nodes[i].ip, ip) && nodes[i].port == port) return i;
    return -1;
}

static void test_cluster_nodes(void) {
    printf("=== CLUSTER NODES parsing ===\n");
    static ClusterNode nodes[MAX_NODES];
    static int slots[CLUSTER_SLOTS];

    /* real output (replica cluster after a failover), plus a migrating slot */
    const char *real =
        "6b664fb7010cac5ae4870f89e0b90e26b9e0e11c 127.0.0.1:7204@17204 master - 0 1792976952061 9 connected 0-5460\n"
        "0a3679b2af54745028f87426e2523839e1cabc3e 127.0.0.1:7205@17205 slave 3fd7946dc8f33a8a8a023e7782ec2a3a42d827d6 "
        "0 1792976952000 10 connected\n"
        "3fd7946dc8f33a8a8a023e7782ec2a3a42d827d6 127.0.0.1:7202@17202 master - 0 1792976951154 10 connected "
        "5461-10921 10922 [10922->-bcb10c46e034df3b625ed674318bfc58b5f371be]\n"
        "bcb10c46e034df3b625ed674318bfc58b5f371be 127.0.0.1:7203@17203 master - 0 1792976951457 11 connected "
        "10923-16383\n"
        "680e0727ea839d634855a43f8a70cd29d5546e57 127.0.0.1:7201@17201 myself,slave "
        "6b664fb7010cac5ae4870f89e0b90e26b9e0e11c 0 0 9 connected\n";
    int n = parse_nodes(real, nodes, slots);
    CHECK(n == 3, "3 masters (replicas skipped), got %d", n);
    int a = find_node(nodes, n, "127.0.0.1", 7204), b = find_node(nodes, n, "127.0.0.1", 7202),
        c = find_node(nodes, n, "127.0.0.1", 7203);
    CHECK(a >= 0 && b >= 0 && c >= 0, "all three masters found");
    CHECK(slots[0] == a && slots[5460] == a && slots[5461] == b && slots[10922] == b && slots[10923] == c &&
              slots[16383] == c,
          "slot ranges map to the right masters");
    int unmapped = 0;
    for (int i = 0; i < CLUSTER_SLOTS; i++) unmapped += slots[i] < 0;
    CHECK(unmapped == 0, "%d slots left unmapped", unmapped);
    CHECK(a >= 0 && !strcmp(nodes[a].node_id, "6b664fb7010cac5ae4870f89e0b90e26b9e0e11c"), "node id kept");

    /* failed masters are skipped; PFAIL ("fail?") ones are kept */
    const char *failed = "aaaa 10.0.0.1:6379@16379 master,fail - 0 0 1 disconnected 0-8191\n"
                         "bbbb 10.0.0.2:6379@16379 master,fail? - 0 0 2 connected 8192-16383\n";
    n = parse_nodes(failed, nodes, slots);
    CHECK(n == 1 && !strcmp(nodes[0].ip, "10.0.0.2"), "fail skipped, fail? kept");
    CHECK(slots[0] == -1 && slots[8192] == 0, "a failed master's slots stay unmapped");

    /* IPv6, hostnames, CRLF line endings, a blank line, a garbage line */
    const char *mixed = "cccc ::1:7001@17001,node-a.example master - 0 0 1 connected 0-100\r\n"
                        "\r\n"
                        "this line is not a node\r\n"
                        "dddd :7002@17002,localhost myself,master - 0 0 2 connected 101-200\r\n";
    n = parse_nodes(mixed, nodes, slots);
    CHECK(n == 2, "IPv6 and hostname-only nodes parsed, got %d", n);
    int v6 = find_node(nodes, n, "::1", 7001), hn = find_node(nodes, n, "localhost", 7002);
    CHECK(v6 >= 0 && !strcmp(nodes[v6].hostname, "node-a.example"), "IPv6 address, announced hostname kept");
    CHECK(hn >= 0 && !strcmp(nodes[hn].hostname, "localhost"), "empty IP: connect by hostname");
    CHECK(slots[50] == v6 && slots[150] == hn && slots[201] == -1, "slots for IPv6/hostname nodes");

    /* migrating/importing entries ("[slot->-id]", "[slot-<-id]") are longer
     * than any slot range and must be skipped whole: no part of the node id
     * may be read as a slot number */
    const char *migrating = "ffff 10.0.0.4:6379@16379 master - 0 0 1 connected 0-99\n"
                            "gggg 10.0.0.5:6379@16379 myself,master - 0 0 2 connected 100-199 "
                            "[150->-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa] "
                            "[300-<-1234aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1234aaaaaaaaaaaaaaaaaaaa]\n";
    n = parse_nodes(migrating, nodes, slots);
    CHECK(n == 2 && slots[0] == 0 && slots[150] == 1 && slots[300] == -1 && slots[1234] == -1,
          "migrating/importing entries: slot 0 -> %d (want 0), 300 -> %d, 1234 -> %d (want -1)", slots[0],
          slots[300], slots[1234]);
    n = parse_nodes("hhhh 10.0.0.6:6379@16379 master - 0 0 1 connected abc 7x 5-x 10\n", nodes, slots);
    CHECK(n == 1 && slots[0] == -1 && slots[7] == -1 && slots[5] == -1 && slots[10] == 0,
          "non-numeric slot tokens ignored");

    /* a single-node cluster's node doesn't know its own IP: the address the
     * reply came from is used for "myself", and only for "myself" */
    n = parse_nodes("iiii :6379@16379 myself,master - 0 0 1 connected 0-16383\n"
                    "jjjj :6380@16380 master - 0 0 1 connected\n",
                    nodes, slots);
    CHECK(n == 1 && !strcmp(nodes[0].ip, "192.0.2.1") && nodes[0].port == 6379 && slots[16383] == 0,
          "single-node cluster: myself at the source address, got %d node(s)", n);

    /* out-of-range slots are ignored, not written past the slot table */
    n = parse_nodes("eeee 10.0.0.3:6379@16379 master - 0 0 1 connected 16000-99999 -5 70000 5\n", nodes, slots);
    CHECK(n == 1 && slots[5] == 0 && slots[16000] == -1, "bad slot ranges ignored");

    /* a large cluster: 64 masters with 3 replicas each, replicas listed
     * first, slot ranges fragmented by resharding and Kubernetes-style hostnames -- every
     * master must still be found, wherever it sits in the reply */
    size_t cap = 1 << 20, o = 0;
    char *big = malloc(cap);
    for (int m = 0; m < 64; m++)
        for (int r = 0; r < 3; r++)
            o += (size_t)snprintf(big + o, cap - o,
                                  "%040d 10.1.%d.%d:6379@16379,valkey-%d-%d.valkey-headless.prod.svc.cluster.local "
                                  "slave %040d 0 1792976952061 %d connected\n",
                                  m * 4 + r + 1, m, r + 1, m, r + 1, m * 4, m + 1);
    for (int m = 0; m < 64; m++) {
        o += (size_t)snprintf(big + o, cap - o,
                              "%040d 10.1.%d.0:6379@16379,valkey-%d-0.valkey-headless.prod.svc.cluster.local "
                              "master - 0 1792976952061 %d connected",
                              m * 4, m, m, m + 1);
        for (int s = m * 256; s < (m + 1) * 256; s += 8) /* 32 ranges per master */
            o += (size_t)snprintf(big + o, cap - o, " %d-%d", s, s + 7);
        big[o++] = '\n';
    }
    big[o] = '\0';
    n = parse_nodes(big, nodes, slots);
    unmapped = 0;
    for (int i = 0; i < CLUSTER_SLOTS; i++) unmapped += slots[i] < 0;
    CHECK(n == 64 && unmapped == 0, "%zu-byte reply: %d of 64 masters found, %d slots unmapped", o, n, unmapped);
    free(big);
}

/* ── config file parsing ────────────────────────────────────────────── */
/* parse_conf() exits on any error, so each case runs in a child process;
 * the child's stderr and exit status are what's checked. */
static char g_conf_path[256];

static int conf_run(const char *text, int (*verify)(void), char *err, size_t errsz) {
    FILE *f = fopen(g_conf_path, "w");
    fputs(text, f);
    fclose(f);
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], 2);
        parse_conf(g_conf_path);
        _exit(verify && !verify() ? 2 : 0);
    }
    close(pfd[1]);
    size_t got = 0;
    ssize_t r;
    while (got + 1 < errsz && (r = read(pfd[0], err + got, errsz - got - 1)) > 0) got += (size_t)r;
    err[got] = '\0';
    close(pfd[0]);
    int st;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
}

static int verify_good(void) {
    return !strcmp(g_config.server_ip, "10.0.0.1") && g_config.server_port == 6379 && g_config.proxy_port == 7777 &&
           g_config.worker_thread_no == 4 && g_config.tls_backend == 1 && g_config.tls_auth_clients == 2 &&
           g_config.unix_socket_perm == 0660 && !strcmp(g_config.unix_socket_path, "/run/a#b.sock") &&
           g_config.cluster_refresh_interval_ms == 2000 && g_config.maxclients == 10000 &&
           g_config.tcp_keepalive == 300 && g_pool_max[POOL_NORMAL] == 50;
}

static void conf_error(const char *text, const char *want) {
    char err[1024];
    int rc = conf_run(text, NULL, err, sizeof(err));
    CHECK(rc == 1 && strstr(err, want), "config error: want exit 1 with \"%s\", got exit %d: %s", want, rc, err);
}

static void test_config(void) {
    printf("=== config parsing ===\n");
    snprintf(g_conf_path, sizeof(g_conf_path), "/tmp/valkey-proxy-unit-%d.conf", (int)getpid());
    char err[1024];
    const char *base = "server-ip 10.0.0.1\nserver-port 6379\nport 7777\n";

    int rc = conf_run("# a comment\n"
                      "server-ip 10.0.0.1\n"
                      "  server-port   6379   # trailing comment\n"
                      "port 7777\n"
                      "\n"
                      "worker-thread-no 4\n"
                      "tls-backend yes\n"
                      "tls-auth-clients optional\n"
                      "unix-socket /run/a#b.sock\n"
                      "unix-socket-perm 660\n"
                      "max_normal_connection 50\n",
                      verify_good, err, sizeof(err));
    CHECK(rc == 0, "valid config: exit %d %s", rc, err);

    static char text[8192];
#define WITH(line) (snprintf(text, sizeof(text), "%s%s\n", base, line), text)
    conf_error(WITH("tls-backend yess"), ":4: 'tls-backend' must be yes or no, got 'yess'");
    conf_error(WITH("tls-auth-clients maybe"), ":4: 'tls-auth-clients' must be yes, no or optional");
    conf_error(WITH("worker-thread-no 0"), ":4: 'worker-thread-no' must be in 1..");
    conf_error(WITH("port 99999"), ":4: 'port' must be in 1..65535");
    conf_error(WITH("timeout 12ab"), ":4: 'timeout' needs a whole number, got '12ab'");
    conf_error(WITH("timeout -1"), ":4: 'timeout' must be in 0..");
    conf_error(WITH("maxclients 99999999999999999999"), ":4: 'maxclients' needs a whole number");
    conf_error(WITH("unix-socket-perm 999"), ":4: 'unix-socket-perm' needs a whole number");
    conf_error(WITH("tls-backnd yes"), ":4: unknown setting 'tls-backnd'");
    conf_error(WITH("bind"), ":4: 'bind' has no value");
    conf_error(WITH("bind 1.2.3.4 5.6.7.8"), ":4: 'bind' takes a single value");
    conf_error(WITH("min_normal_connection 30"), "min_normal_connection exceeds max");
    conf_error("server-port 6379\nport 7777\n", "missing required setting 'server-ip'");
    conf_error("server-ip 10.0.0.1\nport 7777\n", "missing required setting 'server-port'");
    conf_error("server-ip 10.0.0.1\nserver-port 6379\n", "missing required setting 'port'");

    static char longline[4096];
    memset(longline, 'x', 3000);
    memcpy(longline, "server-ip ", 10);
    longline[3000] = '\0';
    conf_error(WITH(longline), ":4: line too long");

    unlink(g_conf_path);
#undef WITH
}

static void test_config_missing_file(void) {
    char err[512];
    int pfd[2];
    if (pipe(pfd) < 0) return;
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], 2);
        parse_conf("/nonexistent/valkey-proxy.conf");
        _exit(0);
    }
    close(pfd[1]);
    ssize_t r = read(pfd[0], err, sizeof(err) - 1);
    err[r > 0 ? r : 0] = '\0';
    close(pfd[0]);
    int st;
    waitpid(pid, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 1 && strstr(err, "/nonexistent/valkey-proxy.conf"),
          "missing config file: exit 1 naming the file, got: %s", err);
}

int main(void) {
    test_key_slot();
    test_scan_command();
    test_scan_command_fuzz();
    test_inline();
    test_response_len();
    test_resp3();
    test_keys();
    test_cluster_nodes();
    test_config();
    test_config_missing_file();

    printf("\n========================================\n");
    printf("Total: Passed: %d, Failed: %d\n", g_pass, g_fail);
    printf("========================================\n");
    return g_fail ? 1 : 0;
}
