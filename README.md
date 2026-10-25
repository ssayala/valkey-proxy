# valkey-proxy

A non-blocking, multi-threaded proxy for Valkey/Redis Cluster written in C. It routes commands to the correct shard based on CRC16 key hashing, follows `MOVED`/`ASK` redirects transparently, and fans out multi-key commands across nodes.

Plain single-key commands from all clients of a worker thread are pipelined over one shared connection per backend node, so client pipelining (`valkey-benchmark -P 16`, client-library pipelines) is fully supported, and replies always come back in command order. `MULTI`/`EXEC`/`WATCH` run on a connection pinned to the client for the duration of the transaction, and inline (telnet-style) commands are accepted.

## Build

Requires GCC and (optionally) OpenSSL for TLS support. Supported on Linux, macOS, and BSD.

```bash
make            # build → produces ./valkey-proxy
make NO_TLS=1   # build without TLS support
make clean      # remove binary
```

### Code style

Sources are formatted with `clang-format` (config in `.clang-format`, based on Valkey's style).

```bash
make format        # format src/ and test/ in place
make format-check  # fail if any file is not formatted (for CI)
git config blame.ignoreRevsFile .git-blame-ignore-revs   # skip the bulk-format commit in git blame
```

## Configuration
Create a `proxy.conf` file before starting the proxy. All four parameters are required:

```
# One node in the Valkey cluster (used to discover the full topology)
server-ip    192.168.1.100
server-port  6379

# Address clients connect to
bind  192.168.1.200
port  7777
```
Optional parameters:
```
worker-thread-no  1    # number of worker threads (default: 1)
db                0    # default database (default: 0)

# Connection pool sizes
min_normal_connection        2
min_blocking_connection      2
min_subscription_connection  0
min_transaction_connection   0
min_acl_connection           0

# TLS (client ↔ proxy), TCP listener only -- the unix socket stays plaintext
tls-enabled  no
# tls-cert  /etc/ssl/certs/proxy.crt      # certificate (chain) presented to clients
# tls-key   /etc/ssl/private/proxy.key
# tls-ca-cert       /etc/ssl/certs/ca.crt # CA for verifying client certificates
# tls-auth-clients  no                    # no | yes (require a client cert) | optional

# TLS (proxy ↔ cluster nodes)
# tls-backend          yes
# tls-backend-ca-cert  /etc/ssl/certs/ca.crt   # default: system trust store
# tls-backend-verify   yes                     # verify the nodes' certificate chain
# tls-backend-cert     /etc/ssl/certs/proxy-client.crt   # client cert, if the nodes require one
# tls-backend-key      /etc/ssl/private/proxy-client.key

# Kernel TLS (default: no). After the handshake OpenSSL hands record
# encryption/decryption to the kernel when possible: Linux with the `tls`
# module loaded (`modprobe tls`) and an AES-GCM / ChaCha20-Poly1305 cipher;
# otherwise it silently stays in userspace. `verbose yes` logs which
# connections got kTLS. This only moves the crypto into the kernel -- on a
# plain NIC it measured equal to ~18% *more* proxy CPU than userspace TLS
# (larger values cost more), so it's worth enabling only with NICs that do
# TLS offload in hardware.
# tls-ktls  no

# Unix domain socket (optional)
# unix-socket  /tmp/valkey-proxy.sock

# Per-command / per-connection trace logging (default: no)
# verbose  yes

# Largest single client command accepted, in bytes (default: 512MB)
# max_command_size  536870912
```

## Run

```bash
./valkey-proxy proxy.conf
```

## Integration Tests

Build the test runner once; then point it at any running proxy:

```bash
make test                              # compiles → ./run-test
./run-test -h=<proxy-ip> -p=<proxy-port> [--cluster=<node-ip:port>]
```

Example:

```bash
./run-test -h=192.168.1.200 -p=7777                              # default suites
./run-test -h=192.168.1.200 -p=7777 --cluster=192.168.1.200:6379 # + AUTH / HELLO AUTH as real ACL users
```

### Options

| Option | Meaning |
|---|---|
| `-h=<host>` | proxy IP address (default `127.0.0.1`) |
| `-p=<port>` | proxy port (default `7777`) |
| `--cluster=<host:port>` | **optional**, any *backend* cluster node (not the proxy) — enables the tests that need a real non-default ACL user, see below |
| `--bloomfilter` / `--json` / `--search` | run that module suite |
| `--string` / `--pubsub` | run only that suite |

Giving any suite option (`--bloomfilter`, `--json`, `--search`, `--string`, `--pubsub`) runs
**only** the selected suites — the default suites are skipped. Several can be combined, e.g.
`./run-test --bloomfilter --json -h=... -p=...`. `--cluster` is not a suite option and can be
added to any run.

The runner prints a per-test result followed by a summary:

```
Running integration tests against proxy 10.30.50.180:7777

=== Bitmap Tests ===
  [PASS] SETBIT: set bit 7 to 1, returns prev value 0
  [PASS] GETBIT: get set bit returns 1
  ...
  [SKIP] AUTH as a real ACL user (needs --cluster=<host:port>)
  ...

========================================
Total: Passed: 868, Failed: 0
========================================
```

Exit code is `0` when all tests pass, `1` when any test fails. `[SKIP]` lines are not counted
as either.

### ACL user tests (`--cluster`)

Tests for `AUTH user pass` and `HELLO <ver> AUTH user pass` need a non-default user that exists on
**every** cluster node (ACLs are per node), and the proxy itself never forwards
`ACL SETUSER`/`DELUSER`. With `--cluster=<node>`, the runner (`test/acl/acl_fixture.c`) talks to
the cluster directly:

1. reads `CLUSTER NODES` from that node (masters and replicas; nodes flagged
   `fail`/`noaddr`/`handshake` are skipped),
2. creates two temporary users on every node before any suite runs:
   - `tc-proxy-acl` — full access (`~* &* +@all`)
   - `tc-proxy-acl-ro` — read-only (`~* +@read +@connection +acl|whoami`); a `SET` from a client
     logged in as this user must come back `-NOPERM`, which proves its traffic really runs on its
     own ACL connections rather than the shared default-identity pools,
3. deletes both users again after all suites have finished.

Without `--cluster` those tests print `[SKIP]` and everything else runs as before — the option
**writes ACL state on the backend**, which is why it is opt-in. If a run is interrupted (e.g.
Ctrl-C) the two users are left behind; the next `--cluster` run resets and removes them, or
remove them by hand with `ACL DELUSER tc-proxy-acl tc-proxy-acl-ro` on each node.

### RESP3 ordering note

The `resp3` suite runs last on purpose: its first successful `HELLO 3` flips a process-wide,
sticky "backend speaks RESP3" flag in the proxy, so every other suite runs against a proxy that has
never negotiated RESP3. For the same reason some RESP3 paths (e.g. the very first `HELLO 3` being a
`HELLO 3 AUTH ...`, which doubles as the RESP3 probe) are only really exercised on a **freshly
started** proxy — restart it before a run to cover them.

### Module tests

Bloom Filter, JSON and Search tests are **not** included in the default run. They require the
Bloom Filter module (RedisBloom/ValkeyBloom), the JSON module (RedisJSON/ValkeyJSON) and the
Search module to be loaded on the cluster, and must be invoked explicitly:

```bash
./run-test --bloomfilter -h=<proxy-ip> -p=<proxy-port>
./run-test --json        -h=<proxy-ip> -p=<proxy-port>
./run-test --search      -h=<proxy-ip> -p=<proxy-port>

# Several modules in one run (default suites are NOT included)
./run-test --bloomfilter --json -h=<proxy-ip> -p=<proxy-port>
```
