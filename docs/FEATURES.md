# Supported Features and Commands

## 1. Six ways a command can be handled

| Handling | Description |
|---|---|
| **Single-key routing** | Compute `CRC16(key)` to find the slot and pipeline the command onto the worker's shared connection to that node (one per node/db/RESP version); replies are matched in order and returned in each client's command order. `MOVED`/`ASK` replies are retried on the right node (up to 5 times) and `MOVED` triggers an immediate topology refresh |
| **Multi-key (same-slot check)** | Extract every key in the command; if they don't all hash to the same slot, return `-CROSSSLOT` immediately, otherwise forward like a single-key command |
| **Multi-key fan-out** | Split the command per key into several sub-commands sent to their respective nodes, then merge the replies |
| **No-key broadcast** | Broadcast to every primary node and merge the replies |
| **Single-node forward** | Pick one master node, forward the command, and relay its reply verbatim (no broadcast, no merging) |
| **Local reply** | The proxy builds the reply itself, with no backend request at all |

## 2. Fan-out command details

These commands are split per key into several sub-commands sent to each key's owning node, then
merged into one reply (`FANOUT_CMDS` in `src/fanout.c`):

| Command | Merge strategy |
|---|---|
| `MGET` `JSON.MGET` | Results reassembled in original key order |
| `MSET` `JSON.MSET` | Broadcast write; returns `+OK` only if every node succeeds |
| `MSETEX key seconds value [...]` | **A proxy-specific extension** (not a native Valkey command); each triplet is translated into its own `SETEX` and dispatched individually |
| `DEL` `EXISTS` `TOUCH` `UNLINK` | Integer results summed across nodes |
| `LCS` | Dispatched per key pair; the proxy recomputes the LCS result itself (not a simple forward) |

> `MSETNX` is **not** a fan-out command — it's a multi-key, same-slot command (all keys must
> share a slot, otherwise `-CROSSSLOT`).

Fan-out commands accept any number of keys (bounded only by `max_command_size`); sub-commands
travel over the same shared pipelined connections as single-key commands.

## 2a. Transactions (`MULTI` / `EXEC` / `DISCARD` / `WATCH` / `UNWATCH`)

`WATCH` or the first keyed command after `MULTI` pins the client to a private backend connection
on the owning node; the rest of the transaction runs there and the backend enforces the usual
rules (all keys must share a slot, otherwise `EXEC` fails with `-CROSSSLOT`; watched-key
invalidation; `EXECABORT`). `MULTI` itself is answered locally, and keyless commands queued before
the first key (`PING`, `ECHO`, ...) are answered `+QUEUED` locally and replayed on the pinned
connection. A keyless-only transaction runs on the first master. Pub/Sub, `AUTH`, `HELLO`,
`SELECT`, `CLIENT`, `ACL` and `MODULE` are rejected inside `MULTI` (and make `EXEC` return
`EXECABORT`). Pinned connections are reused after `EXEC`/`DISCARD`/`UNWATCH`.

## 3. No-key broadcast / single-node forward command details

### 3.1 Local direct reply (no backend request)
`PING` (replies `+PONG` with no argument, echoes a bulk string with one), `ECHO`, `TIME`, `CLIENT
ID/GETNAME/SETNAME/INFO/HELP`, `SCRIPT HELP`, `FUNCTION HELP`, and the help-text portion of
`ACL HELP`.

### 3.2 Single-node forward (pick one master, relay its reply verbatim)
`RANDOMKEY` `LOLWUT` `FT._LIST` `FT.INFO` `FT.CREATE` `FT.DROPINDEX` `FT.SEARCH` `FT.AGGREGATE` `OBJECT HELP` `XGROUP HELP` `XINFO HELP`
`SCRIPT EXISTS/SHOW` `FUNCTION LIST` `MODULE LIST` `COMMAND HELP/GETKEYS/GETKEYSANDFLAGS`
`SLOWLOG HELP` `COMMANDLOG HELP` `PUBSUB HELP` `ACL LIST/USERS/WHOAMI/GETUSER/DRYRUN` (uses the
shared connection while unauthenticated / authenticated as the default user; once a client has
`AUTH`'d as a non-default user, it switches to that client's own dedicated authenticated
connection — see §8)

`COMMAND` (the bare command is equivalent to `COMMAND INFO` with no arguments); the reply to
`COMMAND INFO/DOCS/LIST` is forwarded and then **filtered** down to only the subset of commands
this proxy itself supports before being relayed to the client; `COMMAND COUNT` forwards
`COMMAND LIST` and counts the filtered result; `COMMAND GETKEYS/GETKEYSANDFLAGS` first checks
whether the target command is on the supported list and rejects it outright (without forwarding
anything) if it isn't.

### 3.3 Broadcast to all masters, results merged
`DBSIZE` (summed), `KEYS` (concatenated), `SCAN` (each node's cursor is encoded into the returned
cursor value; scanning proceeds per node and results are reassembled), `FLUSHALL`/`FLUSHDB`
(`+OK` only if every node succeeds), `PUBSUB CHANNELS`/`SHARDCHANNELS` (deduplicated and
merged), `PUBSUB NUMSUB`/`SHARDNUMSUB` (per-channel counts summed), `PUBSUB NUMPAT` (summed),
`SLOWLOG GET [count]` (each node's entries merged newest first by timestamp and truncated to
`count` — default 10, `-1` = all; entry ids are per-node and so not unique across the merged
reply), `SLOWLOG LEN` (summed), `SLOWLOG RESET` (`+OK` only if every node succeeds), `COMMANDLOG GET <count> <type>`
(merged newest first and truncated to `count`, same as `SLOWLOG GET`; `-1` = all), `COMMANDLOG LEN`
(summed), `COMMANDLOG RESET` (`+OK` only if every node succeeds), `SCRIPT KILL` (succeeds if
**any** node succeeds), `SCRIPT FLUSH [ASYNC|SYNC]` (**the argument is ignored** — always
rewritten as `SCRIPT FLUSH ASYNC` and broadcast, always replies `+OK`), `SCRIPT LOAD` (broadcast
to every node so any shard's subsequent `EVALSHA` can find it; only one sha1 is relayed back),
`FUNCTION KILL` (succeeds if **any** node succeeds), `FUNCTION FLUSH [ASYNC|SYNC]` (same
treatment as `SCRIPT FLUSH` — always `ASYNC`, always `+OK`), `FUNCTION DELETE` (succeeds only if
every node succeeds), `FUNCTION LOAD` (succeeds only if every node succeeds), `FUNCTION STATS`
(each node's execution state is reported separately, not merged).

## 4. Blocking commands

Blocking commands use a separate `POOL_BLOCKING` connection pool (long-lived, kept in blocking
mode) so they don't stall the non-blocking event loop.

| Command | Notes |
|---|---|
| `BLPOP` `BRPOP` | Block until an element is available in any of the listed lists |
| `BLMOVE` `BRPOPLPUSH` | Block until a source list is non-empty, then pop and move one element |
| `BLMPOP` | Block until any of the listed lists is non-empty, then pop one or more elements |
| `BZPOPMIN` `BZPOPMAX` | Block until a member is available in any of the listed sorted sets |
| `BZMPOP` | Block until any of the listed sorted sets is non-empty, then pop one or more members |
| `XREAD ... BLOCK ...` | Block until new entries arrive on the listed streams (only uses the blocking pool when `BLOCK` is present, otherwise takes the ordinary multi-key path) |
| `XREADGROUP ... BLOCK ...` | Same, for a consumer-group read |

## 5. Pub/Sub

`(P|S)SUBSCRIBE` pins the client connection to a dedicated `POOL_SUBSCRIPTION` backend connection
until it unsubscribes; subsequent subscribe/unsubscribe calls on the same client connection reuse
that same pinned connection. `PUBLISH`/`SPUBLISH` need no dedicated connection — they're routed by
channel like an ordinary single-key command.

## 6. Key configuration knobs (`proxy.conf`) at a glance

See the comments in `proxy.conf` at the repo root for the full picture; only the settings that
directly affect command behavior are listed here:

| Setting | Default | Effect |
|---|---|---|
| `min_normal_connection` / `max_normal_connection` | 2 / 20 | Pool used by the vast majority of read/write commands |
| `min_blocking_connection` / `max_blocking_connection` | 2 / 10 | `BLPOP` and other blocking commands |
| `min_subscription_connection` / `max_subscription_connection` | 0 / 10 | Pub/Sub |
| `min_transaction_connection` / `max_transaction_connection` | 0 / 10 | Unused: transactions use pinned connections (see 2a) |
| `min_acl_connection` / `max_acl_connection` | 0 / 10 | `ACL`/`AUTH`, plus each authenticated client's dedicated per-node connections |
| `cluster_refresh_interval_ms` | 0 (on `MOVED` only) | How often the cluster topology is refreshed in the background; a `MOVED` reply always triggers an immediate refresh |
| `max_command_size` | 512MB | Largest single client command accepted |
| `verbose` | no | Per-command / per-connection trace logging |
| `max_connection` | 4000 | Per-worker-thread fd budget (client sockets + backend connections + listener fd(s)) |
