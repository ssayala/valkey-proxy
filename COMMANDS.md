# Supported Features and Commands

## 1. Six ways a command can be handled

| Handling | Description |
|---|---|
| **Single-key routing** | Compute `CRC16(key)` to find the slot, forward to that node, streaming the raw bytes through unparsed |
| **Multi-key (same-slot check)** | Extract every key in the command; if they don't all hash to the same slot, return `-CROSSSLOT` immediately, otherwise forward like a single-key command |
| **Multi-key fan-out** | Split the command per key into several sub-commands sent to their respective nodes, then merge the replies |
| **No-key broadcast** | Broadcast to every primary node and merge the replies |
| **Single-node forward** | Pick one master node, forward the command, and relay its reply verbatim (no broadcast, no merging) |
| **Local reply** | The proxy builds the reply itself, with no backend request at all |

The list below covers every supported command.

## 2. Supported command list (Update it later)

### 2.1 Bitmap

| Command | Notes |
|---|---|
| `BITCOUNT` | |
| `BITFIELD` | |
| `BITFIELD_RO` | |
| `BITOP` | The destkey and every srckey must hash to the same slot, otherwise the proxy returns `-CROSSSLOT` without contacting a backend|
| `BITPOS` | |
| `GETBIT` | |
| `SETBIT` | |

## 3. Fan-out command details

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

## 4. No-key broadcast / single-node forward command details

### 4.1 Local direct reply (no backend request)
`PING` (replies `+PONG` with no argument, echoes a bulk string with one), `ECHO`, `TIME`, `CLIENT
ID/GETNAME/SETNAME/INFO/HELP`, `SCRIPT HELP`, `FUNCTION HELP`, and the help-text portion of
`ACL HELP`.

### 4.2 Single-node forward (pick one master, relay its reply verbatim)
`RANDOMKEY` `LOLWUT` `FT._LIST` `FT.INFO` `OBJECT HELP` `XGROUP HELP` `XINFO HELP`
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

### 4.3 Broadcast to all masters, results merged
`DBSIZE` (summed), `KEYS` (concatenated), `SCAN` (each node's cursor is encoded into the returned
cursor value; scanning proceeds per node and results are reassembled), `FLUSHALL`/`FLUSHDB`
(`+OK` only if every node succeeds), `FT.CREATE`/`FT.DROPINDEX` (`+OK` only if every node
succeeds), `FT.SEARCH` (result sets merged), `PUBSUB CHANNELS`/`SHARDCHANNELS` (deduplicated and
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

## 5. Blocking commands

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

## 6. Pub/Sub

`(P|S)SUBSCRIBE` pins the client connection to a dedicated `POOL_SUBSCRIPTION` backend connection
until it unsubscribes; subsequent subscribe/unsubscribe calls on the same client connection reuse
that same pinned connection. `PUBLISH`/`SPUBLISH` need no dedicated connection — they're routed by
channel like an ordinary single-key command.

## 7. Key configuration knobs (`proxy.conf`) at a glance

See the comments in `proxy.conf` at the repo root for the full picture; only the settings that
directly affect command behavior are listed here:

| Setting | Default | Effect |
|---|---|---|
| `min_normal_connection` / `max_normal_connection` | 2 / 20 | Pool used by the vast majority of read/write commands |
| `min_blocking_connection` / `max_blocking_connection` | 2 / 10 | `BLPOP` and other blocking commands |
| `min_subscription_connection` / `max_subscription_connection` | 0 / 10 | Pub/Sub |
| `min_transaction_connection` / `max_transaction_connection` | 0 / 10 | Capacity settings exist for the transaction pool |
| `min_acl_connection` / `max_acl_connection` | 0 / 10 | `ACL`/`AUTH`, plus each authenticated client's dedicated per-node connections |
| `cluster_refresh_interval_ms` | 0 (disabled) | Whether/how often the cluster topology is refreshed in the background |
| `max_connection` | 4000 | Per-worker-thread fd budget (client sockets + backend connections + listener fd(s)) |
