"""Client protocol handling: pipelining and reply order, framing, inline
commands, transactions, errors, hostile input. One proxy (2 workers) in front
of the shared plain cluster for the whole class."""

import random
import socket
import time
import unittest

from harness import Proxy, cmd, close_wait_count, plain_cluster, split_replies


class Protocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = Proxy(plain_cluster(), workers=2).start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()

    def setUp(self):
        plain_cluster().flushall()

    def conn(self, **kw):
        c = self.proxy.conn(**kw)
        self.addCleanup(c.close)
        return c

    def exchange(self, cmds, n=None, timeout=10):
        """Sends all of cmds at once (one pipeline), returns n raw replies."""
        c = self.conn(timeout=timeout)
        c.send(b"".join(cmds))
        return b"".join(c.read_raw(n if n is not None else len(cmds)))

    # ── pipelining and reply order ──────────────────────────────────────

    def test_mixed_pipeline_keeps_order(self):
        """Pipelined fast-path, local (PING/ECHO), fan-out (MGET) and plain
        commands across shards come back in command order."""
        got = self.exchange([cmd("SET", "k1", "v1"), cmd("SET", "k2", "v2"), cmd("PING"), cmd("GET", "k1"),
                             cmd("MGET", "k1", "k2", "k3"), cmd("GET", "k2"), cmd("INCR", "ctr"), cmd("ECHO", "hi"),
                             cmd("DEL", "ctr")])
        self.assertEqual(got, b"+OK\r\n+OK\r\n+PONG\r\n$2\r\nv1\r\n*3\r\n$2\r\nv1\r\n$2\r\nv2\r\n$-1\r\n"
                              b"$2\r\nv2\r\n:1\r\n$2\r\nhi\r\n:1\r\n")

    def test_10k_pipelined_commands_across_slots(self):
        n = 5000
        c = self.conn(timeout=30)
        c.send(b"".join(cmd("SET", "key:%d" % i, "val%d" % i) for i in range(n)) +
               b"".join(cmd("GET", "key:%d" % i) for i in range(n)))
        got = c.read_raw(2 * n)
        self.assertEqual(got[:n], [b"+OK\r\n"] * n)
        self.assertEqual(got[n:], [b"$%d\r\nval%d\r\n" % (len("val%d" % i), i) for i in range(n)])

    def test_ordering_around_legacy_commands(self):
        """Commands still on the one-at-a-time path, sandwiched between fast
        and local ones, don't let later replies overtake them."""
        c = self.conn()
        c.call("SET", "ok", "1")
        for legacy in (cmd("DBSIZE"), cmd("OBJECT", "ENCODING", "ok"), cmd("KEYS", "ok"), cmd("TIME"),
                       cmd("INFO", "server"), cmd("SCARD", "none")):
            c.send(cmd("PING") + legacy + cmd("ECHO", "LAST") + cmd("GET", "ok"))
            r = c.read_raw(4)
            self.assertEqual((r[0], r[2], r[3]), (b"+PONG\r\n", b"$4\r\nLAST\r\n", b"$1\r\n1\r\n"), legacy)

    def test_half_close_after_pipeline(self):
        """A client that sends a pipeline and shuts down its write side still
        gets every reply."""
        c = self.conn()
        c.call("SET", "ok", "1")
        c.send(cmd("PING") + cmd("GET", "ok") + cmd("DBSIZE") + cmd("PING"))
        c.sock.shutdown(socket.SHUT_WR)
        r = split_replies(c.readall(3))
        self.assertEqual(len(r), 4, r)
        self.assertEqual((r[0], r[1], r[3]), (b"+PONG\r\n", b"$1\r\n1\r\n", b"+PONG\r\n"))

    # ── framing ─────────────────────────────────────────────────────────

    def test_command_split_into_tiny_writes(self):
        c = self.conn()
        p = cmd("SET", "split", "x" * 1000) + cmd("GET", "split")
        for i in range(0, len(p), 7):
            c.send(p[i:i + 7])
            if i % 140 == 0:
                time.sleep(0.0005)
        self.assertEqual(b"".join(c.read_raw(2)), b"+OK\r\n$1000\r\n" + b"x" * 1000 + b"\r\n")

    def test_20mb_value(self):
        big = b"y" * (20 * 1024 * 1024)
        got = self.exchange([cmd("SET", "big", big), cmd("STRLEN", "big"), cmd("GET", "big")], timeout=30)
        self.assertTrue(got == b"+OK\r\n:%d\r\n$%d\r\n%s\r\n" % (len(big), len(big), big), "20MB round trip")
        self.proxy.call("DEL", "big")

    def test_select(self):
        """Only db 0 exists in cluster mode (the proxy's "db" setting picks
        the one used on backend connections)."""
        got = self.exchange([cmd("SET", "dbk", "zero"), cmd("SELECT", "0"), cmd("SELECT", "1"), cmd("GET", "dbk")])
        self.assertEqual(got, b"+OK\r\n+OK\r\n-ERR DB index is out of range\r\n$4\r\nzero\r\n")

    def test_resp3_client(self):
        c = self.conn()
        c.call("HELLO", "3")
        c.send(cmd("DEL", "h3") + cmd("HSET", "h3", "f", "v") + cmd("HGETALL", "h3") + cmd("GET", "nosuch"))
        self.assertEqual(b"".join(c.read_raw(4)), b":0\r\n:1\r\n%1\r\n$1\r\nf\r\n$1\r\nv\r\n_\r\n")
        # a RESP2 client sees the same keys in RESP2 shapes
        c2 = self.conn()
        c2.send(cmd("HGETALL", "h3") + cmd("GET", "nosuch"))
        self.assertEqual(b"".join(c2.read_raw(2)), b"*2\r\n$1\r\nf\r\n$1\r\nv\r\n$-1\r\n")

    def test_inline_commands(self):
        c = self.conn()
        c.send(b'SET inl "a b\\x41"\r\nGET inl\r\n\r\nPING\nMGET inl nosuch\r\nECHO \'it\\\'s\'\r\n')
        self.assertEqual(b"".join(c.read_raw(5)),
                         b"+OK\r\n$4\r\na bA\r\n+PONG\r\n*2\r\n$4\r\na bA\r\n$-1\r\n$4\r\nit's\r\n")

    def test_inline_unbalanced_quotes(self):
        c = self.conn()
        c.send(b'SET "oops\r\n')
        self.assertEqual(c.readall(2), b"-ERR Protocol error: unbalanced quotes in request\r\n")

    def test_protocol_error_after_valid_command(self):
        """The valid command's reply comes first, then the error, then the
        proxy closes the connection."""
        c = self.conn()
        c.send(cmd("SET", "k1", "v1"))
        c.read()
        c.send(cmd("GET", "k1") + b"*1\r\n$abc\r\n")
        r = c.readall(2)
        self.assertTrue(r.lower().startswith(b"$2\r\nv1\r\n-err protocol error"), r)
        self.assertTrue(c.closed_by_peer())

    # ── errors ──────────────────────────────────────────────────────────

    def test_wrong_arity_errors_in_order(self):
        """Keyed commands sent without their key get Valkey's arity error,
        in order, instead of being routed with garbage."""
        c = self.conn()
        c.call("SET", "rk", "v1")
        c.send(cmd("OBJECT", "ENCODING") + cmd("GET", "rk") + cmd("XINFO", "STREAM") + cmd("MEMORY", "USAGE") +
               cmd("PING"))
        r = c.read_raw(5)
        self.assertTrue(r[0].startswith(b"-ERR wrong number"), r)
        self.assertEqual(r[1], b"$2\r\nv1\r\n")
        self.assertTrue(r[2].startswith(b"-ERR wrong number") and r[3].startswith(b"-ERR wrong number"), r)
        self.assertEqual(r[4], b"+PONG\r\n")

    def test_errors_behind_a_full_socket_buffer(self):
        """Errors generated by the proxy itself queue behind 40MB of
        replies the client hasn't read yet, instead of jumping ahead."""
        c = self.conn(timeout=30)
        c.call("SET", "bigv", "x" * (1 << 20))
        n = 40
        c.send(cmd("GET", "bigv") * n + cmd("OBJECT", "ENCODING") + cmd("NOSUCHCMD") + cmd("XINFO", "STREAM") +
               cmd("PING"))
        time.sleep(1.5)  # don't read: the proxy's socket buffer fills up
        r = c.read_raw(n + 4)
        self.assertTrue(all(x.startswith(b"$1048576") for x in r[:n]))
        tail = r[n:]
        self.assertTrue(tail[0].startswith(b"-ERR wrong") and tail[1].startswith(b"-ERR") and
                        tail[2].startswith(b"-ERR wrong"), tail)
        self.assertEqual(tail[3], b"+PONG\r\n")

    # ── transactions ────────────────────────────────────────────────────

    def test_multi_exec(self):
        got = self.exchange([cmd("DEL", "{t}a"), cmd("SET", "{t}a", "1"), cmd("MULTI"), cmd("INCR", "{t}a"),
                             cmd("INCR", "{t}a"), cmd("EXEC"), cmd("GET", "{t}a")])
        self.assertEqual(got, b":0\r\n+OK\r\n+OK\r\n+QUEUED\r\n+QUEUED\r\n*2\r\n:2\r\n:3\r\n$1\r\n3\r\n")

    def test_multi_keyless_commands(self):
        self.assertEqual(self.exchange([cmd("MULTI"), cmd("PING"), cmd("SET", "{t}b", "x"), cmd("GET", "{t}b"),
                                        cmd("EXEC")]),
                         b"+OK\r\n+QUEUED\r\n+QUEUED\r\n+QUEUED\r\n*3\r\n+PONG\r\n+OK\r\n$1\r\nx\r\n")
        self.assertEqual(self.exchange([cmd("MULTI"), cmd("PING"), cmd("ECHO", "e"), cmd("EXEC")]),
                         b"+OK\r\n+QUEUED\r\n+QUEUED\r\n*2\r\n+PONG\r\n$1\r\ne\r\n")
        self.assertEqual(self.exchange([cmd("MULTI"), cmd("EXEC")]), b"+OK\r\n*0\r\n")

    def test_discard(self):
        self.assertEqual(self.exchange([cmd("SET", "{t}c", "1"), cmd("MULTI"), cmd("SET", "{t}c", "2"),
                                        cmd("DISCARD"), cmd("GET", "{t}c")]),
                         b"+OK\r\n+OK\r\n+QUEUED\r\n+OK\r\n$1\r\n1\r\n")

    def test_transaction_misuse_errors(self):
        self.assertEqual(self.exchange([cmd("EXEC"), cmd("DISCARD"), cmd("MULTI"), cmd("MULTI"), cmd("WATCH", "x"),
                                        cmd("DISCARD")]),
                         b"-ERR EXEC without MULTI\r\n-ERR DISCARD without MULTI\r\n+OK\r\n"
                         b"-ERR MULTI calls can not be nested\r\n-ERR WATCH inside MULTI is not allowed\r\n+OK\r\n")

    def test_unsupported_command_in_multi(self):
        self.assertEqual(self.exchange([cmd("MULTI"), cmd("SET", "{t}a", "1"), cmd("SUBSCRIBE", "ch"), cmd("EXEC"),
                                        cmd("PING")]),
                         b"+OK\r\n+QUEUED\r\n-ERR 'SUBSCRIBE' is not supported inside a transaction by the proxy\r\n"
                         b"-EXECABORT Transaction discarded because of previous errors.\r\n+PONG\r\n")

    def test_cross_node_transaction_aborts(self):
        """Keys on different nodes in one MULTI: Valkey refuses the second
        and EXEC aborts; nothing is half-applied."""
        c = plain_cluster()
        a, b = "{t}x", next("{z%d}x" % i for i in range(1000) if c.owner("{z%d}x" % i) is not c.owner("{t}x"))
        r = split_replies(self.exchange([cmd("DEL", a), cmd("MULTI"),
                                         cmd("SET", a, "1"), cmd("SET", b, "1"), cmd("EXEC"), cmd("GET", a)]))
        self.assertEqual(r[1:3], [b"+OK\r\n", b"+QUEUED\r\n"])
        self.assertTrue(r[3].startswith(b"-"), r)
        self.assertTrue(r[4].startswith(b"-EXECABORT"), r)
        self.assertEqual(r[5], b"$-1\r\n")

    def test_watch(self):
        c = self.conn()
        c.send(cmd("SET", "{w}k", "1") + cmd("WATCH", "{w}k") + cmd("GET", "{w}k"))
        c.read_raw(3)
        self.proxy.call("SET", "{w}k", "changed")
        c.send(cmd("MULTI") + cmd("SET", "{w}k", "mine") + cmd("EXEC") + cmd("GET", "{w}k"))
        self.assertEqual(b"".join(c.read_raw(4)), b"+OK\r\n+QUEUED\r\n*-1\r\n$7\r\nchanged\r\n",
                         "watched key changed: EXEC returns nil")
        c.send(cmd("WATCH", "{w}k") + cmd("MULTI") + cmd("SET", "{w}k", "mine") + cmd("EXEC"))
        self.assertEqual(b"".join(c.read_raw(4)), b"+OK\r\n+OK\r\n+QUEUED\r\n*1\r\n+OK\r\n", "untouched: EXEC runs")
        c.send(cmd("WATCH", "{w}k") + cmd("UNWATCH") + cmd("GET", "{w}k"))
        self.assertEqual(b"".join(c.read_raw(3)), b"+OK\r\n+OK\r\n$4\r\nmine\r\n")

    def test_select_and_auth_rejected_while_watching(self):
        """They would move the client to another connection and silently
        drop the WATCH."""
        r = split_replies(self.exchange([cmd("WATCH", "wk"), cmd("SELECT", "0"), cmd("AUTH", "x"), cmd("UNWATCH"),
                                         cmd("SELECT", "0")]))
        self.assertEqual(r[0], b"+OK\r\n")
        self.assertIn(b"WATCH is active", r[1])
        self.assertIn(b"WATCH is active", r[2])
        self.assertEqual(r[3:], [b"+OK\r\n", b"+OK\r\n"])

    def test_many_short_transactions(self):
        """Pinned connections are released and reused correctly."""
        for _ in range(200):
            c = self.proxy.conn()
            c.send(cmd("MULTI") + cmd("INCR", "{cnt}x") + cmd("EXEC"))
            r = c.read_raw(3)
            c.close()
            self.assertEqual(r[:2], [b"+OK\r\n", b"+QUEUED\r\n"])
            self.assertTrue(r[2].startswith(b"*1\r\n:"), r)

    # ── robustness ──────────────────────────────────────────────────────

    def test_clients_vanishing_with_replies_in_flight(self):
        for _ in range(50):
            c = self.proxy.conn()
            c.send(b"".join(cmd("GET", "key:%d" % i) for i in range(2000)))
            c.close()
        self.assertEqual(self.exchange([cmd("SET", "k1", "v1"), cmd("PING"), cmd("GET", "k1")]),
                         b"+OK\r\n+PONG\r\n$2\r\nv1\r\n")

    def test_hostile_input(self):
        """Malformed, truncated, oversized and random input, with and without
        reading the reply, then hanging up: the proxy keeps serving and
        leaves no half-closed sockets behind."""
        cases = [b"*", b"*\r\n", b"*-1\r\n", b"*0\r\n", b"*1\r\n$-5\r\n", b"*1\r\n$abc\r\n",
                 b"*2147483647\r\n$1\r\nx\r\n", b"*1\r\n$2147483647\r\n", b"*99999999999\r\n", b"*1\r\n$3\r\nGETX",
                 b"*2\r\n$3\r\nGET\r\n$1\r\nabcdef\r\n", b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$5\r\nv", b"\"unterminated\r\n",
                 b"'x\\'\r\n", b"\"\\x\"\r\n", b"\"\\xZZ\"\r\n", b"\"a\"b\r\n", b"   \r\n", b"\r\n\r\n\n",
                 b"PING " * 20000 + b"\r\n", b"A" * 70000, b"*1\r\n$4\r\nPING\r\n" * 3 + b"*1\r\n$",
                 b"*3\r\n$4\r\nMSET\r\n$1\r\na\r\n", b"*2\r\n$4\r\nMGET\r\n$0\r\n\r\n",
                 b"*1\r\n$5\r\nMULTI\r\n*1\r\n$4\r\nEXEC\r\n*1\r\n$4\r\nEXEC\r\n", b"*2\r\n$5\r\nWATCH\r\n$0\r\n\r\n",
                 b"*1\r\n$3\r\nDEL\r\n", b"*1\r\n$4\r\nECHO\r\n", b"*3\r\n$4\r\nPING\r\n$1\r\na\r\n$1\r\nb\r\n",
                 b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\nc\r\n*1\r\n$4\r\nPING\r\n*2\r\n$11\r\nUNSUBSCRIBE\r\n$1\r\nc\r\n",
                 b"*2\r\n$5\r\nHELLO\r\n$1\r\n9\r\n",
                 b"*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n*2\r\n$3\r\nGET\r\n$1\r\nk\r\n*2\r\n$5\r\nHELLO\r\n$1\r\n2\r\n"]
        rnd = random.Random(1)

        def one(data, read):
            c = self.proxy.conn(timeout=0.3)
            try:
                c.send(data)
                if read:
                    c.readall(0.3)
            except OSError:
                pass
            c.close()

        for data in cases:
            one(data, True)
            one(data, False)
        for _ in range(400):
            pre = rnd.choice([b"", b"*2\r\n$3\r\nGET\r\n$", b"*3\r\n$3\r\nSET\r\n", b"PING ", b"*1\r\n$4\r\nPING\r\n"])
            one(pre + bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 3000))), rnd.random() < 0.5)
        pipeline = b"".join(cmd("SET", "k%d" % j, "v" * 100) for j in range(50))
        for _ in range(200):
            one(pipeline[:rnd.randint(1, len(pipeline))], False)

        self.assertEqual(self.proxy.call("PING"), "PONG")
        # a blocked and a subscribed client that vanish are noticed too
        for data in (cmd("BLPOP", "nolist", "0"), cmd("SUBSCRIBE", "ch")):
            c = self.proxy.conn()
            c.send(data)
            time.sleep(0.3)
            c.close()
        time.sleep(0.5)
        self.assertEqual(close_wait_count(self.proxy.port), 0, "sockets left in CLOSE_WAIT")


if __name__ == "__main__":
    unittest.main()
