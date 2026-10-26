"""Client lifecycle and limits: idle timeouts, graceful shutdown, connection
and output-buffer limits, connection setup failures, config errors."""

import os
import signal
import socket
import stat
import subprocess
import threading
import time
import unittest

from harness import PROXY_BIN, Proxy, cmd, plain_cluster, wait_for, workdir


class Lifecycle(unittest.TestCase):
    def setUp(self):
        plain_cluster().flushall()

    def proxy(self, **kw):
        p = Proxy(plain_cluster(), **kw).start()
        self.addCleanup(lambda: p.proc and p.proc.alive() and p.stop())
        return p

    def other_master(self):
        """A master that isn't the proxy's seed node."""
        return plain_cluster().masters[1]

    @staticmethod
    def answers(c):
        try:
            c.send(cmd("PING"))
            return bool(c.read_raw(1))
        except OSError:
            return False

    # ── timeouts ────────────────────────────────────────────────────────

    def test_idle_clients_are_closed(self):
        """'timeout 2' closes an idle client; busy, blocked and subscribed
        clients stay (as in Valkey)."""
        p = self.proxy(settings={"timeout": 2})
        idle = p.conn()
        idle.call("PING")
        blocked = p.conn()
        blocked.send(cmd("BLPOP", "to:list", "6"))
        sub = p.conn()
        sub.call("SUBSCRIBE", "to:ch")
        busy = p.conn()
        for _ in range(5):
            time.sleep(1)
            busy.call("PING")
        self.assertTrue(idle.closed_by_peer(0.5), "idle client still open")
        self.assertTrue(self.answers(busy))
        self.assertEqual(blocked.read_raw(1), [b"*-1\r\n"], "blocked client got its BLPOP timeout reply")
        self.assertTrue(self.answers(sub), "subscribed client still open")

    def test_slow_fanout_outlives_idle_timeout(self):
        """A client waiting on a fan-out that takes longer than 'timeout'
        isn't idle."""
        p = self.proxy(settings={"timeout": 1})
        self.other_master().call("CLIENT", "PAUSE", 3500, "ALL")
        c = p.conn()
        c.send(cmd("DBSIZE"))
        self.assertEqual(c.read(), 0)

    # ── graceful shutdown ───────────────────────────────────────────────

    def test_sigterm_drains_clients(self):
        p = self.proxy(workers=2, unix=True)
        idle = p.conn()
        idle.call("PING")
        sub = p.conn()
        sub.call("SUBSCRIBE", "dr:ch")
        blk = p.conn()
        blk.send(cmd("BLPOP", "dr:list", "2"))
        time.sleep(0.2)
        t0 = time.time()
        p.proc.signal(signal.SIGTERM)
        self.assertTrue(idle.closed_by_peer(1), "idle client closed promptly")
        self.assertTrue(sub.closed_by_peer(1), "subscriber closed")
        with self.assertRaises(OSError, msg="new connections refused"):
            socket.create_connection(("127.0.0.1", p.port), timeout=1).close()
        self.assertFalse(os.path.exists(p.unix), "unix socket path removed")
        self.assertEqual(blk.read_raw(1), [b"*-1\r\n"], "blocked client gets its reply")
        self.assertTrue(blk.closed_by_peer(2), "and is then closed")
        self.assertEqual(p.stop(timeout=5), 0)
        self.assertLess(time.time() - t0, 5)

    def test_sigterm_delivers_inflight_fanout_reply(self):
        p = self.proxy()
        self.other_master().call("CLIENT", "PAUSE", 1500, "ALL")
        c = p.conn()
        c.send(cmd("DBSIZE"))
        time.sleep(0.2)
        p.proc.signal(signal.SIGTERM)
        self.assertEqual(c.read(), 0)
        self.assertEqual(p.stop(), 0)

    def test_shutdown_timeout_bounds_the_drain(self):
        """A client blocked forever doesn't keep the proxy alive past
        'shutdown-timeout'."""
        p = self.proxy(settings={"shutdown-timeout": 1})
        blk = p.conn()
        blk.send(cmd("BLPOP", "forever", "0"))
        time.sleep(0.2)
        t0 = time.time()
        self.assertEqual(p.stop(timeout=10), 0)
        self.assertLess(time.time() - t0, 4)

    # ── limits ──────────────────────────────────────────────────────────

    def test_maxclients(self):
        p = self.proxy(settings={"maxclients": 5})
        conns = [p.conn() for _ in range(8)]
        replies = []
        for c in conns:
            try:
                replies.append(c.call("PING"))
            except OSError as e:
                replies.append(e)
        self.assertEqual(replies[:5], ["PONG"] * 5)
        for r in replies[5:]:
            self.assertIn("max number of clients reached", str(r))
        for c in conns:
            c.close()
        wait_for(lambda: p.call("PING") == "PONG", 5, what="a slot to free up")

    def test_many_subscribers_on_one_worker(self):
        p = self.proxy()
        subs = [p.conn() for _ in range(60)]
        for s in subs:
            self.assertEqual(s.call("SUBSCRIBE", "lim:ch")[0], b"subscribe")
        p.call("PUBLISH", "lim:ch", "hello")
        for s in subs:
            self.assertEqual(s.read(), [b"message", b"lim:ch", b"hello"])

    def test_slow_subscriber_is_disconnected(self):
        """A subscriber that stops reading is dropped at the pub/sub output
        buffer limit instead of growing the proxy's memory."""
        p = self.proxy(settings={"client-output-buffer-limit-pubsub": 4 * 1024 * 1024})
        slow = p.conn()
        slow.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        slow.call("SUBSCRIBE", "lim:big")
        pub = p.conn()
        payload = b"x" * (1 << 20)
        for _ in range(24):
            pub.call("PUBLISH", "lim:big", payload)
        time.sleep(0.5)
        slow.readall(2)  # drain what was sent before the cut-off...
        self.assertTrue(slow.closed_by_peer(1), "slow subscriber still connected")  # ...then EOF
        self.assertEqual(p.call("PING"), "PONG")

    # ── backend connection setup ────────────────────────────────────────

    def test_rejected_connection_setup_fails_requests(self):
        """With 'db 1' on a cluster (db 0 only), the backend rejects the
        SELECT: requests fail with that error instead of quietly running
        against db 0."""
        p = self.proxy(settings={"db": 1})
        c = p.conn()
        c.send(cmd("GET", "a") + cmd("SET", "a", "x"))
        for r in c.read_raw(2):
            self.assertTrue(r.startswith(b"-ERR backend rejected connection setup"), r)

    # ── listeners and config ────────────────────────────────────────────

    def test_unix_socket(self):
        p = self.proxy(unix=True, settings={"unix-socket-perm": 660})
        self.assertEqual(stat.S_IMODE(os.stat(p.unix).st_mode), 0o660)
        c = p.conn(unix=True)
        self.assertEqual(c.call("SET", "ux", "1"), "OK")
        self.assertEqual(c.call("GET", "ux"), b"1")
        c.close()

    def test_bad_config_names_file_and_line(self):
        conf = os.path.join(workdir("badconf"), "bad.conf")
        with open(conf, "w") as f:
            f.write("server-ip 127.0.0.1\nserver-port %d\nport 1\n\ntls-backend yess\n" % plain_cluster().seed)
        r = subprocess.run([PROXY_BIN, conf], capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 1)
        self.assertIn("%s:5: 'tls-backend' must be yes or no, got 'yess'" % conf, r.stderr)

    def test_concurrent_clients_across_workers(self):
        """Many clients at once on 4 workers, each with its own keys: every
        reply lands at the client that asked."""
        p = self.proxy(workers=4)
        errors = []

        def client(i):
            try:
                c = p.conn()
                for j in range(200):
                    c.send(cmd("SET", "c%d:%d" % (i, j), j) + cmd("GET", "c%d:%d" % (i, j)))
                    if c.read_raw(2) != [b"+OK\r\n", b"$%d\r\n%d\r\n" % (len(str(j)), j)]:
                        errors.append(i)
                        break
                c.close()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=client, args=(i,)) for i in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
