"""Topology changes under the proxy: slot migration (ASK/MOVED), a master
dying and coming back, and replica failover under load. The destructive
tests start their own clusters."""

import threading
import time
import unittest

from harness import Cluster, Proxy, cmd, plain_cluster, wait_for


class SlotMigration(unittest.TestCase):
    def test_ask_and_moved_during_migration(self):
        c = plain_cluster()
        c.flushall()
        key, new = "{mv}k", "{mv}new"
        slot = c.masters[0].call("CLUSTER", "KEYSLOT", key)
        src = c.owner(key)
        dst = next(m for m in c.masters if m is not src)

        def assign(owner):
            for m in c.masters:
                m.call("CLUSTER", "SETSLOT", slot, "NODE", owner.id)

        with Proxy(c) as p:
            pc = p.conn()
            self.assertEqual(pc.call("SET", key, "before"), "OK")
            try:
                dst.call("CLUSTER", "SETSLOT", slot, "IMPORTING", src.id)
                src.call("CLUSTER", "SETSLOT", slot, "MIGRATING", dst.id)
                # a new key during migration is ASK-redirected to dst
                self.assertEqual(pc.call("SET", new, "fresh"), "OK")
                self.assertEqual(pc.call("GET", new), b"fresh")
                d = dst.conn()
                d.call("ASKING")
                self.assertEqual(d.call("GET", new), b"fresh", "stored on the importing node")
                d.close()
                # an existing key moved mid-migration: ASK as well
                src.call("MIGRATE", "127.0.0.1", dst.port, "", 0, 5000, "KEYS", key)
                self.assertEqual(pc.call("GET", key), b"before")
                # migration finished: MOVED, then the proxy's map catches up
                assign(dst)
                pc.send(cmd("GET", key) + cmd("GET", new) + cmd("SET", key, "after") + cmd("GET", key))
                self.assertEqual(b"".join(pc.read_raw(4)), b"$6\r\nbefore\r\n$5\r\nfresh\r\n+OK\r\n$5\r\nafter\r\n")
                self.assertEqual(pc.call("MGET", key, new, "other"), [b"after", b"fresh", None])
            finally:
                # move the slot (and its keys) back
                src.call("CLUSTER", "SETSLOT", slot, "IMPORTING", dst.id)
                dst.call("CLUSTER", "SETSLOT", slot, "MIGRATING", src.id)
                dst.call("MIGRATE", "127.0.0.1", src.port, "", 0, 5000, "KEYS", key, new)
                assign(src)
            self.assertEqual(pc.call("GET", key), b"after")
            pc.close()


class NodeFailure(unittest.TestCase):
    def test_master_dies_and_comes_back(self):
        """No replicas: requests fail (quickly, without hanging) while the
        master is down, and everything works again once it's back."""
        c = Cluster("dead-node", node_timeout=2000).start()
        self.addCleanup(c.stop)
        with Proxy(c) as p:
            keys = ["dn:%d" % i for i in range(30)]
            pc = p.conn(timeout=10)
            for k in keys:
                self.assertEqual(pc.call("SET", k, "x"), "OK")
            victim = c.masters[2]
            victim.stop()
            for _ in range(3):
                for k in keys[:10]:
                    t0 = time.time()
                    pc.call("GET", k)          # error or value, but an answer
                    pc.call("MGET", k, keys[-1])
                    self.assertLess(time.time() - t0, 5)
            victim.start()
            c.wait_ok()

            def all_ok():
                return all(pc.call("SET", k, "back") == "OK" for k in keys)
            wait_for(all_ok, 15, interval=0.5, what="every key writable again")
            self.assertEqual(pc.call("MGET", *keys[:5]), [b"back"] * 5)
            pc.close()


class Failover(unittest.TestCase):
    """A master is killed under steady load; its replica takes over and the
    proxy follows within a few seconds, without a restart."""

    def run_failover(self, victim_index):
        c = Cluster("failover-%d" % victim_index, masters=3, replicas=1, node_timeout=2000).start()
        self.addCleanup(c.stop)
        with Proxy(c, workers=2) as p:
            buckets = {}
            t_start = time.time()
            kill_at = 3.0
            duration = 15.0

            def load():
                conn, i = None, 0
                while time.time() - t_start < duration:
                    sec = int(time.time() - t_start)
                    k = "fo:%d" % (i % 997)
                    i += 1
                    ok = False
                    try:
                        if conn is None:
                            conn = p.conn(timeout=3)
                        conn.send(cmd("SET", k, "v") + cmd("GET", k))
                        ok = conn.read_raw(2) == [b"+OK\r\n", b"$1\r\nv\r\n"]
                    except OSError:
                        if conn:
                            conn.close()
                        conn = None
                    b = buckets.setdefault(sec, [0, 0])
                    b[0 if ok else 1] += 1
                    if not ok:
                        time.sleep(0.01)
                if conn:
                    conn.close()

            t = threading.Thread(target=load)
            t.start()
            time.sleep(kill_at)
            c.masters[victim_index].stop()
            t.join()

            timeline = " ".join("%ds:%d/%d" % (s, b[0], b[1]) for s, b in sorted(buckets.items()))
            err_secs = [s for s, b in buckets.items() if b[1]]
            self.assertTrue(all(buckets[s][1] == 0 for s in buckets if s < kill_at), timeline)
            last_err = max(err_secs, default=0)
            # recovered: the tail of the run is error-free and serving
            self.assertLess(last_err, duration - 3, "still failing at the end (ok/err per second: %s)" % timeline)
            self.assertLess(last_err - kill_at, 10, "took too long to recover: %s" % timeline)
            for s in range(int(duration) - 2, int(duration)):
                self.assertGreater(buckets.get(s, [0, 0])[0], 0, timeline)

    def test_failover_of_a_non_seed_master(self):
        self.run_failover(1)

    def test_failover_of_the_seed_master(self):
        """The node named in server-ip/server-port dies: the proxy has to
        keep discovering the topology through the others."""
        self.run_failover(0)


if __name__ == "__main__":
    unittest.main()
