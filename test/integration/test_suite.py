"""The C command suite (./run-test) against proxies in different setups."""

import unittest

from harness import Proxy, TlsForwarder, plain_cluster, require_tls, run_c_suite, tls_cluster


class CommandSuite(unittest.TestCase):
    def setUp(self):
        plain_cluster().flushall()

    def check(self, rc, out):
        summary = [l for l in out.splitlines() if l.startswith("Total:")]
        failed = [l.strip() for l in out.splitlines() if "[FAIL]" in l]
        self.assertEqual(rc, 0, "%s\n%s" % (summary, "\n".join(failed[:30]) or out[-3000:]))

    def test_one_worker(self):
        c = plain_cluster()
        with Proxy(c, workers=1) as p:
            self.check(*run_c_suite(p.port, ["--cluster=127.0.0.1:%d" % c.seed]))

    def test_four_workers(self):
        c = plain_cluster()
        with Proxy(c, workers=4) as p:
            self.check(*run_c_suite(p.port, ["--cluster=127.0.0.1:%d" % c.seed]))

    def test_tls_clients_and_backends_four_workers(self):
        require_tls(self)
        tls_cluster().flushall()
        with Proxy(tls_cluster(), workers=4, tls_clients=True) as p:
            fwd = TlsForwarder(p.port, p.client_tls())
            try:
                self.check(*run_c_suite(fwd.port))
            finally:
                fwd.close()


if __name__ == "__main__":
    unittest.main()
