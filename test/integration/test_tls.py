"""TLS: mutual TLS, handshake handling, certificate reload, backend
certificate verification. Skipped when valkey-server has no TLS support."""

import os
import shutil
import signal
import socket
import ssl
import time
import unittest

from harness import Cluster, Conn, Proxy, certs, client_tls_context, plain_cluster, require_tls, tls_cluster, \
    wait_for, workdir


def peer_cn(conn):
    return dict(x[0] for x in conn.sock.getpeercert()["subject"])["commonName"]


class Tls(unittest.TestCase):
    def setUp(self):
        require_tls(self)

    def proxy(self, cluster, **kw):
        p = Proxy(cluster, **kw).start()
        self.addCleanup(lambda: p.proc.alive() and p.stop())
        return p

    def test_plain_clients_tls_backends(self):
        p = self.proxy(tls_cluster())
        c = p.conn()
        c.send(b"".join(b"*3\r\n$3\r\nSET\r\n$3\r\nk%02d\r\n$1\r\nv\r\n" % i for i in range(50)))
        self.assertEqual(c.read_raw(50), [b"+OK\r\n"] * 50)
        self.assertEqual(c.call("MGET", "k01", "k02", "nosuch"), [b"v", b"v", None])

    def test_mutual_tls_required(self):
        c = certs()
        p = self.proxy(plain_cluster(), tls_clients=True, client_cert="client",
                       settings={"tls-ca-cert": c.ca, "tls-auth-clients": "yes"})
        self.assertEqual(p.call("PING"), "PONG")
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            Conn(p.port, tls=client_tls_context(c.ca), timeout=3).call("PING")
        # a certificate from the right CA, but not a client certificate one
        # would present, still works: only the chain is checked
        self.assertEqual(Conn(p.port, tls=p.client_tls("server2")).call("PING"), "PONG")

    def test_plaintext_and_silence_on_the_tls_port(self):
        """Plain text on the TLS port is dropped; a client that connects and
        sends nothing is closed after tls-handshake-timeout."""
        p = self.proxy(plain_cluster(), tls_clients=True, settings={"tls-handshake-timeout": 1})
        s = socket.create_connection(("127.0.0.1", p.port))
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        s.settimeout(3)
        try:
            got = s.recv(100)
        except OSError:
            got = b""
        self.assertNotIn(b"PONG", got)
        s.close()
        quiet = socket.create_connection(("127.0.0.1", p.port))
        quiet.settimeout(5)
        t0 = time.time()
        self.assertEqual(quiet.recv(100), b"")
        self.assertLess(time.time() - t0, 3)
        self.assertEqual(p.call("PING"), "PONG")

    def test_certificate_reload(self):
        """SIGHUP, and tls-auto-reload noticing replaced files, switch new
        connections to the new certificate; open connections carry on; a
        broken file keeps the old certificate."""
        c = certs()
        live = workdir("live-certs")

        def install(name):  # the way Kubernetes updates a secret: write elsewhere, rename over
            for ext in ("crt", "key"):
                shutil.copy(os.path.join(c.dir, "%s.%s" % (name, ext)), os.path.join(live, "tmp." + ext))
                os.replace(os.path.join(live, "tmp." + ext), os.path.join(live, "tls." + ext))

        install("server")
        p = self.proxy(plain_cluster(), tls_clients=True,
                       settings={"tls-cert": os.path.join(live, "tls.crt"), "tls-key": os.path.join(live, "tls.key")})
        old = p.conn()
        self.assertEqual(peer_cn(old), "server")

        install("server2")
        p.proc.signal(signal.SIGHUP)
        wait_for(lambda: peer_cn(p.conn()) == "server2", 5, what="certificate after SIGHUP")
        self.assertEqual(old.call("PING"), "PONG", "open connection unaffected")

        install("server")  # no signal: the periodic check picks it up
        wait_for(lambda: peer_cn(p.conn()) == "server", 15, interval=0.5, what="automatic reload")

        with open(os.path.join(live, "tls.crt"), "w") as f:
            f.write("not a certificate\n")
        p.proc.signal(signal.SIGHUP)
        time.sleep(0.5)
        new = p.conn()
        self.assertEqual(peer_cn(new), "server", "broken file: old certificate kept")
        self.assertEqual(new.call("PING"), "PONG")

    def test_backend_verify_host(self):
        """tls-backend-verify-host: nodes whose certificate names their
        address are accepted; a valid certificate for another host isn't."""
        p = self.proxy(tls_cluster(), settings={"tls-backend-verify-host": "yes"})
        self.assertEqual(p.call("SET", "vh", "1"), "OK")
        p.stop()

        wrong = Cluster("wrongsan", masters=1, tls=True, cert_name="wrongsan").start()
        self.addCleanup(wrong.stop)
        with self.assertRaises(RuntimeError) as e:
            Proxy(wrong, settings={"tls-backend-verify-host": "yes"}).start()
        self.assertIn("certificate verify failed", str(e.exception))
        # the same cluster without host checking: the chain is still valid
        p = self.proxy(wrong)
        self.assertEqual(p.call("SET", "vh", "1"), "OK")


if __name__ == "__main__":
    unittest.main()
