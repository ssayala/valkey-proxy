"""Integration test harness: throwaway Valkey clusters and proxy processes.

Everything runs on 127.0.0.1 with free ports, under one temporary directory
(kept, with all server and proxy logs, when a test fails). Nothing here needs
anything installed except python3, openssl and a valkey-server binary:

  VALKEY_SERVER=/path/to/valkey-server   use this one
  (unset)                                 download the pinned release below,
                                          check its sha256, build it once with
                                          TLS into test/.deps/

A valkey-server built without TLS still runs every non-TLS test; the TLS
tests are skipped and say why.
"""

import asyncio
import hashlib
import os
import random
import shutil
import signal
import socket
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROXY_BIN = os.path.join(ROOT, "valkey-proxy")
RUN_TEST_BIN = os.path.join(ROOT, "run-test")
DEPS = os.path.join(ROOT, "test", ".deps")

VALKEY_VERSION = "9.1.2"
VALKEY_SHA256 = "19c23908e7d57e8d91ef85b41f5646307582f10f4f0fb999bbf89ed24ec9c983"
VALKEY_URL = "https://github.com/valkey-io/valkey/archive/refs/tags/%s.tar.gz" % VALKEY_VERSION

# Reports any of the sanitizers write; a proxy log containing one fails the test.
SANITIZER_MARKERS = ("ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "WARNING: ThreadSanitizer", "runtime error:")

WORK = None          # temp dir for this run, set by init()
_processes = []      # everything started, stopped at cleanup()
_used_ports = set()


def log(msg):
    print(msg, flush=True)


def init(keep=False):
    global WORK
    WORK = tempfile.mkdtemp(prefix="valkey-proxy-it-")
    return WORK


def cleanup(keep):
    for p in list(_processes):
        p.kill()
    _stop_shared()
    if WORK and not keep:
        shutil.rmtree(WORK, ignore_errors=True)


def workdir(name):
    d = os.path.join(WORK, name)
    os.makedirs(d, exist_ok=True)
    return d


def wait_for(cond, timeout, interval=0.05, what="condition"):
    end = time.time() + timeout
    while True:
        try:
            v = cond()
            if v:
                return v
        except Exception:
            pass
        if time.time() > end:
            raise TimeoutError("timed out after %.1fs waiting for %s" % (timeout, what))
        time.sleep(interval)


def free_port():
    """A free port whose cluster bus port (+10000) is free as well."""
    for _ in range(1000):
        p = random.randint(20000, 29999)
        if p in _used_ports:
            continue
        try:
            for q in (p, p + 10000):
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", q))
                s.close()
        except OSError:
            continue
        _used_ports.add(p)
        return p
    raise RuntimeError("no free port")


# ── RESP client ────────────────────────────────────────────────────────

def cmd(*args):
    out = [b"*%d\r\n" % len(args)]
    for a in args:
        a = a if isinstance(a, bytes) else str(a).encode()
        out.append(b"$%d\r\n%s\r\n" % (len(a), a))
    return b"".join(out)


class RespError(Exception):
    pass


def reply_len(b, o=0):
    """Length of the complete RESP reply at b[o:], or None if incomplete."""
    if o >= len(b):
        return None
    nl = b.find(b"\r\n", o)
    if nl < 0:
        return None
    t = b[o:o + 1]
    if t in b"+-:_,#(":
        return nl + 2 - o
    n = int(b[o + 1:nl])
    if t in b"$=":
        end = nl + 2 if n < 0 else nl + 2 + n + 2
        return end - o if end <= len(b) else None
    p = nl + 2
    for _ in range(max(n, 0) * (2 if t == b"%" else 1)):
        el = reply_len(b, p)
        if el is None:
            return None
        p += el
    return p - o


def split_replies(b):
    out, o = [], 0
    while o < len(b):
        n = reply_len(b, o)
        if n is None:
            raise ValueError("incomplete reply at byte %d: %r" % (o, b[o:o + 60]))
        out.append(b[o:o + n])
        o += n
    return out


def parse_reply(b):
    """Decodes one complete raw reply: bytes / int / str / None / list,
    and RespError instances (returned, not raised) for errors."""
    t, nl = b[:1], b.index(b"\r\n")
    line = b[1:nl]
    if t == b"+":
        return line.decode()
    if t == b"-":
        return RespError(line.decode())
    if t == b":":
        return int(line)
    if t == b"_":
        return None
    if t == b"$":
        n = int(line)
        return None if n < 0 else b[nl + 2:nl + 2 + n]
    if t in b"*~>%":
        n = int(line)
        if n < 0:
            return None
        items, p = [], nl + 2
        for _ in range(n * (2 if t == b"%" else 1)):
            ln = reply_len(b, p)
            items.append(parse_reply(b[p:p + ln]))
            p += ln
        return items
    return b


def client_tls_context(ca, cert=None, key=None):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if cert:
        ctx.load_cert_chain(cert, key)
    return ctx


class Conn:
    """A blocking RESP connection (plain, TLS, or a Unix socket path)."""

    def __init__(self, port, tls=None, timeout=10, unix=None):
        if unix:
            s = socket.socket(socket.AF_UNIX)
            s.settimeout(timeout)
            s.connect(unix)
        else:
            s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        if tls:
            s = tls.wrap_socket(s)
        s.settimeout(timeout)
        self.sock = s
        self.buf = b""

    def send(self, data):
        self.sock.sendall(data)

    def _fill(self):
        d = self.sock.recv(1 << 20)
        if not d:
            raise ConnectionError("connection closed by the proxy")
        self.buf += d

    def read_raw(self, n=1):
        """The next n replies, as raw bytes each."""
        out = []
        while len(out) < n:
            ln = reply_len(self.buf)
            if ln is None:
                self._fill()
                continue
            out.append(self.buf[:ln])
            self.buf = self.buf[ln:]
        return out

    def read(self):
        return parse_reply(self.read_raw(1)[0])

    def call(self, *args):
        self.send(cmd(*args))
        return self.read()

    def readall(self, timeout=1.0):
        """Whatever arrives until the peer closes or `timeout` passes quietly."""
        self.sock.settimeout(timeout)
        data, self.buf = self.buf, b""
        try:
            while True:
                d = self.sock.recv(1 << 20)
                if not d:
                    break
                data += d
        except (socket.timeout, ConnectionResetError, ssl.SSLError):
            pass
        return data

    def closed_by_peer(self, timeout=2.0):
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(65536) == b""
        except (ConnectionResetError, BrokenPipeError):
            return True
        except (socket.timeout, ssl.SSLError, OSError):
            return False

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ── processes ──────────────────────────────────────────────────────────

class Process:
    def __init__(self, argv, logfile, env=None, cwd=None):
        self.argv, self.logfile = argv, logfile
        self.log_fh = open(logfile, "ab")
        self.proc = subprocess.Popen(argv, stdout=self.log_fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     env=env, cwd=cwd, start_new_session=True)
        _processes.append(self)

    @property
    def pid(self):
        return self.proc.pid

    def alive(self):
        return self.proc.poll() is None

    def signal(self, sig):
        if self.alive():
            self.proc.send_signal(sig)

    def wait(self, timeout):
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self):
        if self.alive():
            self.proc.kill()
            self.proc.wait()
        self.log_fh.close()
        if self in _processes:
            _processes.remove(self)

    def log_text(self):
        if not self.log_fh.closed:
            self.log_fh.flush()
        with open(self.logfile, "rb") as f:
            return f.read().decode(errors="replace")


# ── valkey-server ──────────────────────────────────────────────────────

_server_bin = None
_server_tls = None


def valkey_server():
    global _server_bin
    if _server_bin:
        return _server_bin
    env = os.environ.get("VALKEY_SERVER")
    if env:
        if not os.access(env, os.X_OK):
            raise RuntimeError("VALKEY_SERVER=%s is not an executable" % env)
        _server_bin = env
        return env
    built = os.path.join(DEPS, "valkey-" + VALKEY_VERSION, "src", "valkey-server")
    if not os.access(built, os.X_OK):
        _build_valkey()
    _server_bin = built
    return built


def _build_valkey():
    os.makedirs(DEPS, exist_ok=True)
    tgz = os.path.join(DEPS, "valkey-%s.tar.gz" % VALKEY_VERSION)
    if not os.path.exists(tgz):
        log("downloading valkey %s (set VALKEY_SERVER to use your own build instead)" % VALKEY_VERSION)
        with urllib.request.urlopen(VALKEY_URL, timeout=120) as r, open(tgz + ".part", "wb") as f:
            shutil.copyfileobj(r, f)
        os.replace(tgz + ".part", tgz)
    with open(tgz, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    if digest != VALKEY_SHA256:
        os.unlink(tgz)
        raise RuntimeError("valkey %s tarball sha256 mismatch: got %s, want %s" % (VALKEY_VERSION, digest,
                                                                                   VALKEY_SHA256))
    src = os.path.join(DEPS, "valkey-" + VALKEY_VERSION)
    shutil.rmtree(src, ignore_errors=True)
    with tarfile.open(tgz) as t:
        t.extractall(DEPS, filter="data")
    log("building valkey %s with TLS (once, about a minute) ..." % VALKEY_VERSION)
    buildlog = os.path.join(DEPS, "valkey-build.log")
    with open(buildlog, "wb") as f:
        rc = subprocess.call(["make", "-j%d" % (os.cpu_count() or 2), "BUILD_TLS=yes"], cwd=src, stdout=f,
                             stderr=subprocess.STDOUT)
    if rc != 0:
        with open(buildlog, "rb") as f:
            tail = f.read()[-3000:].decode(errors="replace")
        raise RuntimeError("building valkey failed (full log: %s):\n%s" % (buildlog, tail))


def server_has_tls():
    """Whether the valkey-server binary can serve TLS: tried once, for real."""
    global _server_tls
    if _server_tls is None:
        c = certs()
        port = free_port()
        d = workdir("tls-probe")
        p = Process([valkey_server(), "--port", "0", "--tls-port", str(port), "--tls-cert-file", c.server_crt,
                     "--tls-key-file", c.server_key, "--tls-ca-cert-file", c.ca, "--tls-auth-clients", "no",
                     "--save", "", "--dir", d], os.path.join(d, "log.txt"))
        try:
            ctx = client_tls_context(c.ca)
            wait_for(lambda: Conn(port, tls=ctx, timeout=1).call("PING") == "PONG", 3, what="TLS probe")
            _server_tls = True
        except Exception:
            _server_tls = False
        p.kill()
    return _server_tls


def require_tls(test):
    if not server_has_tls():
        test.skipTest("valkey-server has no TLS support: unset VALKEY_SERVER to use the pinned build, "
                      "or point it at a 'make BUILD_TLS=yes' build")


# ── certificates ───────────────────────────────────────────────────────

class Certs:
    def __init__(self, d):
        self.dir = d
        self.ca = os.path.join(d, "ca.crt")

    def crt(self, name):
        return os.path.join(self.dir, name + ".crt")

    def key(self, name):
        return os.path.join(self.dir, name + ".key")

    server_crt = property(lambda self: self.crt("server"))
    server_key = property(lambda self: self.key("server"))


_certs = None


def certs():
    """A test CA plus certificates: server and server2 (both for 127.0.0.1
    and localhost, distinguished by CN), client (for mTLS) and wrongsan (a
    valid certificate for some other host)."""
    global _certs
    if _certs:
        return _certs
    d = workdir("certs")

    def ossl(*args):
        subprocess.run(["openssl"] + list(args), cwd=d, check=True, capture_output=True)

    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    ossl("req", "-x509", *ec, "-keyout", "ca.key", "-out", "ca.crt", "-days", "7", "-subj", "/CN=test-ca")
    for name, ext in (("server", "subjectAltName=IP:127.0.0.1,DNS:localhost"),
                      ("server2", "subjectAltName=IP:127.0.0.1,DNS:localhost"),
                      ("client", "extendedKeyUsage=clientAuth"),
                      ("wrongsan", "subjectAltName=DNS:wrong.example")):
        with open(os.path.join(d, name + ".ext"), "w") as f:
            f.write(ext + "\n")
        ossl("req", *ec, "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + name)
        ossl("x509", "-req", "-in", name + ".csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
             "-out", name + ".crt", "-days", "7", "-extfile", name + ".ext")
    _certs = Certs(d)
    return _certs


# ── clusters ───────────────────────────────────────────────────────────

class Node:
    def __init__(self, cluster, port):
        self.cluster, self.port = cluster, port
        self.dir = workdir("%s/%d" % (cluster.name, port))
        self.proc = None
        self.id = None

    def start(self):
        c = self.cluster
        args = [valkey_server(), "--cluster-enabled", "yes", "--cluster-config-file", "nodes.conf",
                "--cluster-node-timeout", str(c.node_timeout), "--save", "", "--appendonly", "no", "--dir", self.dir,
                "--bind", "127.0.0.1", "--enable-debug-command", "yes", "--repl-diskless-sync-delay", "0"]
        if c.tls:
            args += ["--port", "0", "--tls-port", str(self.port), "--tls-cluster", "yes", "--tls-replication", "yes",
                     "--tls-cert-file", c.certs.crt(c.cert_name), "--tls-key-file", c.certs.key(c.cert_name),
                     "--tls-ca-cert-file", c.certs.ca, "--tls-auth-clients", "no"]
        else:
            args += ["--port", str(self.port)]
        self.proc = Process(args, os.path.join(self.dir, "log.txt"))
        wait_for(lambda: self.call("PING") == "PONG", 10, what="valkey-server on port %d" % self.port)
        self.id = self.call("CLUSTER", "MYID").decode()

    def stop(self):
        if self.proc:
            self.proc.kill()
            self.proc = None

    def conn(self, timeout=5):
        return Conn(self.port, tls=self.cluster.client_tls, timeout=timeout)

    def call(self, *args):
        c = self.conn()
        try:
            return c.call(*args)
        finally:
            c.close()


class Cluster:
    def __init__(self, name, masters=3, replicas=0, tls=False, node_timeout=2000, cert_name="server"):
        self.name, self.tls, self.node_timeout, self.cert_name = name, tls, node_timeout, cert_name
        self.certs = certs() if tls else None
        self.client_tls = client_tls_context(self.certs.ca) if tls else None
        self.masters = [Node(self, free_port()) for _ in range(masters)]
        self.replicas = [Node(self, free_port()) for _ in range(masters * replicas)]
        self.nodes = self.masters + self.replicas

    @property
    def seed(self):
        return self.masters[0].port

    def start(self):
        for n in self.nodes:
            n.start()
        per = 16384 // len(self.masters)
        for i, m in enumerate(self.masters):
            last = 16383 if i == len(self.masters) - 1 else (i + 1) * per - 1
            m.call("CLUSTER", "ADDSLOTSRANGE", i * per, last)
        for n in self.nodes[1:]:
            n.call("CLUSTER", "MEET", "127.0.0.1", self.seed)
        wait_for(lambda: all(len(n.call("CLUSTER", "NODES").splitlines()) == len(self.nodes) for n in self.nodes),
                 20, what="cluster %s to meet" % self.name)
        nrep = len(self.replicas) // len(self.masters)
        for i, r in enumerate(self.replicas):
            r.call("CLUSTER", "REPLICATE", self.masters[i // nrep].id)
        # a replica that has never synced refuses to take over, so a test
        # that kills a master must not start before this
        for r in self.replicas:
            wait_for(lambda: b"master_link_status:up" in r.call("INFO", "replication"), 20,
                     what="replica %d to sync" % r.port)
        self.wait_ok()
        return self

    def wait_ok(self, timeout=30):
        def ok():
            for n in self.nodes:
                if not n.proc:
                    continue
                if b"cluster_state:ok" not in n.call("CLUSTER", "INFO"):
                    return False
                if any(b"fail" in l.split()[2] for l in n.call("CLUSTER", "NODES").splitlines()):
                    return False
            return True
        wait_for(ok, timeout, interval=0.2, what="cluster %s state ok" % self.name)

    def stop(self):
        for n in self.nodes:
            n.stop()

    def flushall(self):
        """Empties every database on every master, so tests don't see each
        other's keys."""
        for m in self.masters:
            if m.proc and b"role:master" in m.call("INFO", "replication"):
                m.call("FLUSHALL")

    def node_by_port(self, port):
        return next(n for n in self.nodes if n.port == port)

    def owner(self, key):
        """The master currently serving key's slot."""
        slot = self.masters[0].call("CLUSTER", "KEYSLOT", key)
        for n in self.nodes:
            if not n.proc:
                continue
            for line in n.call("CLUSTER", "NODES").decode().splitlines():
                f = line.split()
                if "master" not in f[2] or "fail" in f[2]:
                    continue
                for r in f[8:]:
                    if r.startswith("["):
                        continue
                    lo, _, hi = r.partition("-")
                    if int(lo) <= slot <= int(hi or lo):
                        return self.node_by_port(int(f[1].split("@")[0].rsplit(":", 1)[1]))
            break
        raise LookupError("no owner for slot %d" % slot)


# Shared clusters, started on first use and kept for the whole run. Tests
# that kill or reconfigure nodes start their own instead.
_shared = {}


def plain_cluster():
    if "plain" not in _shared:
        _shared["plain"] = Cluster("plain").start()
    return _shared["plain"]


def tls_cluster():
    if "tls" not in _shared:
        _shared["tls"] = Cluster("tls", tls=True).start()
    return _shared["tls"]


def _stop_shared():
    for c in _shared.values():
        c.stop()
    _shared.clear()


# ── the proxy ──────────────────────────────────────────────────────────

class Proxy:
    """A valkey-proxy in front of `cluster`. tls_clients: clients connect with
    TLS. settings: extra config lines as {key: value}. Use as a context
    manager, or start()/stop(); stop() fails the test if the log contains a
    sanitizer report."""

    _n = 0

    def __init__(self, cluster, workers=1, tls_clients=False, settings=None, unix=False, client_cert=None):
        Proxy._n += 1
        self.cluster, self.tls_clients = cluster, tls_clients
        self.client_cert = client_cert  # certs() name presented by default TLS connections
        self.dir = workdir("proxy-%d" % Proxy._n)
        self.port = free_port()
        self.unix = os.path.join(self.dir, "proxy.sock") if unix else None
        conf = {"server-ip": "127.0.0.1", "server-port": cluster.seed, "bind": "127.0.0.1", "port": self.port,
                "worker-thread-no": workers}
        if cluster.tls:
            conf.update({"tls-backend": "yes", "tls-backend-ca-cert": cluster.certs.ca})
        if tls_clients:
            c = certs()
            conf.update({"tls-enabled": "yes", "tls-cert": c.server_crt, "tls-key": c.server_key})
        if self.unix:
            conf["unix-socket"] = self.unix
        conf.update(settings or {})
        self.conf = os.path.join(self.dir, "proxy.conf")
        with open(self.conf, "w") as f:
            for k, v in conf.items():
                f.write("%s %s\n" % (k, v))
        self.proc = None

    def client_tls(self, cert=None):
        """TLS context for a client connection (None for a plain proxy);
        cert: the certs() name to present, default client_cert."""
        if not self.tls_clients:
            return None
        cert = cert or self.client_cert
        c = certs()
        return client_tls_context(c.ca, c.crt(cert), c.key(cert)) if cert else client_tls_context(c.ca)

    def start(self):
        env = dict(os.environ)
        env.setdefault("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=0")
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1")
        env.setdefault("TSAN_OPTIONS", "halt_on_error=0:second_deadlock_stack=1")
        self.proc = Process([PROXY_BIN, self.conf], os.path.join(self.dir, "proxy.log"), env=env)

        def up():
            if not self.proc.alive():
                raise RuntimeError("proxy exited during startup:\n" + self.proc.log_text()[-3000:])
            c = self.conn(timeout=1)
            ok = c.call("PING") == "PONG"
            c.close()
            return ok
        try:
            wait_for(up, 20, what="proxy on port %d" % self.port)
        except TimeoutError:
            raise RuntimeError("proxy did not come up:\n" + self.proc.log_text()[-3000:])
        return self

    @property
    def pid(self):
        return self.proc.pid

    def conn(self, timeout=10, tls=None, unix=False):
        if unix:
            return Conn(None, unix=self.unix, timeout=timeout)
        return Conn(self.port, tls=tls or self.client_tls(), timeout=timeout)

    def call(self, *args):
        c = self.conn()
        try:
            return c.call(*args)
        finally:
            c.close()

    def stop(self, timeout=30):
        """SIGTERM and wait; returns the exit code."""
        if not self.proc:
            return None
        self.proc.signal(signal.SIGTERM)
        rc = self.proc.wait(timeout)
        if rc is None:
            self.proc.signal(signal.SIGABRT)
            self.proc.wait(10)
        self.proc.kill()
        self.check_log()
        if rc is None:
            raise AssertionError("proxy did not exit within %ds of SIGTERM" % timeout)
        return rc

    def check_log(self):
        text = self.proc.log_text()
        hits = [m for m in SANITIZER_MARKERS if m in text]
        if hits:
            raise AssertionError("sanitizer report in %s:\n%s" % (self.proc.logfile, text[-6000:]))

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


# ── helpers for tests ──────────────────────────────────────────────────

class TlsForwarder:
    """Plain TCP on a local port -> TLS to the proxy, for the C test runner
    (which only speaks plain TCP) against a TLS-only proxy. asyncio in a
    background thread: an SSL socket can't be read and written from two
    threads at once."""

    def __init__(self, target_port, ctx):
        self.target, self.ctx = target_port, ctx
        self.loop = asyncio.new_event_loop()
        # connections still open at close() are torn down mid-flight; that's
        # expected here, and any real problem fails run-test anyway
        self.loop.set_exception_handler(lambda loop, ctx: None)
        ready = threading.Event()
        threading.Thread(target=self._run, args=(ready,), daemon=True).start()
        ready.wait(10)

    def _run(self, ready):
        asyncio.set_event_loop(self.loop)
        self.server = self.loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", 0))
        self.port = self.server.sockets[0].getsockname()[1]
        ready.set()
        self.loop.run_forever()

    async def _handle(self, cr, cw):
        try:
            ur, uw = await asyncio.open_connection("127.0.0.1", self.target, ssl=self.ctx)
        except OSError:
            cw.close()
            return
        await asyncio.gather(self._pipe(cr, uw), self._pipe(ur, cw))

    @staticmethod
    async def _pipe(r, w):
        try:
            while True:
                d = await r.read(65536)
                if not d:
                    break
                w.write(d)
                await w.drain()
            if w.can_write_eof():
                w.write_eof()           # pass a half-close on
            else:
                w.close()
        except Exception:
            w.close()

    async def _shutdown(self):
        self.server.close()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def close(self):
        asyncio.run_coroutine_threadsafe(self._shutdown(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)


def run_c_suite(port, extra=()):
    """Runs the C test runner (./run-test) against a proxy port; returns
    (exit code, output)."""
    r = subprocess.run([RUN_TEST_BIN, "-h=127.0.0.1", "-p=%d" % port] + list(extra), capture_output=True,
                       timeout=1800)
    return r.returncode, r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")


def close_wait_count(port):
    """Sockets on `port` in CLOSE_WAIT: the peer hung up but the proxy never
    closed its end (a leaked client)."""
    n = 0
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = open(f).read().splitlines()[1:]
        except OSError:
            continue
        for l in lines:
            parts = l.split()
            if int(parts[1].rsplit(":", 1)[1], 16) == port and parts[3] == "08":
                n += 1
    return n

