# Running valkey-proxy as a Kubernetes sidecar

Run the proxy as a container **inside each application pod**. Containers in a
pod share the network namespace and can share volumes, so the application
reaches the proxy over a Unix socket (or `localhost`) and the only network hop
left is proxy → cluster. On a single host, a Unix socket client measured about
+8 µs p50 over going straight to Valkey, versus about +15 µs over loopback TCP.

## Pod spec

Native sidecars (Kubernetes 1.29+: an init container with
`restartPolicy: Always`) start before the application containers and are
stopped after them, so the proxy is up before the app connects and still
serving while the app shuts down.

```yaml
spec:
  terminationGracePeriodSeconds: 30
  volumes:
    - name: proxy-sock
      emptyDir: {}
    - name: proxy-conf
      configMap: { name: valkey-proxy-conf }
    - name: valkey-tls                      # only with tls-backend
      secret: { secretName: valkey-client-tls }
  initContainers:
    - name: valkey-proxy
      image: your-registry/valkey-proxy:<tag>
      restartPolicy: Always                 # native sidecar
      args: ["/etc/valkey-proxy/proxy.conf"]
      volumeMounts:
        - { name: proxy-sock, mountPath: /var/run/valkey }
        - { name: proxy-conf, mountPath: /etc/valkey-proxy }
        - { name: valkey-tls, mountPath: /etc/valkey-tls }
      startupProbe:
        tcpSocket: { port: 7777 }
        periodSeconds: 1
        failureThreshold: 30
      livenessProbe:
        tcpSocket: { port: 7777 }
      resources:
        requests: { cpu: 250m, memory: 64Mi }
  containers:
    - name: app
      env:
        - { name: VALKEY_SOCKET, value: /var/run/valkey/proxy.sock }
      volumeMounts:
        - { name: proxy-sock, mountPath: /var/run/valkey }
```

`proxy.conf` (ConfigMap `valkey-proxy-conf`):

```
server-ip   valkey-cluster.valkey.svc.cluster.local   # hostname or IP
server-port 6379
bind        127.0.0.1             # reachable from inside the pod only
port        7777
unix-socket /var/run/valkey/proxy.sock
unix-socket-perm 660              # app container must share the group (fsGroup)
worker-thread-no 1
cluster_refresh_interval_ms 5000  # Valkey pods come back on new IPs
min_normal_connection   0         # warm lazily: N pods x nodes adds up
min_blocking_connection 0
shutdown-timeout 10               # keep below terminationGracePeriodSeconds
# tls-backend yes
# tls-backend-ca-cert /etc/valkey-tls/ca.crt
```

## Notes

- **Addresses.** `server-ip` and `bind` accept hostnames and IPv6. Nodes
  announcing hostnames (`cluster-announce-hostname`,
  `cluster-preferred-endpoint-type hostname`) work too, including `MOVED`/`ASK`
  replies that name a hostname. Node addresses are resolved by the topology
  refresh, never on the request path.
- **Shutdown.** On SIGTERM the proxy stops accepting, lets every client finish
  what's in flight (a blocked `BLPOP` gets its reply), closes subscribers so
  they reconnect elsewhere, and exits once no clients remain, after
  `shutdown-timeout`, or on a second signal. As a native sidecar it gets
  SIGTERM after the app containers have exited, so normally there is nothing
  left to drain.
- **Unix socket.** The image runs as UID 10001. With `unix-socket-perm 660`,
  give the pod an `fsGroup` the app also runs with, or use `666` (the socket
  is only reachable from inside the pod's `emptyDir`). Socket paths are
  limited to 107 bytes. The socket is always plaintext; use `tls-enabled`
  only for TCP clients.
- **Probes.** `PING` is answered by the proxy itself, so it shows the proxy is
  up, not that the cluster is reachable. A keyed command (e.g.
  `GET healthcheck`) exercises the backend path; `tcpSocket` is enough for
  liveness.
- **Backend connection count.** Each proxy opens roughly one or two shared
  connections per Valkey node per worker, plus pool connections for blocking,
  pub/sub and ACL traffic as needed. With the `min_*_connection 0` settings
  above, 100 pods against a cluster mean on the order of 100-200 connections
  per Valkey node.
- **Sizing.** Without client pipelining the proxy uses roughly 4-9 µs of CPU
  per request (similar to what a Valkey node spends), with pipelining well
  under 1 µs. One worker thread covers most sidecars.
- **io_uring images** (`--build-arg MAKE_FLAGS=USE_IOURING=1`): container
  runtimes' default seccomp profiles commonly block io_uring; the proxy then
  logs `io_uring unavailable (Operation not permitted), using epoll` and keeps
  working. The gain is small (about 10% less CPU per request), so the default
  image without it is a fine choice.
