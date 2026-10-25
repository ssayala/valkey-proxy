FROM debian:12 AS build

# e.g. --build-arg MAKE_FLAGS=USE_IOURING=1  (io_uring I/O, Linux >= 6.1 hosts)
ARG MAKE_FLAGS=""

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev liburing-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
COPY src ./src
COPY Makefile .
RUN make ${MAKE_FLAGS}

FROM debian:12
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 liburing2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/valkey-proxy /usr/local/bin/valkey-proxy
COPY proxy.conf /etc/valkey-proxy/proxy.conf
RUN useradd --system --uid 10001 valkey-proxy
USER 10001

# The config path is the only argument: mount your own (e.g. a Kubernetes
# ConfigMap) and pass its path as the container args.
ENTRYPOINT ["valkey-proxy"]
CMD ["/etc/valkey-proxy/proxy.conf"]
