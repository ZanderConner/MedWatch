FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      conntrack \
      iproute2 \
      iptables \
      iputils-ping \
      netcat-openbsd \
      procps \
      tcpdump \
      traceroute \
    && rm -rf /var/lib/apt/lists/*

COPY start-router.sh /usr/local/bin/start-router.sh
RUN chmod +x /usr/local/bin/start-router.sh

CMD ["/usr/local/bin/start-router.sh"]
