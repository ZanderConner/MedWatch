FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      dcmtk \
      dnsutils \
      iproute2 \
      iptables \
      iputils-ping \
      jq \
      netcat-openbsd \
      procps \
      python3 \
      tcpdump \
      traceroute \
    && rm -rf /var/lib/apt/lists/*

COPY range-entrypoint.sh /usr/local/bin/range-entrypoint.sh
COPY route-default.sh /usr/local/bin/route-default.sh
COPY send-dicom-echo.sh /usr/local/bin/send-dicom-echo
COPY send-hl7-adt.sh /usr/local/bin/send-hl7-adt
COPY probe-range.sh /usr/local/bin/probe-range
RUN chmod +x \
      /usr/local/bin/range-entrypoint.sh \
      /usr/local/bin/route-default.sh \
      /usr/local/bin/send-dicom-echo \
      /usr/local/bin/send-hl7-adt \
      /usr/local/bin/probe-range

CMD ["/usr/local/bin/range-entrypoint.sh"]
