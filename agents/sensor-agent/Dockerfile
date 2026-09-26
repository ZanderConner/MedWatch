# Multi-stage build: compiles the MedWatch Rust sensor agent, then ships
# a minimal Debian runtime image with just libpcap + the stripped binary.
# Built for the range's monitoring-agent service (agents/sensor-agent).

# ---- build stage ----------------------------------------------------------
FROM rust:1.90-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy the whole workspace: the sensor-agent binary depends on the sibling
# fingerprinting/protocol-parsers path crates, so a partial COPY breaks the
# build. Layer caching still works because Docker hashes the copied tree,
# not individual crates — acceptable for a hackathon-scale workspace.
COPY Cargo.toml Cargo.lock ./
COPY agents ./agents

RUN cargo build --release -p medwatch-sensor-agent \
    && strip target/release/medwatch-sensor

# ---- runtime stage ----------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      iproute2 \
      libcap2-bin \
      libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin medwatch

COPY --from=build /src/target/release/medwatch-sensor /usr/local/bin/medwatch-sensor
COPY agents/sensor-agent/resolve-bridge-and-run.sh /usr/local/bin/resolve-bridge-and-run.sh
RUN chmod +x /usr/local/bin/resolve-bridge-and-run.sh

# CAP_NET_RAW + CAP_NET_ADMIN on the binary itself so the container can run
# as a non-root user and still open a capture handle (promiscuous mode /
# BPF filter installation needs NET_ADMIN, not just NET_RAW). The
# capabilities still must be in the container's bounding set — grant them
# via `cap_add: [NET_ADMIN, NET_RAW]` in docker-compose.
RUN setcap 'cap_net_raw,cap_net_admin=eip' /usr/local/bin/medwatch-sensor

# Bundle the generic template as a fallback default; real deployments
# should bind-mount an environment-specific config over this path instead
# of baking deployment config into the image.
COPY agents/sensor-agent/config/sensor-agent.toml /etc/medwatch/sensor-agent.toml

# Deliberately root, not `medwatch`: the entrypoint wrapper needs to run
# `ip link set <bridge> promisc on` on the HOST's network namespace
# (--network host) and query the Docker API over the mounted socket to
# resolve a bridge's name at container start, both of which need real
# root/CAP_NET_ADMIN, not just the binary's own setcap grant. The
# container already declares cap_add: [NET_ADMIN, NET_RAW] at the
# compose level for exactly this reason — running the wrapper as
# `medwatch` would need a second layer of setcap/sudo plumbing for no
# real security benefit in this already-privileged, `--network host`
# capture container.
ENTRYPOINT ["/usr/local/bin/resolve-bridge-and-run.sh"]
CMD ["--config", "/etc/medwatch/sensor-agent.toml"]
