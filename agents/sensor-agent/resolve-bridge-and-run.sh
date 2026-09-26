#!/bin/sh
# Entrypoint wrapper: resolves this container's target Docker bridge
# network to its actual host bridge device name (br-<first 12 hex chars
# of the network's Docker-assigned Id>), makes sure that bridge is in
# promiscuous mode (the Docker-native SPAN/mirror-port equivalent — see
# demo/range/monitoring-agent/TAP-VALIDATION.md for why this is needed:
# a container attached normally to a bridge network only ever sees its
# own traffic, since a Docker bridge is a learning switch, not a hub),
# then execs the real sensor binary with that device as its capture
# interface.
#
# Needed because a compose project's bridge network ID (and therefore
# its br-<id> host device name) isn't known until the network is
# actually created — unlike the original single-subnet demo, which
# hardcoded a discovered br-ebd816471007, this wrapper lets the SAME
# image serve multiple, differently-named subnets (imaging_net,
# lab_net, ...) without a human re-discovering and hand-editing a
# bridge ID into a config file for each one.
#
# Requires: --network host (operates on the HOST's bridge devices,
# not a namespaced one), cap_add [NET_ADMIN, NET_RAW], and
# /var/run/docker.sock mounted read-only so this can ask the Docker
# API "what is this network's ID" without needing the full docker CLI
# or a docker-compose-specific project-name convention baked in.
set -eu

: "${TARGET_NETWORK:?TARGET_NETWORK env var must name the Docker network to tap (e.g. medsim-range_imaging_net)}"
: "${DOCKER_SOCK:=/var/run/docker.sock}"

network_id=$(curl -s --unix-socket "$DOCKER_SOCK" \
  "http://localhost/networks/${TARGET_NETWORK}" \
  | grep -o '"Id":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)

if [ -z "$network_id" ]; then
  echo "resolve-bridge-and-run: could not resolve network '${TARGET_NETWORK}' via ${DOCKER_SOCK} — is it mounted, and does the network exist yet?" >&2
  exit 1
fi

bridge_iface="br-$(printf '%s' "$network_id" | cut -c1-12)"

echo "resolve-bridge-and-run: TARGET_NETWORK=${TARGET_NETWORK} -> bridge=${bridge_iface}"

if ! ip link show "$bridge_iface" >/dev/null 2>&1; then
  echo "resolve-bridge-and-run: host bridge device '${bridge_iface}' not found — is this container really on --network host with that bridge already created?" >&2
  exit 1
fi

ip link set "$bridge_iface" promisc on

exec /usr/local/bin/medwatch-sensor "$@" --interface "$bridge_iface"
