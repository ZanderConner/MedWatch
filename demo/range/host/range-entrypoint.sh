#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${RANGE_GATEWAY:-}" ]]; then
  ip route replace default via "$RANGE_GATEWAY"
fi

echo "host ${HOSTNAME} ready role=${LAB_ROLE:-generic}"
ip -brief address
ip route

trap 'exit 0' TERM INT
while true; do
  sleep 3600 &
  wait $!
done
