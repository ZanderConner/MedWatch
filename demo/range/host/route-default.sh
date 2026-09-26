#!/usr/bin/env bash
set -euo pipefail

: "${RANGE_GATEWAY:?RANGE_GATEWAY must be set}"
refresh_seconds="${ROUTE_REFRESH_SECONDS:-15}"

while true; do
  ip route replace default via "$RANGE_GATEWAY"
  sleep "$refresh_seconds"
done
