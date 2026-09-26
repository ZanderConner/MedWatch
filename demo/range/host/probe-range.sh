#!/usr/bin/env bash
set -euo pipefail

targets=(
  "openemr-http 10.20.10.10 80"
  "mirth-admin 10.20.20.10 8443"
  "orthanc-http 10.20.30.10 8042"
  "orthanc-dicom 10.20.30.10 4242"
)

for target in "${targets[@]}"; do
  read -r name host port <<< "$target"
  printf '%-16s ' "$name"
  if nc -zvw2 "$host" "$port" >/dev/null 2>&1; then
    echo "reachable at $host:$port"
  else
    echo "blocked or down at $host:$port"
  fi
done
