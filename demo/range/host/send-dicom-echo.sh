#!/usr/bin/env bash
set -euo pipefail

host="${1:-10.20.30.10}"
port="${2:-4242}"
called_aet="${3:-ORTHANC}"
calling_aet="${4:-MEDSIM}"

echoscu -v -aec "$called_aet" -aet "$calling_aet" "$host" "$port"
