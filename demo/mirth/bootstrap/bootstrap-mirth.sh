#!/bin/sh
# Bootstraps Mirth Connect for the medSim range: waits for the API, then
# imports and deploys every channel XML under ./channels so a fresh
# `docker compose up` produces a fully wired HL7 pipeline with no manual
# steps in the Mirth Administrator UI.
set -eu

base="${MIRTH_BASE_URL:-https://mirth:8443}"
user="${MIRTH_USER:-admin}"
pass="${MIRTH_PASSWORD:-admin}"
channels_dir="${MIRTH_CHANNELS_DIR:-/bootstrap/channels}"

curl_api() {
  # Mirth's REST API requires this header on every call or it 400s.
  curl -k -sS -u "$user:$pass" -H 'X-Requested-With: bootstrap-mirth' "$@"
}

echo "Waiting for Mirth API at $base ..."
i=0
until curl_api -fsS "$base/api/server/version" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 90 ]; then
    echo "Mirth API did not become reachable after 180s; aborting bootstrap." >&2
    exit 1
  fi
  sleep 2
done
echo "Mirth API is reachable ($(curl_api -fsS "$base/api/server/version" 2>/dev/null))."

if [ ! -d "$channels_dir" ] || [ -z "$(ls -A "$channels_dir" 2>/dev/null)" ]; then
  echo "No channel XML files found under $channels_dir; nothing to import." >&2
  exit 0
fi

status=0
for channel_xml in "$channels_dir"/*.xml; do
  [ -f "$channel_xml" ] || continue

  channel_id=$(sed -n 's:.*<id>\(.*\)</id>.*:\1:p' "$channel_xml" | head -n1)
  channel_name=$(sed -n 's:.*<name>\(.*\)</name>.*:\1:p' "$channel_xml" | head -n1)

  if [ -z "$channel_id" ]; then
    echo "Skipping $channel_xml: could not find <id> element." >&2
    status=1
    continue
  fi

  echo "== $channel_name ($channel_id) =="

  # Remove any previous deployment of this channel ID so re-running
  # bootstrap (e.g. after editing a channel XML) is idempotent.
  curl_api -o /dev/null -X DELETE "$base/api/channels/$channel_id" || true

  import_code=$(curl_api -o /tmp/import-response.txt -w '%{http_code}' \
    -X POST "$base/api/channels" \
    -H 'Content-Type: application/xml' \
    --data-binary "@$channel_xml")

  if [ "$import_code" != "200" ]; then
    echo "  IMPORT FAILED (HTTP $import_code): $(cat /tmp/import-response.txt)" >&2
    status=1
    continue
  fi

  if curl_api -fsS "$base/api/channels/$channel_id" | grep -q 'This channel is invalid'; then
    echo "  IMPORT SUCCEEDED but channel is marked invalid by Mirth — check connector properties in $channel_xml." >&2
    status=1
    continue
  fi

  deploy_code=$(curl_api -o /dev/null -w '%{http_code}' \
    -X POST "$base/api/channels/$channel_id/_deploy")

  if [ "$deploy_code" != "204" ]; then
    echo "  DEPLOY FAILED (HTTP $deploy_code)" >&2
    status=1
    continue
  fi

  echo "  imported and deployed."
done

echo "Mirth bootstrap complete."
exit "$status"
