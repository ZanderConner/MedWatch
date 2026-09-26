-- MedWatch backend schema.
-- SQLite via node:sqlite (built into Node 22.5+, no native deps).

-- One row per observed network event, exactly as the sensor agent sends
-- it. Raw telemetry, append-only (no upserts here — events are never
-- updated, only inserted).
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  sensor_id TEXT NOT NULL,
  observed_at TEXT NOT NULL,        -- the agent's "@timestamp", RFC3339 UTC
  src_ip TEXT NOT NULL,
  src_port INTEGER,
  src_mac TEXT,
  dst_ip TEXT NOT NULL,
  dst_port INTEGER,
  dst_mac TEXT,
  transport TEXT NOT NULL,          -- tcp | udp | icmp | other
  application TEXT NOT NULL,        -- dicom | hl7 | http | https | dns | dhcp | ssh | rdp | smb | unknown
  length_bytes INTEGER NOT NULL,
  protocol_metadata TEXT,           -- raw JSON string, or NULL
  received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events (observed_at);
CREATE INDEX IF NOT EXISTS idx_events_sensor_id ON events (sensor_id);
CREATE INDEX IF NOT EXISTS idx_events_application ON events (application);

-- One row per discovered asset, keyed by asset_id (MAC, else an
-- IP-derived id — decided by the agent, not us). Upserted on every
-- sighting: last_seen advances, ip_addresses/observed_ports/
-- observed_protocols are unioned (stored as JSON arrays), first_seen
-- never regresses, os_guess/device_identity_hint may be overwritten by
-- a fresher (non-worse) guess from the agent.
CREATE TABLE IF NOT EXISTS assets (
  asset_id TEXT PRIMARY KEY,
  sensor_id TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  mac_address TEXT,
  ip_addresses TEXT NOT NULL,       -- JSON array of strings
  vendor_oui TEXT,
  os_guess TEXT NOT NULL,           -- windows | linux | bsd | network-appliance | embedded-or-iot | unknown
  observed_ports TEXT NOT NULL,     -- JSON array of integers
  observed_protocols TEXT NOT NULL, -- JSON array of strings
  device_identity_hint TEXT,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets (last_seen);
CREATE INDEX IF NOT EXISTS idx_assets_os_guess ON assets (os_guess);

-- Correlation/alerting output (see backend/correlation). Kept separate
-- from events/assets so alerting logic can be re-run/backfilled without
-- touching raw telemetry.
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL,
  rule TEXT NOT NULL,               -- short machine-readable rule name
  severity TEXT NOT NULL,           -- info | warning | critical
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (asset_id) REFERENCES assets (asset_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_asset_id ON alerts (asset_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
