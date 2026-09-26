-- Admin metadata for sensors: human-friendly labels/notes and a
-- "retired" flag for decommissioning a sensor in the admin UI without
-- deleting its historical data. The sensor agent has no registration
-- flow (see backend/README.md) — a sensor_meta row is created lazily
-- the first time an admin labels/retires a sensor, not on first sighting.
CREATE TABLE IF NOT EXISTS sensor_meta (
  sensor_id TEXT PRIMARY KEY,
  label TEXT,
  notes TEXT,
  retired INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
