// Sensor/agent activity stats derived from events + assets (the sensor
// agent has no separate heartbeat endpoint, so "active" is inferred from
// recent activity — see ACTIVE_WINDOW_MS below).
const { getDb } = require('../db/connection');

// A sensor counts as "active" if it has shipped an event OR an asset
// sighting within this window. 5 minutes = generous multiple of both
// flush intervals (events every ~5s, asset upserts every ~60s), so a
// healthy sensor stays "active" between flushes without flapping.
const ACTIVE_WINDOW_MS = 5 * 60 * 1000;

function listSensors(db = getDb()) {
  const now = Date.now();
  const cutoff = new Date(now - ACTIVE_WINDOW_MS).toISOString();

  // Union of every sensor_id ever seen in either table, with per-sensor
  // counts and last-activity timestamps pulled from both.
  const rows = db
    .prepare(
      `SELECT
         sensor_id,
         MAX(last_event_at) AS last_event_at,
         MAX(last_asset_at) AS last_asset_at,
         SUM(event_count) AS event_count,
         SUM(asset_count) AS asset_count
       FROM (
         SELECT sensor_id, MAX(observed_at) AS last_event_at, NULL AS last_asset_at,
                COUNT(*) AS event_count, 0 AS asset_count
         FROM events GROUP BY sensor_id
         UNION ALL
         SELECT sensor_id, NULL AS last_event_at, MAX(last_seen) AS last_asset_at,
                0 AS event_count, COUNT(*) AS asset_count
         FROM assets GROUP BY sensor_id
       )
       GROUP BY sensor_id`
    )
    .all();

  return rows.map((row) => {
    const lastSeen = [row.last_event_at, row.last_asset_at].filter(Boolean).sort().pop() || null;
    return {
      sensor_id: row.sensor_id,
      last_seen: lastSeen,
      event_count: row.event_count,
      asset_count: row.asset_count,
      active: lastSeen ? lastSeen >= cutoff : false,
    };
  });
}

function getStats(db = getDb()) {
  const sensors = listSensors(db);
  const totals = db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM events) AS total_events,
         (SELECT COUNT(*) FROM assets) AS total_assets,
         (SELECT COUNT(*) FROM alerts) AS total_alerts`
    )
    .get();

  return {
    sensors_total: sensors.length,
    sensors_active: sensors.filter((s) => s.active).length,
    active_window_seconds: ACTIVE_WINDOW_MS / 1000,
    ...totals,
    sensors,
  };
}

module.exports = { listSensors, getStats, ACTIVE_WINDOW_MS };
