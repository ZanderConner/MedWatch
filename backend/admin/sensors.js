// Backend logic for the sensor admin page (frontend consumes this via
// admin/routes.js). Layers human-friendly metadata (label, notes,
// retired flag) on top of the raw activity data api/sensors.js already
// derives — doesn't duplicate that derivation.
const { getDb } = require('../db/connection');
const { listSensors } = require('../api/sensors');

function getMetaMap(db = getDb()) {
  const rows = db.prepare('SELECT * FROM sensor_meta').all();
  return new Map(rows.map((r) => [r.sensor_id, r]));
}

// GET /api/v1/admin/sensors — every sensor with activity/counts (from
// api/sensors.js) merged with admin metadata (label/notes/retired).
function listSensorsAdmin(db = getDb()) {
  const sensors = listSensors(db);
  const metaMap = getMetaMap(db);

  return sensors.map((sensor) => {
    const meta = metaMap.get(sensor.sensor_id);
    return {
      ...sensor,
      label: meta?.label ?? null,
      notes: meta?.notes ?? null,
      retired: meta ? Boolean(meta.retired) : false,
      // A retired sensor is never "active" for admin purposes even if
      // it happens to still be shipping (e.g. decommission in progress).
      active: sensor.active && !(meta && meta.retired),
    };
  });
}

// GET /api/v1/admin/sensors/:sensor_id — full detail: activity summary,
// per-application event breakdown, recent alerts for this sensor's
// assets, and admin metadata.
function getSensorDetail(sensorId, db = getDb()) {
  const sensors = listSensorsAdmin(db);
  const summary = sensors.find((s) => s.sensor_id === sensorId);
  if (!summary) return null;

  const applicationBreakdown = db
    .prepare(
      `SELECT application, COUNT(*) AS count
       FROM events WHERE sensor_id = ?
       GROUP BY application ORDER BY count DESC`
    )
    .all(sensorId);

  const assetIds = db
    .prepare('SELECT asset_id FROM assets WHERE sensor_id = ?')
    .all(sensorId)
    .map((r) => r.asset_id);

  let recentAlerts = [];
  if (assetIds.length > 0) {
    const placeholders = assetIds.map(() => '?').join(',');
    recentAlerts = db
      .prepare(
        `SELECT * FROM alerts WHERE asset_id IN (${placeholders})
         ORDER BY created_at DESC LIMIT 20`
      )
      .all(...assetIds);
  }

  return {
    ...summary,
    application_breakdown: applicationBreakdown,
    recent_alerts: recentAlerts,
  };
}

// PATCH /api/v1/admin/sensors/:sensor_id — set label/notes/retired.
// Creates the sensor_meta row if it doesn't exist yet (lazy, since
// there's no registration flow: a sensor exists the moment it ships
// its first event/asset, see api/sensors.js).
function setSensorMeta(sensorId, { label, notes, retired }, db = getDb()) {
  const existing = db
    .prepare('SELECT * FROM sensor_meta WHERE sensor_id = ?')
    .get(sensorId);

  const next = {
    label: label !== undefined ? label : existing?.label ?? null,
    notes: notes !== undefined ? notes : existing?.notes ?? null,
    retired: retired !== undefined ? (retired ? 1 : 0) : existing?.retired ?? 0,
  };

  if (existing) {
    db.prepare(
      `UPDATE sensor_meta SET label = ?, notes = ?, retired = ?,
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
       WHERE sensor_id = ?`
    ).run(next.label, next.notes, next.retired, sensorId);
  } else {
    db.prepare(
      `INSERT INTO sensor_meta (sensor_id, label, notes, retired)
       VALUES (?, ?, ?, ?)`
    ).run(sensorId, next.label, next.notes, next.retired);
  }

  return { sensor_id: sensorId, ...next, retired: Boolean(next.retired) };
}

// DELETE /api/v1/admin/sensors/:sensor_id — permanently purge every
// event/asset/alert/meta row for this sensor_id. Destructive; the admin
// UI should confirm before calling this. Assets are matched by
// sensor_id (the sensor that discovered them), not by which sensor last
// updated them, so this only removes what THIS sensor contributed.
function purgeSensor(sensorId, db = getDb()) {
  const assetIds = db
    .prepare('SELECT asset_id FROM assets WHERE sensor_id = ?')
    .all(sensorId)
    .map((r) => r.asset_id);

  db.exec('BEGIN');
  try {
    const eventsDeleted = db
      .prepare('DELETE FROM events WHERE sensor_id = ?')
      .run(sensorId).changes;

    let alertsDeleted = 0;
    if (assetIds.length > 0) {
      const placeholders = assetIds.map(() => '?').join(',');
      alertsDeleted = db
        .prepare(`DELETE FROM alerts WHERE asset_id IN (${placeholders})`)
        .run(...assetIds).changes;
    }

    const assetsDeleted = db
      .prepare('DELETE FROM assets WHERE sensor_id = ?')
      .run(sensorId).changes;

    const metaDeleted = db
      .prepare('DELETE FROM sensor_meta WHERE sensor_id = ?')
      .run(sensorId).changes;

    db.exec('COMMIT');
    return { events_deleted: eventsDeleted, assets_deleted: assetsDeleted, alerts_deleted: alertsDeleted, meta_deleted: metaDeleted };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

module.exports = { listSensorsAdmin, getSensorDetail, setSensorMeta, purgeSensor };
