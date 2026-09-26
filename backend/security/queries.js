// Security page logic: alert severity breakdown and "flagged assets"
// (assets that have at least one correlation alert, with their alerts
// attached — the frontend's security page needs the asset context, not
// just a bare asset_id string like GET /api/v1/alerts returns).
const { getDb } = require('../db/connection');

function parseJsonArrayColumn(value) {
  try {
    return JSON.parse(value);
  } catch {
    return [];
  }
}

function rowToAsset(row) {
  return {
    asset_id: row.asset_id,
    sensor_id: row.sensor_id,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    mac_address: row.mac_address,
    ip_addresses: parseJsonArrayColumn(row.ip_addresses),
    vendor_oui: row.vendor_oui,
    os_guess: row.os_guess,
    observed_ports: parseJsonArrayColumn(row.observed_ports),
    observed_protocols: parseJsonArrayColumn(row.observed_protocols),
    device_identity_hint: row.device_identity_hint,
  };
}

// GET data: alert counts grouped by severity (info/warning/critical).
function severityBreakdown(db = getDb()) {
  return db
    .prepare('SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity ORDER BY count DESC')
    .all();
}

// GET data: every asset with >=1 alert, each with its own alerts
// attached (most recent first), ordered by most recently alerted.
function flaggedAssets(db = getDb()) {
  const assetRows = db
    .prepare(
      `SELECT a.* FROM assets a
       WHERE EXISTS (SELECT 1 FROM alerts al WHERE al.asset_id = a.asset_id)
       ORDER BY a.last_seen DESC`
    )
    .all();

  return assetRows.map((row) => {
    const alerts = db
      .prepare('SELECT * FROM alerts WHERE asset_id = ? ORDER BY created_at DESC')
      .all(row.asset_id);
    return { ...rowToAsset(row), alerts };
  });
}

module.exports = { severityBreakdown, flaggedAssets };
