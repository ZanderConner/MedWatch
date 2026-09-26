// Security page logic: alert severity breakdown and "flagged assets"
// (assets that have at least one correlation alert, with their alerts
// attached — the frontend's security page needs the asset context, not
// just a bare asset_id string like GET /api/v1/alerts returns).
const { getDb } = require('../db/connection');

const VALID_INTERVALS = new Set(['minute', 'hour', 'day']);

// Buckets created_at (an RFC3339 UTC string like "2026-09-26T13:04:05Z")
// by truncating to the minute, hour, or day boundary — same
// string-truncation approach as analytics/queries.js's bucketExpr,
// since alerts.created_at is written with the same strftime format as
// events.observed_at.
function bucketExpr(interval) {
  if (interval === 'day') return "substr(created_at, 1, 10) || 'T00:00:00Z'";
  if (interval === 'minute') return "substr(created_at, 1, 16) || ':00Z'";
  return "substr(created_at, 1, 13) || ':00:00Z'";
}

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

const STEP_MS = { minute: 60_000, hour: 3_600_000, day: 86_400_000 };

// GET data: alert (policy violation) counts bucketed by minute/hour/
// day, optionally scoped to a time range. Same underlying shape as
// analytics/queries.js's eventsTimeseries, but with two differences:
//
// 1. Alert bursts are genuinely instantaneous (a whole attack's worth
//    of alerts land in the same single bucket), so the raw SQL
//    grouping often returns exactly one row — which a line chart can
//    only ever draw as a lone dot, no matter how it's styled. To
//    render a burst as an actual spike (rise then fall back to zero)
//    instead of an isolated point, a zero-count bucket is anchored
//    immediately before the real data's start.
//
// 2. The trailing anchor is pinned to *now* (floored to the bucket
//    boundary), not to "last alert + 1 bucket". Without this, once a
//    burst passes and nothing new fires, every field in the response
//    stays byte-for-byte identical forever — the chart looks frozen/
//    dead even though the frontend is still polling every 3s, because
//    there's nothing telling it time has moved on. Pinning the last
//    point to now means the x-axis keeps advancing on every poll (the
//    line recedes into the past) even with zero new violations, which
//    is what actually reads as "live" instead of "stuck".
//
// This never invents non-zero data or changes any real count — it
// only adds two zero-count boundary points around the actual data.
// Reads from the append-only alert_events history (see
// 005_alert_history.sql), NOT the live `alerts` table — `alerts` rows
// are deleted the moment an asset is confirmed or a rule stops
// matching (see correlation/rules.js's runCorrelation), so a short
// attack burst that gets cleared before the next chart fetch would
// otherwise vanish from the graph entirely.
function violationsTimeseries({ interval = 'hour', since, until } = {}, db = getDb()) {
  const bucket = VALID_INTERVALS.has(interval) ? interval : 'hour';
  const clauses = [];
  const params = [];
  if (since) {
    clauses.push('created_at >= ?');
    params.push(since);
  }
  if (until) {
    clauses.push('created_at <= ?');
    params.push(until);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

  const rows = db
    .prepare(
      `SELECT ${bucketExpr(bucket)} AS bucket, COUNT(*) AS count
       FROM alert_events ${where}
       GROUP BY bucket ORDER BY bucket ASC`
    )
    .all(...params);

  const step = STEP_MS[bucket];
  const nowBucket = new Date(Math.floor(Date.now() / step) * step).toISOString().replace(/\.\d+Z$/, 'Z');

  if (rows.length > 0) {
    const before = new Date(new Date(rows[0].bucket).getTime() - step).toISOString().replace(/\.\d+Z$/, 'Z');
    rows.unshift({ bucket: before, count: 0 });
    // Only append a trailing "now" anchor if it's actually later than
    // the last real bucket — otherwise (a violation just landed in the
    // current bucket) it would duplicate/precede the real point.
    if (nowBucket > rows.at(-1).bucket) {
      rows.push({ bucket: nowBucket, count: 0 });
    }
  }

  return { interval: bucket, buckets: rows };
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

module.exports = { severityBreakdown, violationsTimeseries, flaggedAssets };
