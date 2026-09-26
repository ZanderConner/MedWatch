// Aggregation queries backing the frontend's Analytics page: event
// volume over time, protocol/transport/OS distributions, and top
// talkers by source IP. All derived from events/assets — no new
// storage needed.
const { getDb } = require('../db/connection');

const VALID_INTERVALS = new Set(['hour', 'day']);

// Buckets observed_at (an RFC3339 UTC string like "2026-09-26T13:04:05Z")
// by truncating to the hour or day boundary. String truncation instead
// of strftime() because the agent's timestamps are already UTC and
// this avoids parsing edge cases with variable fractional-second
// precision.
function bucketExpr(interval) {
  return interval === 'day'
    ? "substr(observed_at, 1, 10) || 'T00:00:00Z'"
    : "substr(observed_at, 1, 13) || ':00:00Z'";
}

// GET data: event counts bucketed by hour or day, optionally filtered
// to a time range and/or a single application (dicom/hl7/etc).
function eventsTimeseries({ interval = 'hour', since, until, application } = {}, db = getDb()) {
  const bucket = VALID_INTERVALS.has(interval) ? interval : 'hour';
  const clauses = [];
  const params = [];
  if (since) {
    clauses.push('observed_at >= ?');
    params.push(since);
  }
  if (until) {
    clauses.push('observed_at <= ?');
    params.push(until);
  }
  if (application) {
    clauses.push('application = ?');
    params.push(application);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

  const rows = db
    .prepare(
      `SELECT ${bucketExpr(bucket)} AS bucket, COUNT(*) AS count
       FROM events ${where}
       GROUP BY bucket ORDER BY bucket ASC`
    )
    .all(...params);

  return { interval: bucket, buckets: rows };
}

// Event counts grouped by application (dicom/hl7/http/.../unknown).
function protocolDistribution(db = getDb()) {
  return db
    .prepare('SELECT application, COUNT(*) AS count FROM events GROUP BY application ORDER BY count DESC')
    .all();
}

// Event counts grouped by transport (tcp/udp/icmp/other).
function transportDistribution(db = getDb()) {
  return db
    .prepare('SELECT transport, COUNT(*) AS count FROM events GROUP BY transport ORDER BY count DESC')
    .all();
}

// Asset counts grouped by os_guess.
function osDistribution(db = getDb()) {
  return db
    .prepare('SELECT os_guess, COUNT(*) AS count FROM assets GROUP BY os_guess ORDER BY count DESC')
    .all();
}

// Busiest source IPs by event count, best-effort matched back to a
// known asset_id (an IP can be seen before/without a matching asset
// row, so asset_id may be null).
function topTalkers({ limit = 10 } = {}, db = getDb()) {
  const cappedLimit = Math.min(Number(limit) || 10, 100);
  return db
    .prepare(
      `SELECT
         e.src_ip AS ip,
         COUNT(*) AS event_count,
         (SELECT a.asset_id FROM assets a
          WHERE EXISTS (SELECT 1 FROM json_each(a.ip_addresses) WHERE value = e.src_ip)
          LIMIT 1) AS asset_id
       FROM events e
       GROUP BY e.src_ip
       ORDER BY event_count DESC
       LIMIT ?`
    )
    .all(cappedLimit);
}

module.exports = {
  eventsTimeseries,
  protocolDistribution,
  transportDistribution,
  osDistribution,
  topTalkers,
};
