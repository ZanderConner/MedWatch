// Aggregation queries backing the frontend's Analytics page: event
// volume over time, protocol/transport/OS distributions, and top
// talkers by source IP. All derived from events/assets — no new
// storage needed. Every query accepts an optional `sensor_id` filter
// so a multi-sensor deployment (see demo/docker-compose.yml's
// monitoring-agent-imaging / monitoring-agent-lab) can be analyzed
// per-subnet as well as in aggregate.
const { getDb } = require('../db/connection');
const { listSensors } = require('../api/sensors');

const VALID_INTERVALS = new Set(['minute', 'hour', 'day']);

// Buckets observed_at (an RFC3339 UTC string like "2026-09-26T13:04:05Z")
// by truncating to the minute, hour, or day boundary. String truncation
// instead of strftime() because the agent's timestamps are already UTC
// and this avoids parsing edge cases with variable fractional-second
// precision.
function bucketExpr(interval) {
  if (interval === 'day') return "substr(observed_at, 1, 10) || 'T00:00:00Z'";
  if (interval === 'minute') return "substr(observed_at, 1, 16) || ':00Z'";
  return "substr(observed_at, 1, 13) || ':00:00Z'";
}

function buildFilters({ since, until, application, sensor_id, alias = '' } = {}) {
  const prefix = alias ? `${alias}.` : '';
  const clauses = [];
  const params = [];
  if (since) {
    clauses.push(`${prefix}observed_at >= ?`);
    params.push(since);
  }
  if (until) {
    clauses.push(`${prefix}observed_at <= ?`);
    params.push(until);
  }
  if (application) {
    clauses.push(`${prefix}application = ?`);
    params.push(application);
  }
  if (sensor_id) {
    clauses.push(`${prefix}sensor_id = ?`);
    params.push(sensor_id);
  }
  return { where: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '', params };
}

// GET data: event counts bucketed by hour or day, optionally filtered
// to a time range, a single application (dicom/hl7/etc), and/or a
// single sensor_id.
function eventsTimeseries({ interval = 'hour', since, until, application, sensor_id } = {}, db = getDb()) {
  const bucket = VALID_INTERVALS.has(interval) ? interval : 'hour';
  const { where, params } = buildFilters({ since, until, application, sensor_id });

  const rows = db
    .prepare(
      `SELECT ${bucketExpr(bucket)} AS bucket, COUNT(*) AS count
       FROM events ${where}
       GROUP BY bucket ORDER BY bucket ASC`
    )
    .all(...params);

  return { interval: bucket, buckets: rows };
}

// Event counts grouped by application (dicom/hl7/http/.../unknown),
// optionally scoped to a time range and/or sensor_id.
function protocolDistribution({ since, until, sensor_id } = {}, db = getDb()) {
  const { where, params } = buildFilters({ since, until, sensor_id });
  return db
    .prepare(`SELECT application, COUNT(*) AS count FROM events ${where} GROUP BY application ORDER BY count DESC`)
    .all(...params);
}

// Event counts grouped by transport (tcp/udp/icmp/other), optionally
// scoped to a time range and/or sensor_id.
function transportDistribution({ since, until, sensor_id } = {}, db = getDb()) {
  const { where, params } = buildFilters({ since, until, sensor_id });
  return db
    .prepare(`SELECT transport, COUNT(*) AS count FROM events ${where} GROUP BY transport ORDER BY count DESC`)
    .all(...params);
}

// Asset counts grouped by os_guess, optionally scoped to a sensor_id
// (assets have no time-range-able "observed_at", so no since/until here).
function osDistribution({ sensor_id } = {}, db = getDb()) {
  const clauses = [];
  const params = [];
  if (sensor_id) {
    clauses.push('sensor_id = ?');
    params.push(sensor_id);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  return db
    .prepare(`SELECT os_guess, COUNT(*) AS count FROM assets ${where} GROUP BY os_guess ORDER BY count DESC`)
    .all(...params);
}

// Busiest source IPs by event count, best-effort matched back to a
// known asset_id (an IP can be seen before/without a matching asset
// row, so asset_id may be null). Optionally scoped to a time range
// and/or sensor_id.
function topTalkers({ limit = 10, since, until, sensor_id } = {}, db = getDb()) {
  const cappedLimit = Math.min(Number(limit) || 10, 100);
  const { where, params } = buildFilters({ since, until, sensor_id, alias: 'e' });
  return db
    .prepare(
      `SELECT
         e.src_ip AS ip,
         COUNT(*) AS event_count,
         (SELECT a.asset_id FROM assets a
          WHERE EXISTS (SELECT 1 FROM json_each(a.ip_addresses) WHERE value = e.src_ip)
          LIMIT 1) AS asset_id
       FROM events e
       ${where}
       GROUP BY e.src_ip
       ORDER BY event_count DESC
       LIMIT ?`
    )
    .all(...params, cappedLimit);
}

// System/fleet health summary for a dashboard "system status" panel:
// backend process uptime, per-sensor liveness (reusing api/sensors.js's
// active-window logic), and headline counts. Deliberately NOT scoped
// by sensor_id/time-range like the other analytics queries — this is a
// single always-current snapshot, not something you'd want to look
// back in time on.
const processStartedAt = new Date().toISOString();
function systemHealth(db = getDb()) {
  const sensors = listSensors(db);
  const totals = db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM events) AS total_events,
         (SELECT COUNT(*) FROM assets) AS total_assets,
         (SELECT COUNT(*) FROM assets WHERE confirmed = 1) AS confirmed_assets,
         (SELECT COUNT(*) FROM alerts) AS open_alerts`
    )
    .get();

  return {
    backend_started_at: processStartedAt,
    backend_uptime_seconds: Math.round(process.uptime()),
    sensors_total: sensors.length,
    sensors_active: sensors.filter((s) => s.active).length,
    sensors: sensors.map((s) => ({
      sensor_id: s.sensor_id,
      active: s.active,
      last_seen: s.last_seen,
    })),
    ...totals,
  };
}

module.exports = {
  eventsTimeseries,
  protocolDistribution,
  transportDistribution,
  osDistribution,
  topTalkers,
  systemHealth,
};
