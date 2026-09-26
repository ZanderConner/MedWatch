// Read API for the frontend: list/filter assets, list/filter events,
// asset detail (asset + its recent events). No auth on these routes for
// the hackathon demo (adjust if the frontend needs auth — flag it back
// to the team rather than assuming a scheme).
const express = require('express');
const { getDb } = require('../db/connection');
const { listSensors, getStats } = require('./sensors');

const router = express.Router();

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
    updated_at: row.updated_at,
  };
}

function rowToEvent(row) {
  return {
    event_id: row.event_id,
    sensor_id: row.sensor_id,
    '@timestamp': row.observed_at,
    src_ip: row.src_ip,
    src_port: row.src_port,
    src_mac: row.src_mac,
    dst_ip: row.dst_ip,
    dst_port: row.dst_port,
    dst_mac: row.dst_mac,
    transport: row.transport,
    application: row.application,
    length_bytes: row.length_bytes,
    protocol_metadata: row.protocol_metadata ? JSON.parse(row.protocol_metadata) : null,
  };
}

function clampLimit(raw, fallback, max) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(n, max);
}

// GET /api/v1/assets?os_guess=linux&protocol=dicom&limit=100&offset=0
router.get('/assets', (req, res) => {
  const db = getDb();
  const limit = clampLimit(req.query.limit, 100, 1000);
  const offset = Number(req.query.offset) || 0;

  const clauses = [];
  const params = [];
  if (req.query.os_guess) {
    clauses.push('os_guess = ?');
    params.push(req.query.os_guess);
  }
  if (req.query.protocol) {
    // observed_protocols is a JSON array column; json_each unnests it
    // so the filter runs in SQL (before LIMIT/OFFSET), not after.
    clauses.push('EXISTS (SELECT 1 FROM json_each(observed_protocols) WHERE value = ?)');
    params.push(req.query.protocol);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

  const rows = db
    .prepare(`SELECT * FROM assets ${where} ORDER BY last_seen DESC LIMIT ? OFFSET ?`)
    .all(...params, limit, offset)
    .map(rowToAsset);

  res.json({ assets: rows, limit, offset });
});

// GET /api/v1/assets/:asset_id — one asset plus its recent events.
router.get('/assets/:asset_id', (req, res) => {
  const db = getDb();
  const asset = db
    .prepare('SELECT * FROM assets WHERE asset_id = ?')
    .get(req.params.asset_id);

  if (!asset) {
    return res.status(404).json({ error: 'asset not found' });
  }

  const events = db
    .prepare(
      `SELECT * FROM events
       WHERE src_ip IN (SELECT value FROM json_each(?))
          OR dst_ip IN (SELECT value FROM json_each(?))
          OR src_mac = ? OR dst_mac = ?
       ORDER BY observed_at DESC LIMIT 50`
    )
    .all(asset.ip_addresses, asset.ip_addresses, asset.mac_address, asset.mac_address)
    .map(rowToEvent);

  res.json({ asset: rowToAsset(asset), recent_events: events });
});

// GET /api/v1/events?sensor_id=...&application=dicom&since=...&until=...&limit=100&offset=0
router.get('/events', (req, res) => {
  const db = getDb();
  const limit = clampLimit(req.query.limit, 100, 1000);
  const offset = Number(req.query.offset) || 0;

  const clauses = [];
  const params = [];

  if (req.query.sensor_id) {
    clauses.push('sensor_id = ?');
    params.push(req.query.sensor_id);
  }
  if (req.query.application) {
    clauses.push('application = ?');
    params.push(req.query.application);
  }
  if (req.query.since) {
    clauses.push('observed_at >= ?');
    params.push(req.query.since);
  }
  if (req.query.until) {
    clauses.push('observed_at <= ?');
    params.push(req.query.until);
  }

  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = db
    .prepare(
      `SELECT * FROM events ${where} ORDER BY observed_at DESC LIMIT ? OFFSET ?`
    )
    .all(...params, limit, offset)
    .map(rowToEvent);

  res.json({ events: rows, limit, offset });
});

// GET /api/v1/sensors — every sensor_id ever seen, with per-sensor
// event/asset counts, last-activity timestamp, and an "active" flag
// (active = shipped something within the last 5 minutes).
router.get('/sensors', (_req, res) => {
  res.json({ sensors: listSensors() });
});

// GET /api/v1/stats — overall counts for a dashboard: total
// events/assets/alerts, how many sensors are known vs currently active.
router.get('/stats', (_req, res) => {
  res.json(getStats());
});

module.exports = router;
