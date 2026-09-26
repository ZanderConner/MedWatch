// Backend logic for the Asset Inventory admin page: list assets with
// their confirm/source state, manually add an asset (source='manual',
// confirmed=1 immediately — an admin typed it in, nothing to confirm),
// confirm/unconfirm an agent-discovered asset, and delete an asset
// entirely (manual entries only need a plain delete; agent-discovered
// ones can be deleted too, but will simply reappear on the next sighting
// since the agent doesn't know it was removed — same caveat as any
// other asset-inventory tool would have with an active discovery feed).
const { randomUUID } = require('node:crypto');
const { getDb } = require('../db/connection');

function rowToAsset(row) {
  return {
    asset_id: row.asset_id,
    sensor_id: row.sensor_id,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    mac_address: row.mac_address,
    ip_addresses: JSON.parse(row.ip_addresses),
    vendor_oui: row.vendor_oui,
    os_guess: row.os_guess,
    observed_ports: JSON.parse(row.observed_ports),
    observed_protocols: JSON.parse(row.observed_protocols),
    device_identity_hint: row.device_identity_hint,
    updated_at: row.updated_at,
    source: row.source,
    confirmed: Boolean(row.confirmed),
  };
}

// GET /api/v1/admin/assets?confirmed=true|false — same rows as the
// public /api/v1/assets read endpoint, plus source/confirmed, with an
// optional confirmed-state filter for the inventory page's two views
// ("Confirmed inventory" vs "Pending confirmation").
function listAssetsAdmin({ confirmed } = {}, db = getDb()) {
  const clauses = [];
  const params = [];
  if (confirmed !== undefined) {
    clauses.push('confirmed = ?');
    params.push(confirmed ? 1 : 0);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  return db
    .prepare(`SELECT * FROM assets ${where} ORDER BY last_seen DESC`)
    .all(...params)
    .map(rowToAsset);
}

// POST /api/v1/admin/assets — manually add an asset the agent hasn't
// (or can't) discover on its own. Always source='manual', confirmed=1
// (an admin typing it in has already vetted it by definition).
function createManualAsset(input, db = getDb()) {
  const assetId = input.asset_id?.trim() || `manual-${randomUUID()}`;
  const now = new Date().toISOString();

  const existing = db.prepare('SELECT asset_id FROM assets WHERE asset_id = ?').get(assetId);
  if (existing) {
    return { error: 'asset_id already exists' };
  }

  db.prepare(
    `INSERT INTO assets
      (asset_id, sensor_id, first_seen, last_seen, mac_address,
       ip_addresses, vendor_oui, os_guess, observed_ports,
       observed_protocols, device_identity_hint, updated_at, source, confirmed)
     VALUES (?, 'manual', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual', 1)`
  ).run(
    assetId,
    now,
    now,
    input.mac_address ?? null,
    JSON.stringify(input.ip_addresses ?? []),
    input.vendor_oui ?? null,
    input.os_guess ?? 'unknown',
    JSON.stringify(input.observed_ports ?? []),
    JSON.stringify(input.observed_protocols ?? []),
    input.device_identity_hint ?? null,
    now
  );

  return { asset: rowToAsset(db.prepare('SELECT * FROM assets WHERE asset_id = ?').get(assetId)) };
}

// PATCH /api/v1/admin/assets/:asset_id — confirm/unconfirm an
// agent-discovered asset, or edit its device_identity_hint (the one
// field an admin is likely to want to correct/add, e.g. naming an
// auto-discovered MAC "Infusion Pump #04").
function updateAsset(assetId, { confirmed, device_identity_hint }, db = getDb()) {
  const existing = db.prepare('SELECT * FROM assets WHERE asset_id = ?').get(assetId);
  if (!existing) return null;

  const next = {
    confirmed: confirmed !== undefined ? (confirmed ? 1 : 0) : existing.confirmed,
    device_identity_hint:
      device_identity_hint !== undefined ? device_identity_hint : existing.device_identity_hint,
  };

  db.prepare(
    `UPDATE assets SET confirmed = ?, device_identity_hint = ?,
       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE asset_id = ?`
  ).run(next.confirmed, next.device_identity_hint, assetId);

  return rowToAsset(db.prepare('SELECT * FROM assets WHERE asset_id = ?').get(assetId));
}

// DELETE /api/v1/admin/assets/:asset_id
function deleteAsset(assetId, db = getDb()) {
  const result = db.prepare('DELETE FROM assets WHERE asset_id = ?').run(assetId);
  return result.changes > 0;
}

module.exports = { listAssetsAdmin, createManualAsset, updateAsset, deleteAsset };
