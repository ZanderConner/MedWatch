// Asset upsert-merge logic. Called once per AssetRecord in a POST
// /api/v1/assets batch. Key by asset_id. On repeat sighting:
//   - last_seen advances to the max of existing/incoming
//   - first_seen keeps the min of existing/incoming (never regresses)
//   - ip_addresses / observed_ports / observed_protocols are unioned,
//     not overwritten (the agent may see a subset of a device's full
//     port/protocol set on any given ~60s flush)
//   - os_guess / device_identity_hint / vendor_oui / mac_address take
//     the incoming value if it's non-null/non-"unknown", else keep the
//     existing value (the agent's classification can only improve with
//     more traffic, never intentionally regress, but we don't trust
//     that promise blindly — "unknown" never overwrites a real guess).
const { getDb } = require('../db/connection');

function unionArrays(existingJson, incoming) {
  const existing = existingJson ? JSON.parse(existingJson) : [];
  const merged = new Set([...existing, ...incoming]);
  return JSON.stringify([...merged]);
}

function preferNonUnknown(existing, incoming, unknownValue) {
  if (incoming === null || incoming === undefined) return existing;
  if (unknownValue !== undefined && incoming === unknownValue && existing) {
    return existing;
  }
  return incoming;
}

function upsertAsset(asset, db = getDb()) {
  const existing = db
    .prepare('SELECT * FROM assets WHERE asset_id = ?')
    .get(asset.asset_id);

  const incomingLastSeen = asset['@timestamp'];
  const incomingFirstSeen = asset.first_seen;

  if (!existing) {
    db.prepare(
      `INSERT INTO assets
        (asset_id, sensor_id, first_seen, last_seen, mac_address,
         ip_addresses, vendor_oui, os_guess, observed_ports,
         observed_protocols, device_identity_hint, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`
    ).run(
      asset.asset_id,
      asset.sensor_id,
      incomingFirstSeen,
      incomingLastSeen,
      asset.mac_address ?? null,
      JSON.stringify(asset.ip_addresses ?? []),
      asset.vendor_oui ?? null,
      asset.os_guess,
      JSON.stringify(asset.observed_ports ?? []),
      JSON.stringify(asset.observed_protocols ?? []),
      asset.device_identity_hint ?? null
    );
    return { asset_id: asset.asset_id, created: true };
  }

  const lastSeen =
    incomingLastSeen > existing.last_seen ? incomingLastSeen : existing.last_seen;
  const firstSeen =
    incomingFirstSeen < existing.first_seen ? incomingFirstSeen : existing.first_seen;

  const macAddress = preferNonUnknown(existing.mac_address, asset.mac_address ?? null);
  const vendorOui = preferNonUnknown(existing.vendor_oui, asset.vendor_oui ?? null);
  const osGuess = preferNonUnknown(existing.os_guess, asset.os_guess, 'unknown');
  const identityHint = preferNonUnknown(
    existing.device_identity_hint,
    asset.device_identity_hint ?? null
  );

  const ipAddresses = unionArrays(existing.ip_addresses, asset.ip_addresses ?? []);
  const observedPorts = unionArrays(existing.observed_ports, asset.observed_ports ?? []);
  const observedProtocols = unionArrays(
    existing.observed_protocols,
    asset.observed_protocols ?? []
  );

  db.prepare(
    `UPDATE assets SET
       sensor_id = ?, first_seen = ?, last_seen = ?, mac_address = ?,
       ip_addresses = ?, vendor_oui = ?, os_guess = ?, observed_ports = ?,
       observed_protocols = ?, device_identity_hint = ?,
       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE asset_id = ?`
  ).run(
    asset.sensor_id,
    firstSeen,
    lastSeen,
    macAddress,
    ipAddresses,
    vendorOui,
    osGuess,
    observedPorts,
    observedProtocols,
    identityHint,
    asset.asset_id
  );

  return { asset_id: asset.asset_id, created: false };
}

function upsertAssets(assets, db = getDb()) {
  const results = [];
  db.exec('BEGIN');
  try {
    for (const asset of assets) {
      results.push(upsertAsset(asset, db));
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return results;
}

module.exports = { upsertAsset, upsertAssets };
