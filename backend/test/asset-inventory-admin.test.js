// Asset Inventory admin surface: manual add, confirm/unconfirm
// agent-discovered assets, delete, and the confirmed-state filter.
const test = require('node:test');
const assert = require('node:assert/strict');

process.env.MEDWATCH_DB_PATH = ':memory:';
process.env.MEDWATCH_API_KEY = 'test-key';

const { migrate } = require('../db/migrate');
const { getDb } = require('../db/connection');
const { upsertAsset } = require('../asset-inventory/upsert');
const {
  listAssetsAdmin,
  createManualAsset,
  updateAsset,
  deleteAsset,
} = require('../admin/assets');

function agentSeenAsset(overrides = {}) {
  return {
    asset_id: 'aa:bb:cc:dd:ee:ff',
    sensor_id: 'sensor-1',
    '@timestamp': '2026-01-01T00:00:00.000Z',
    first_seen: '2026-01-01T00:00:00.000Z',
    mac_address: 'aa:bb:cc:dd:ee:ff',
    ip_addresses: ['10.0.0.5'],
    os_guess: 'linux',
    observed_ports: [443],
    observed_protocols: ['https'],
    device_identity_hint: null,
    ...overrides,
  };
}

test('asset inventory: manual add, confirm/unconfirm, delete', () => {
  migrate(getDb());
  const db = getDb();

  // Agent-discovered asset starts unconfirmed.
  upsertAsset(agentSeenAsset(), db);
  let assets = listAssetsAdmin({}, db);
  assert.equal(assets.length, 1);
  assert.equal(assets[0].source, 'agent');
  assert.equal(assets[0].confirmed, false);

  // Pending-confirmation filter finds it, confirmed filter doesn't.
  assert.equal(listAssetsAdmin({ confirmed: false }, db).length, 1);
  assert.equal(listAssetsAdmin({ confirmed: true }, db).length, 0);

  // Confirm it.
  const confirmed = updateAsset('aa:bb:cc:dd:ee:ff', { confirmed: true }, db);
  assert.equal(confirmed.confirmed, true);
  assert.equal(listAssetsAdmin({ confirmed: true }, db).length, 1);
  assert.equal(listAssetsAdmin({ confirmed: false }, db).length, 0);

  // Re-sighting by the agent (another upsert) must not silently
  // unconfirm an asset an admin already vetted.
  upsertAsset(agentSeenAsset({ ip_addresses: ['10.0.0.5', '10.0.0.6'] }), db);
  const stillConfirmed = listAssetsAdmin({}, db)[0];
  assert.equal(stillConfirmed.confirmed, true);
  assert.deepEqual(stillConfirmed.ip_addresses.sort(), ['10.0.0.5', '10.0.0.6']);

  // Manual add is created already-confirmed with source='manual'.
  const manual = createManualAsset({
    device_identity_hint: 'Infusion Pump (manually entered)',
    ip_addresses: ['10.0.0.99'],
    os_guess: 'embedded-or-iot',
  }, db);
  assert.ok(manual.asset);
  assert.equal(manual.asset.source, 'manual');
  assert.equal(manual.asset.confirmed, true);
  assert.equal(manual.asset.device_identity_hint, 'Infusion Pump (manually entered)');

  assert.equal(listAssetsAdmin({}, db).length, 2);

  // Delete removes it.
  assert.equal(deleteAsset(manual.asset.asset_id, db), true);
  assert.equal(listAssetsAdmin({}, db).length, 1);
  assert.equal(deleteAsset('nonexistent', db), false);
});

test('asset inventory: relabeling via PATCH device_identity_hint', () => {
  migrate(getDb());
  const db = getDb();
  upsertAsset(agentSeenAsset({ asset_id: '11:22:33:44:55:66' }), db);

  const updated = updateAsset('11:22:33:44:55:66', { device_identity_hint: 'CT Scanner (Bay 3)' }, db);
  assert.equal(updated.device_identity_hint, 'CT Scanner (Bay 3)');
  assert.equal(updated.confirmed, false); // unrelated field untouched

  assert.equal(updateAsset('nonexistent', { confirmed: true }, db), null);
});
