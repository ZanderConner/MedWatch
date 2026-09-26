// Regression test: confirming an asset must not leave stale alerts
// around, and runCorrelation()'s periodic sweep must actively clean up
// any alerts belonging to already-confirmed assets (not just skip
// generating new ones) — this is what actually fixes "everything is
// still flagging as suspicious even after confirming" bug reports,
// where an asset had alerts from before it was ever confirmed.
const test = require('node:test');
const assert = require('node:assert/strict');

process.env.MEDWATCH_DB_PATH = ':memory:';
process.env.MEDWATCH_API_KEY = 'test-key';

const { migrate } = require('../db/migrate');
const { getDb } = require('../db/connection');
const { upsertAssets } = require('../asset-inventory/upsert');
const { runCorrelation } = require('../correlation/rules');
const { updateAsset } = require('../admin/assets');
const { flaggedAssets } = require('../security/queries');

function seedFlaggableAsset(db, assetId = 'aa:aa:aa:aa:aa:aa') {
  const now = new Date().toISOString();
  upsertAssets(
    [
      {
        asset_id: assetId,
        sensor_id: 'sensor-x',
        '@timestamp': now,
        first_seen: now,
        mac_address: assetId,
        ip_addresses: ['10.0.0.50'],
        vendor_oui: null,
        os_guess: 'embedded-or-iot',
        observed_ports: [22],
        observed_protocols: [],
        device_identity_hint: null,
      },
    ],
    db
  );
}

test('runCorrelation sweeps stale alerts for already-confirmed assets', () => {
  migrate(getDb());
  const db = getDb();
  seedFlaggableAsset(db, 'aa:aa:aa:aa:aa:a1');

  // First pass: asset is unconfirmed, embedded-or-iot + port 22 ->
  // should generate the embedded_device_exposing_remote_admin alert.
  const firstPass = runCorrelation(db);
  assert.equal(firstPass.length, 1);
  assert.equal(flaggedAssets(db).length, 1);

  // Confirm the asset directly in the DB (bypassing updateAsset's own
  // alert-clear, to prove runCorrelation's sweep is what actually does
  // the cleanup, not just the confirm-time side effect).
  db.prepare('UPDATE assets SET confirmed = 1 WHERE asset_id = ?').run('aa:aa:aa:aa:aa:a1');
  assert.equal(
    flaggedAssets(db).length,
    1,
    'alert should still be sitting there immediately after a raw confirm, before any correlation pass'
  );

  // Next periodic correlation pass must sweep it away.
  runCorrelation(db);
  assert.equal(
    flaggedAssets(db).length,
    0,
    'a confirmed asset must not still show up as flagged/suspicious after a correlation pass'
  );
});

test('updateAsset(confirmed: true) also clears alerts immediately, not just on next pass', () => {
  migrate(getDb());
  const db = getDb();
  seedFlaggableAsset(db, 'aa:aa:aa:aa:aa:a2');
  runCorrelation(db);
  assert.equal(flaggedAssets(db).length, 1);

  updateAsset('aa:aa:aa:aa:aa:a2', { confirmed: true }, db);
  assert.equal(flaggedAssets(db).length, 0, 'confirming via the admin API should clear alerts immediately');
});
