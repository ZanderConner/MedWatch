// Regression test for GET /api/v1/assets: filters (os_guess, protocol)
// must apply in SQL, before LIMIT/OFFSET — not to an already-paginated
// page in JS. Exercises this over real HTTP against a real Express app.
const test = require('node:test');
const assert = require('node:assert/strict');

process.env.MEDWATCH_DB_PATH = ':memory:';
process.env.MEDWATCH_API_KEY = 'test-key';

const express = require('express');
const { migrate } = require('../db/migrate');
const { getDb } = require('../db/connection');
const { upsertAssets } = require('../asset-inventory/upsert');
const apiRoutes = require('../api/routes');

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/v1', apiRoutes);
  return app;
}

function withServer(app, fn) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        await fn(`http://localhost:${port}`);
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        server.close();
      }
    });
  });
}

test('GET /api/v1/assets filters before paginating, not after', async () => {
  migrate(getDb());
  const db = getDb();

  // 10 "windows" assets (last_seen most recent, so they sort first),
  // then 1 "linux" asset sorted after them. With limit=5, a filter
  // applied AFTER pagination would return 0 linux assets (they're not
  // in the first 5 rows); filtering in SQL must still find it.
  const now = Date.now();
  const windowsAssets = Array.from({ length: 10 }, (_, i) => ({
    asset_id: `win-${i}`,
    sensor_id: 's1',
    '@timestamp': new Date(now - i * 1000).toISOString(),
    first_seen: new Date(now - 100000).toISOString(),
    mac_address: null,
    ip_addresses: [`10.0.0.${i}`],
    vendor_oui: null,
    os_guess: 'windows',
    observed_ports: [],
    observed_protocols: [],
    device_identity_hint: null,
  }));
  const linuxAsset = {
    asset_id: 'linux-1',
    sensor_id: 's1',
    '@timestamp': new Date(now - 999999).toISOString(),
    first_seen: new Date(now - 999999).toISOString(),
    mac_address: null,
    ip_addresses: ['10.0.1.1'],
    vendor_oui: null,
    os_guess: 'linux',
    observed_ports: [22],
    observed_protocols: ['ssh'],
    device_identity_hint: null,
  };
  upsertAssets([...windowsAssets, linuxAsset], db);

  const app = buildApp();
  await withServer(app, async (base) => {
    const res = await fetch(`${base}/api/v1/assets?os_guess=linux&limit=5`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.assets.length, 1, 'the one linux asset should be found even though it is outside the first 5 rows by last_seen');
    assert.equal(body.assets[0].asset_id, 'linux-1');

    const protoRes = await fetch(`${base}/api/v1/assets?protocol=ssh&limit=5`);
    const protoBody = await protoRes.json();
    assert.equal(protoBody.assets.length, 1);
    assert.equal(protoBody.assets[0].asset_id, 'linux-1');
  });
});
