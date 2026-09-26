// End-to-end smoke test: ingest events+assets, then verify the read API
// (assets, events, sensors, stats, alerts, correlation) returns correct
// data. Uses an in-memory DB so it never touches real data.
const test = require('node:test');
const assert = require('node:assert/strict');

process.env.MEDWATCH_DB_PATH = ':memory:';
process.env.MEDWATCH_API_KEY = 'test-key';

const { migrate } = require('../db/migrate');
const { getDb } = require('../db/connection');
const { insertEvents } = require('../ingest/events-store');
const { upsertAssets } = require('../asset-inventory/upsert');
const { runCorrelation } = require('../correlation/rules');
const { listSensors, getStats } = require('../api/sensors');

test('ingest + read API smoke test', () => {
  migrate(getDb());

  const now = new Date().toISOString();

  insertEvents([
    {
      event_id: '11111111-1111-1111-1111-111111111111',
      sensor_id: 'sensor-a',
      '@timestamp': now,
      src_ip: '10.20.50.21',
      src_port: 4242,
      dst_ip: '10.20.50.10',
      dst_port: 4242,
      transport: 'tcp',
      application: 'dicom',
      length_bytes: 128,
      protocol_metadata: { called_ae_title: 'ORTHANC', calling_ae_title: 'DICOMSIM' },
    },
  ]);

  upsertAssets([
    {
      asset_id: 'aa:bb:cc:dd:ee:ff',
      sensor_id: 'sensor-a',
      '@timestamp': now,
      first_seen: now,
      mac_address: 'aa:bb:cc:dd:ee:ff',
      ip_addresses: ['10.20.50.21'],
      vendor_oui: null,
      os_guess: 'embedded-or-iot',
      observed_ports: [22, 104],
      observed_protocols: ['dicom'],
      device_identity_hint: 'DICOMSIM',
    },
  ]);

  // Re-send the same asset with a new port to confirm the upsert-merge
  // unions rather than overwrites.
  upsertAssets([
    {
      asset_id: 'aa:bb:cc:dd:ee:ff',
      sensor_id: 'sensor-a',
      '@timestamp': now,
      first_seen: now,
      mac_address: 'aa:bb:cc:dd:ee:ff',
      ip_addresses: ['10.20.50.21'],
      vendor_oui: null,
      os_guess: 'embedded-or-iot',
      observed_ports: [11112],
      observed_protocols: ['dicom'],
      device_identity_hint: 'DICOMSIM',
    },
  ]);

  const db = getDb();
  const asset = db.prepare('SELECT * FROM assets WHERE asset_id = ?').get('aa:bb:cc:dd:ee:ff');
  const ports = JSON.parse(asset.observed_ports);
  assert.deepEqual(new Set(ports), new Set([22, 104, 11112]), 'observed_ports should union across upserts');

  const events = db.prepare('SELECT * FROM events').all();
  assert.equal(events.length, 1);
  assert.equal(events[0].application, 'dicom');

  // Correlation: the embedded-or-iot asset exposes port 22 -> fires the
  // remote-admin rule; its AE title "DICOMSIM" also isn't in the demo
  // range's known-good AE title list -> fires the unrecognized-DICOM-
  // initiator rule too. Two distinct rules, both legitimately matching.
  const alerts = runCorrelation(db);
  assert.equal(alerts.length, 2);
  const rules = alerts.map((a) => a.rule).sort();
  assert.deepEqual(rules, ['embedded_device_exposing_remote_admin', 'unrecognized_dicom_initiator']);

  // Sensors/stats.
  const sensors = listSensors(db);
  assert.equal(sensors.length, 1);
  assert.equal(sensors[0].sensor_id, 'sensor-a');
  assert.equal(sensors[0].active, true);

  const stats = getStats(db);
  assert.equal(stats.sensors_total, 1);
  assert.equal(stats.sensors_active, 1);
  assert.equal(stats.total_events, 1);
  assert.equal(stats.total_assets, 1);
});
