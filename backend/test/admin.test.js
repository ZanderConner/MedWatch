// Admin sensor page logic test: label/notes/retire, detail breakdown,
// and purge — the destructive path is worth testing explicitly.
const test = require('node:test');
const assert = require('node:assert/strict');

process.env.MEDWATCH_DB_PATH = ':memory:';
process.env.MEDWATCH_API_KEY = 'test-key';

const { migrate } = require('../db/migrate');
const { getDb } = require('../db/connection');
const { insertEvents } = require('../ingest/events-store');
const { upsertAssets } = require('../asset-inventory/upsert');
const { runCorrelation } = require('../correlation/rules');
const {
  listSensorsAdmin,
  getSensorDetail,
  setSensorMeta,
  purgeSensor,
} = require('../admin/sensors');

function seed(db) {
  const now = new Date().toISOString();
  insertEvents([
    {
      event_id: '33333333-3333-3333-3333-333333333333',
      sensor_id: 'sensor-b',
      '@timestamp': now,
      src_ip: '10.0.0.5',
      dst_ip: '10.0.0.6',
      transport: 'tcp',
      application: 'hl7',
      length_bytes: 200,
    },
  ]);
  upsertAssets([
    {
      asset_id: 'bb:cc:dd:ee:ff:00',
      sensor_id: 'sensor-b',
      '@timestamp': now,
      first_seen: now,
      mac_address: 'bb:cc:dd:ee:ff:00',
      ip_addresses: ['10.0.0.5'],
      vendor_oui: null,
      os_guess: 'embedded-or-iot',
      observed_ports: [22],
      observed_protocols: ['hl7'],
      device_identity_hint: null,
    },
  ]);
  runCorrelation(db);
}

test('admin sensor page: label/retire/detail/purge', () => {
  migrate(getDb());
  const db = getDb();
  seed(db);

  // Lazily-created meta via PATCH.
  const meta = setSensorMeta('sensor-b', { label: 'ICU Sensor 3', notes: 'test note' }, db);
  assert.equal(meta.label, 'ICU Sensor 3');
  assert.equal(meta.retired, false);

  const admin = listSensorsAdmin(db);
  const entry = admin.find((s) => s.sensor_id === 'sensor-b');
  assert.equal(entry.label, 'ICU Sensor 3');
  assert.equal(entry.retired, false);

  const detail = getSensorDetail('sensor-b', db);
  assert.equal(detail.application_breakdown.length, 1);
  assert.equal(detail.application_breakdown[0].application, 'hl7');
  assert.equal(detail.recent_alerts.length, 2, 'both correlation rules should fire: SSH-exposure and HL7-on-nonstandard-port');

  // Retire it -> active must be forced false even if recently seen.
  setSensorMeta('sensor-b', { retired: true }, db);
  const afterRetire = listSensorsAdmin(db).find((s) => s.sensor_id === 'sensor-b');
  assert.equal(afterRetire.retired, true);
  assert.equal(afterRetire.active, false);

  // Purge removes everything for this sensor_id.
  const purged = purgeSensor('sensor-b', db);
  assert.equal(purged.events_deleted, 1);
  assert.equal(purged.assets_deleted, 1);
  assert.equal(purged.alerts_deleted, 2);
  assert.equal(purged.meta_deleted, 1);

  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM events WHERE sensor_id = ?').get('sensor-b').c, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM assets WHERE sensor_id = ?').get('sensor-b').c, 0);
  assert.equal(getSensorDetail('sensor-b', db), null);
});

test('runCorrelation only returns genuinely new alerts, not re-matches', () => {
  migrate(getDb());
  const db = getDb();
  seed(db);

  const second = runCorrelation(db);
  assert.equal(second.length, 0, 'a second pass with no asset changes should report 0 new alerts');

  const totalAlerts = db.prepare('SELECT COUNT(*) AS c FROM alerts').get().c;
  assert.equal(totalAlerts, 2, 'alerts table should still only have the 2 alerts from the first pass');
});

test('unknown sensor_id returns null detail', () => {
  migrate(getDb());
  const detail = getSensorDetail('does-not-exist', getDb());
  assert.equal(detail, null);
});
