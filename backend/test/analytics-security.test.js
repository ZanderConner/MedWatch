// Analytics + Security page tests: seed varied events/assets/alerts and
// confirm the aggregation endpoints compute correct distributions/
// timeseries/top-talkers, and that flagged-assets joins alerts to
// assets correctly.
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
  eventsTimeseries,
  protocolDistribution,
  transportDistribution,
  osDistribution,
  topTalkers,
} = require('../analytics/queries');
const { severityBreakdown, flaggedAssets } = require('../security/queries');

function iso(hoursAgo) {
  return new Date(Date.now() - hoursAgo * 3600 * 1000).toISOString();
}

test('analytics + security aggregations', () => {
  migrate(getDb());
  const db = getDb();

  insertEvents([
    { event_id: 'a0000000-0000-0000-0000-000000000001', sensor_id: 's1', '@timestamp': iso(2), src_ip: '10.0.0.1', dst_ip: '10.0.0.9', transport: 'tcp', application: 'dicom', length_bytes: 10 },
    { event_id: 'a0000000-0000-0000-0000-000000000002', sensor_id: 's1', '@timestamp': iso(2), src_ip: '10.0.0.1', dst_ip: '10.0.0.9', transport: 'tcp', application: 'dicom', length_bytes: 10 },
    { event_id: 'a0000000-0000-0000-0000-000000000003', sensor_id: 's1', '@timestamp': iso(1), src_ip: '10.0.0.2', dst_ip: '10.0.0.9', transport: 'udp', application: 'hl7', length_bytes: 20 },
    { event_id: 'a0000000-0000-0000-0000-000000000004', sensor_id: 's1', '@timestamp': iso(0), src_ip: '10.0.0.1', dst_ip: '10.0.0.9', transport: 'tcp', application: 'unknown', length_bytes: 5 },
  ]);

  upsertAssets([
    { asset_id: 'asset-1', sensor_id: 's1', '@timestamp': iso(0), first_seen: iso(2), mac_address: null, ip_addresses: ['10.0.0.1'], vendor_oui: null, os_guess: 'embedded-or-iot', observed_ports: [22], observed_protocols: ['dicom'], device_identity_hint: null },
    { asset_id: 'asset-2', sensor_id: 's1', '@timestamp': iso(0), first_seen: iso(1), mac_address: null, ip_addresses: ['10.0.0.2'], vendor_oui: null, os_guess: 'linux', observed_ports: [2575], observed_protocols: ['hl7'], device_identity_hint: null },
  ]);

  // --- analytics ---
  const distribution = protocolDistribution({}, db);
  const dicom = distribution.find((d) => d.application === 'dicom');
  assert.equal(dicom.count, 2);

  const transport = transportDistribution({}, db);
  assert.ok(transport.some((t) => t.transport === 'tcp' && t.count === 3));

  const os = osDistribution({}, db);
  assert.ok(os.some((o) => o.os_guess === 'embedded-or-iot' && o.count === 1));
  assert.ok(os.some((o) => o.os_guess === 'linux' && o.count === 1));

  const talkers = topTalkers({ limit: 10 }, db);
  const top = talkers.find((t) => t.ip === '10.0.0.1');
  assert.equal(top.event_count, 3);
  assert.equal(top.asset_id, 'asset-1', 'top talker should be matched back to its asset_id');

  const ts = eventsTimeseries({ interval: 'hour' }, db);
  assert.equal(ts.interval, 'hour');
  assert.ok(ts.buckets.length >= 1);
  const totalBucketed = ts.buckets.reduce((sum, b) => sum + b.count, 0);
  assert.equal(totalBucketed, 4);

  // --- sensor_id scoping (new, multi-sensor distributed-agent demo) ---
  insertEvents([
    { event_id: 'a0000000-0000-0000-0000-000000000005', sensor_id: 's2', '@timestamp': iso(0), src_ip: '10.0.0.5', dst_ip: '10.0.0.9', transport: 'tcp', application: 'dicom', length_bytes: 10 },
  ]);
  const s1Only = protocolDistribution({ sensor_id: 's1' }, db);
  const s1Total = s1Only.reduce((sum, d) => sum + d.count, 0);
  assert.equal(s1Total, 4, 'sensor_id filter should exclude the other sensor\'s events');
  const s2Only = protocolDistribution({ sensor_id: 's2' }, db);
  assert.equal(s2Only.reduce((sum, d) => sum + d.count, 0), 1);
  const s1Talkers = topTalkers({ limit: 10, sensor_id: 's1' }, db);
  assert.ok(!s1Talkers.some((t) => t.ip === '10.0.0.5'), 'topTalkers sensor_id filter should exclude s2\'s IP');

  // --- security ---
  runCorrelation(db); // asset-1 (embedded-or-iot, port 22) should trigger an alert
  const severity = severityBreakdown(db);
  assert.ok(severity.some((s) => s.severity === 'warning' && s.count >= 1));

  const flagged = flaggedAssets(db);
  assert.equal(flagged.length, 1);
  assert.equal(flagged[0].asset_id, 'asset-1');
  assert.ok(flagged[0].alerts.length >= 1);
  // asset-1 (embedded-or-iot, port 22, speaks dicom on a non-standard
  // port) can trigger both correlation rules — order between same-tick
  // alerts isn't guaranteed (created_at has only second precision), so
  // assert set membership rather than a specific array index.
  const rules = flagged[0].alerts.map((a) => a.rule);
  assert.ok(rules.includes('embedded_device_exposing_remote_admin'));
});
