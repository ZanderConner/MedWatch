// Minimal correlation rules for the hackathon demo. Not comprehensive —
// two illustrative rules flagging things that are unusual for a medical
// device, run against the current asset table. Designed to be called
// periodically (see server.js) or on-demand via POST /api/v1/correlate.
const crypto = require('node:crypto');
const { getDb } = require('../db/connection');

const RULES = [
  {
    name: 'embedded_device_exposing_remote_admin',
    severity: 'warning',
    matches: (asset) =>
      asset.os_guess === 'embedded-or-iot' &&
      (asset.observed_ports.includes(22) || asset.observed_ports.includes(3389)),
    message: (asset) =>
      `Embedded/IoT device ${asset.asset_id} exposes SSH/RDP (ports: ${asset.observed_ports.join(', ')}) — unusual for a medical device, worth checking for a misconfigured management interface.`,
  },
  {
    name: 'clinical_protocol_on_unexpected_port',
    severity: 'info',
    matches: (asset) => {
      const usesDicom = asset.observed_protocols.includes('dicom');
      const usesHl7 = asset.observed_protocols.includes('hl7');
      const standardPorts = [104, 11112, 2575];
      const onNonStandardPort =
        (usesDicom || usesHl7) &&
        asset.observed_ports.length > 0 &&
        !asset.observed_ports.some((p) => standardPorts.includes(p));
      return onNonStandardPort;
    },
    message: (asset) =>
      `Asset ${asset.asset_id} speaks DICOM/HL7 but none of its observed ports (${asset.observed_ports.join(', ')}) are the standard 104/11112/2575 — confirm this is expected (e.g. a proxy/gateway) and not shadow IT.`,
  },
];

function parseJsonArrayColumn(value) {
  try {
    return JSON.parse(value);
  } catch {
    return [];
  }
}

function runCorrelation(db = getDb()) {
  const assets = db
    .prepare('SELECT * FROM assets')
    .all()
    .map((row) => ({
      ...row,
      observed_ports: parseJsonArrayColumn(row.observed_ports),
      observed_protocols: parseJsonArrayColumn(row.observed_protocols),
    }));

  const candidates = [];
  for (const asset of assets) {
    for (const rule of RULES) {
      if (rule.matches(asset)) {
        candidates.push({
          alert_id: crypto.randomUUID(),
          asset_id: asset.asset_id,
          rule: rule.name,
          severity: rule.severity,
          message: rule.message(asset),
        });
      }
    }
  }

  // Only alerts actually inserted (i.e. genuinely new — no existing
  // (asset_id, rule) alert yet) are returned. Without this, a rule that
  // keeps matching on every periodic pass (see server.js) would be
  // reported as "new" every time, even though nothing changed.
  const insertedAlerts = [];
  if (candidates.length > 0) {
    db.exec('BEGIN');
    try {
      for (const alert of candidates) {
        const existing = db
          .prepare(
            'SELECT 1 FROM alerts WHERE asset_id = ? AND rule = ? ORDER BY created_at DESC LIMIT 1'
          )
          .get(alert.asset_id, alert.rule);
        if (existing) continue;
        db.prepare(
          'INSERT INTO alerts (alert_id, asset_id, rule, severity, message) VALUES (?, ?, ?, ?, ?)'
        ).run(alert.alert_id, alert.asset_id, alert.rule, alert.severity, alert.message);
        insertedAlerts.push(alert);
      }
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  return insertedAlerts;
}

module.exports = { runCorrelation, RULES };
