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
  // The following two rules exist specifically so a red-team box sending
  // deliberately "rough" DICOM/HL7 traffic (self-identifying under an
  // AE title / sending application that was never provisioned in this
  // demo range) trips something concrete — an unconfirmed device
  // speaking a clinical protocol under an unrecognized name is exactly
  // the kind of thing this correlation layer exists to surface.
  // KNOWN_GOOD_* are demo-range-specific device names, not a real-world
  // allowlist mechanism (a real deployment would pull this from an
  // asset registry, not a hardcoded list) — intentionally simple for
  // the hackathon scope.
  {
    name: 'unrecognized_dicom_initiator',
    severity: 'critical',
    matches: (asset) =>
      asset.observed_protocols.includes('dicom') &&
      asset.device_identity_hint &&
      !KNOWN_GOOD_DICOM_AE_TITLES.has(asset.device_identity_hint.toUpperCase()),
    message: (asset) =>
      `Asset ${asset.asset_id} is issuing DICOM associations as AE title "${asset.device_identity_hint}", which isn't a recognized modality/PACS in this environment — verify this isn't an unauthorized device probing the imaging network.`,
  },
  {
    name: 'unrecognized_hl7_sender',
    severity: 'critical',
    matches: (asset) =>
      asset.observed_protocols.includes('hl7') &&
      asset.device_identity_hint &&
      !KNOWN_GOOD_HL7_SENDING_APPS.has(asset.device_identity_hint.toUpperCase()),
    message: (asset) =>
      `Asset ${asset.asset_id} is sending HL7 messages as sending application "${asset.device_identity_hint}", which isn't a recognized lab system in this environment — verify this isn't an unauthorized device injecting HL7 traffic.`,
  },
];

const KNOWN_GOOD_DICOM_AE_TITLES = new Set(['CTSIM', 'MRISIM', 'ORTHANC']);
const KNOWN_GOOD_HL7_SENDING_APPS = new Set(['HEMA-3000', 'MIRTH', 'HEMA-4000']);

function parseJsonArrayColumn(value) {
  try {
    return JSON.parse(value);
  } catch {
    return [];
  }
}

function runCorrelation(db = getDb()) {
  // Confirmed assets are treated as vetted/known-good by an admin — the
  // correlation rules below are heuristics meant to surface *new,
  // unreviewed* devices worth a look, not to re-flag something an admin
  // already looked at and confirmed. Excluding confirmed assets here is
  // what actually stops "everything getting flagged even when
  // confirmed": previously ALL assets (confirmed or not) were evaluated
  // every pass, so a confirmed IoT device with SSH open kept generating
  // "new" alerts forever even after being reviewed.
  //
  // This alone isn't enough on its own, though: an asset can already
  // have alerts sitting in the table from *before* it was confirmed
  // (e.g. discovered, flagged, THEN confirmed by an admin) — updateAsset()
  // clears those at confirm-time (see admin/assets.js), but any asset
  // confirmed by some other path, or any alert inserted between two
  // periodic passes, would otherwise sit there stale forever. So every
  // pass also sweeps alerts belonging to assets that are *currently*
  // confirmed, regardless of how they got that way.
  db.prepare(
    `DELETE FROM alerts WHERE asset_id IN (SELECT asset_id FROM assets WHERE confirmed = 1)`
  ).run();

  const assets = db
    .prepare('SELECT * FROM assets WHERE confirmed = 0')
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
        // Mirror into the append-only history table (never deleted —
        // see 005_alert_history.sql) so a burst that gets cleared
        // (asset confirmed, rule stops matching) before the next chart
        // fetch still shows up on the "Policy Violations Over Time"
        // chart instead of disappearing along with the live `alerts`
        // row.
        const row = db.prepare('SELECT created_at FROM alerts WHERE alert_id = ?').get(alert.alert_id);
        db.prepare(
          'INSERT INTO alert_events (alert_id, asset_id, rule, severity, message, created_at) VALUES (?, ?, ?, ?, ?, ?)'
        ).run(alert.alert_id, alert.asset_id, alert.rule, alert.severity, alert.message, row.created_at);
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
