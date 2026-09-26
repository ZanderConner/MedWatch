// Event insert logic. Events are append-only raw telemetry — no upserts,
// no dedup beyond the primary key (event_id is a UUID from the agent, so
// a genuine duplicate send just no-ops via INSERT OR IGNORE rather than
// erroring the whole batch).
const { getDb } = require('../db/connection');

function insertEvent(event, db = getDb()) {
  db.prepare(
    `INSERT OR IGNORE INTO events
      (event_id, sensor_id, observed_at, src_ip, src_port, src_mac,
       dst_ip, dst_port, dst_mac, transport, application, length_bytes,
       protocol_metadata)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    event.event_id,
    event.sensor_id,
    event['@timestamp'],
    event.src_ip,
    event.src_port ?? null,
    event.src_mac ?? null,
    event.dst_ip,
    event.dst_port ?? null,
    event.dst_mac ?? null,
    event.transport,
    event.application,
    event.length_bytes,
    event.protocol_metadata ? JSON.stringify(event.protocol_metadata) : null
  );
}

function insertEvents(events, db = getDb()) {
  db.exec('BEGIN');
  try {
    for (const event of events) {
      insertEvent(event, db);
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

module.exports = { insertEvent, insertEvents };
