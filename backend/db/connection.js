// Single shared SQLite connection (node:sqlite, built into Node 22.5+ —
// no native module build step, which matters for a hackathon where a
// broken node-gyp toolchain shouldn't block the demo).
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');
const { config } = require('../shared/config');

let db;

function getDb() {
  if (db) return db;

  if (config.dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
  }

  db = new DatabaseSync(config.dbPath);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  return db;
}

module.exports = { getDb };
