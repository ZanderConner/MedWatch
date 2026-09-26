// Applies every backend/db/migrations/*.sql file in filename order against
// the configured SQLite database. Idempotent (uses CREATE TABLE IF NOT
// EXISTS / CREATE INDEX IF NOT EXISTS everywhere) so it's safe to re-run.
const fs = require('node:fs');
const path = require('node:path');
const { getDb } = require('./connection');

function migrate(db = getDb()) {
  const dir = path.join(__dirname, 'migrations');
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const sql = fs.readFileSync(path.join(dir, file), 'utf8');
    db.exec(sql);
    console.log(`[migrate] applied ${file}`);
  }
}

if (require.main === module) {
  migrate();
  console.log('[migrate] done');
}

module.exports = { migrate };
