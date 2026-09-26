// Applies every backend/db/migrations/*.sql file in filename order against
// the configured SQLite database. Idempotent (uses CREATE TABLE IF NOT
// EXISTS / CREATE INDEX IF NOT EXISTS everywhere) so it's safe to re-run.
//
// SQLite has no idempotent "ALTER TABLE ADD COLUMN IF NOT EXISTS", so
// files containing ALTER TABLE ... ADD COLUMN are special-cased: each
// such statement is only run if the column doesn't already exist
// (checked via pragma_table_info), then the rest of the file's
// statements (CREATE INDEX etc, already idempotent) run normally.
const fs = require('node:fs');
const path = require('node:path');
const { getDb } = require('./connection');

const ADD_COLUMN_RE = /ALTER TABLE\s+(\w+)\s+ADD COLUMN\s+(\w+)/i;

function columnExists(db, table, column) {
  return db
    .prepare(`SELECT 1 FROM pragma_table_info(?) WHERE name = ?`)
    .get(table, column) !== undefined;
}

function migrate(db = getDb()) {
  const dir = path.join(__dirname, 'migrations');
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const sql = fs.readFileSync(path.join(dir, file), 'utf8');

    if (ADD_COLUMN_RE.test(sql)) {
      // Split on statement-terminating semicolons (none of these
      // migration files use semicolons inside string literals/values,
      // so a plain split is safe here).
      for (const raw of sql.split(';')) {
        const stmt = raw.trim();
        if (!stmt) continue;
        const match = stmt.match(ADD_COLUMN_RE);
        if (match) {
          const [, table, column] = match;
          if (columnExists(db, table, column)) continue;
        }
        db.exec(stmt);
      }
    } else {
      db.exec(sql);
    }
    console.log(`[migrate] applied ${file}`);
  }
}

if (require.main === module) {
  migrate();
  console.log('[migrate] done');
}

module.exports = { migrate };
