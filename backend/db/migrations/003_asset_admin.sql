-- Asset inventory admin support: distinguish agent-auto-discovered
-- assets from manually-entered ones, and let an admin "confirm" a
-- discovered asset (promote it from a raw sighting to a vetted
-- inventory entry) without deleting the underlying observed data.
--
-- Existing rows (all agent-discovered, from before this migration)
-- default to source='agent', confirmed=0 — they show up in the
-- inventory's "pending confirmation" state until an admin reviews them,
-- same as any newly-discovered asset going forward.
--
-- NOTE: SQLite has no idempotent "ADD COLUMN IF NOT EXISTS", so this
-- file is applied specially by db/migrate.js (checked against
-- pragma_table_info before running), not just blindly re-exec'd like
-- the CREATE TABLE/INDEX migrations.
ALTER TABLE assets ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE assets ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_assets_confirmed ON assets (confirmed);
