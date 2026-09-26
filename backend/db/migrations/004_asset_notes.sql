-- Free-text admin notes on an asset (e.g. "swapped 2026-09, see ticket
-- #412", "biomed-owned, do not touch"). Purely descriptive, no
-- behavioral effect on correlation/alerting.
--
-- NOTE: SQLite has no idempotent "ADD COLUMN IF NOT EXISTS", so this
-- file is applied specially by db/migrate.js (checked against
-- pragma_table_info before running), same as 003_asset_admin.sql.
ALTER TABLE assets ADD COLUMN notes TEXT;
