-- Append-only history of every alert ever raised by correlation
-- (backend/correlation/rules.js). The `alerts` table is mutable state
-- (a row is deleted the moment its asset gets confirmed or the rule
-- stops matching — see runCorrelation()'s DELETE), which makes it
-- unsuitable for a "policy violations over time" chart: a short-lived
-- attack burst that gets confirmed/cleared within the same lookback
-- window would disappear from the alerts table entirely before the
-- chart ever rendered it. alert_events is insert-only and never
-- pruned, so the Security page's timeseries can show every burst that
-- ever happened, not just whatever is still currently open.
CREATE TABLE IF NOT EXISTS alert_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  rule TEXT NOT NULL,
  severity TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alert_events_created_at ON alert_events (created_at);
