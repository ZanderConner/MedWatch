// Alerting read API: expose what correlation has found so far. No
// notification/paging integration for the hackathon — just a queryable
// table the frontend can poll or list.
const express = require('express');
const { getDb } = require('../db/connection');
const { requireApiKey } = require('../shared/auth');
const { runCorrelation } = require('../correlation/rules');

const router = express.Router();

// GET /api/v1/alerts?severity=warning&limit=100
router.get('/alerts', (req, res) => {
  const db = getDb();
  const limit = Math.min(Number(req.query.limit) || 100, 1000);

  const clauses = [];
  const params = [];
  if (req.query.severity) {
    clauses.push('severity = ?');
    params.push(req.query.severity);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

  const alerts = db
    .prepare(`SELECT * FROM alerts ${where} ORDER BY created_at DESC LIMIT ?`)
    .all(...params, limit);

  res.json({ alerts });
});

// POST /api/v1/correlate — manually trigger a correlation pass (also run
// automatically on a timer, see server.js). Returns newly created alerts.
// Requires auth: unlike GET /alerts, this is a write (inserts alert rows).
router.post('/correlate', requireApiKey, (req, res) => {
  try {
    const newAlerts = runCorrelation();
    res.json({ new_alerts: newAlerts });
  } catch (err) {
    console.error('[alerting] correlation pass failed:', err);
    res.status(500).json({ error: 'correlation pass failed' });
  }
});

module.exports = router;
