// Security page endpoints: severity breakdown + flagged assets (assets
// with correlation alerts attached, joined so the frontend doesn't have
// to N+1 GET /api/v1/assets/:id for every alert it lists). Read-only, no
// auth (matches the plain read API — see backend/api/routes.js).
const express = require('express');
const { severityBreakdown, violationsTimeseries, flaggedAssets } = require('./queries');

const router = express.Router();

// GET /api/v1/security/severity-breakdown
router.get('/security/severity-breakdown', (_req, res) => {
  res.json({ breakdown: severityBreakdown() });
});

// GET /api/v1/security/violations-timeseries?interval=hour|day&since=&until=
router.get('/security/violations-timeseries', (req, res) => {
  res.json(
    violationsTimeseries({
      interval: req.query.interval,
      since: req.query.since,
      until: req.query.until,
    })
  );
});

// GET /api/v1/security/flagged-assets
router.get('/security/flagged-assets', (_req, res) => {
  res.json({ assets: flaggedAssets() });
});

module.exports = router;
