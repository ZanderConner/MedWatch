// Analytics page endpoints: event volume over time, protocol/transport/
// OS distributions, top talkers. All read-only, no auth (matches the
// plain read API — see backend/api/routes.js).
const express = require('express');
const {
  eventsTimeseries,
  protocolDistribution,
  transportDistribution,
  osDistribution,
  topTalkers,
} = require('./queries');

const router = express.Router();

// GET /api/v1/analytics/events-timeseries?interval=hour|day&since=&until=&application=
router.get('/analytics/events-timeseries', (req, res) => {
  res.json(
    eventsTimeseries({
      interval: req.query.interval,
      since: req.query.since,
      until: req.query.until,
      application: req.query.application,
    })
  );
});

// GET /api/v1/analytics/protocol-distribution
router.get('/analytics/protocol-distribution', (_req, res) => {
  res.json({ distribution: protocolDistribution() });
});

// GET /api/v1/analytics/transport-distribution
router.get('/analytics/transport-distribution', (_req, res) => {
  res.json({ distribution: transportDistribution() });
});

// GET /api/v1/analytics/os-distribution
router.get('/analytics/os-distribution', (_req, res) => {
  res.json({ distribution: osDistribution() });
});

// GET /api/v1/analytics/top-talkers?limit=10
router.get('/analytics/top-talkers', (req, res) => {
  res.json({ top_talkers: topTalkers({ limit: req.query.limit }) });
});

module.exports = router;
