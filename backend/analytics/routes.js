// Analytics page endpoints: event volume over time, protocol/transport/
// OS distributions, top talkers. All read-only, no auth (matches the
// plain read API — see backend/api/routes.js). Every endpoint accepts
// an optional sensor_id filter (in addition to the existing
// since/until/application filters on the ones that support it) so the
// frontend's Analytics page can scope to a single subnet's sensor as
// well as look at the aggregate across all of them.
const express = require('express');
const {
  eventsTimeseries,
  protocolDistribution,
  transportDistribution,
  osDistribution,
  topTalkers,
  systemHealth,
} = require('./queries');

const router = express.Router();

// GET /api/v1/analytics/events-timeseries?interval=hour|day&since=&until=&application=&sensor_id=
router.get('/analytics/events-timeseries', (req, res) => {
  res.json(
    eventsTimeseries({
      interval: req.query.interval,
      since: req.query.since,
      until: req.query.until,
      application: req.query.application,
      sensor_id: req.query.sensor_id,
    })
  );
});

// GET /api/v1/analytics/protocol-distribution?since=&until=&sensor_id=
router.get('/analytics/protocol-distribution', (req, res) => {
  res.json({
    distribution: protocolDistribution({
      since: req.query.since,
      until: req.query.until,
      sensor_id: req.query.sensor_id,
    }),
  });
});

// GET /api/v1/analytics/transport-distribution?since=&until=&sensor_id=
router.get('/analytics/transport-distribution', (req, res) => {
  res.json({
    distribution: transportDistribution({
      since: req.query.since,
      until: req.query.until,
      sensor_id: req.query.sensor_id,
    }),
  });
});

// GET /api/v1/analytics/os-distribution?sensor_id=
router.get('/analytics/os-distribution', (req, res) => {
  res.json({ distribution: osDistribution({ sensor_id: req.query.sensor_id }) });
});

// GET /api/v1/analytics/top-talkers?limit=10&since=&until=&sensor_id=
router.get('/analytics/top-talkers', (req, res) => {
  res.json({
    top_talkers: topTalkers({
      limit: req.query.limit,
      since: req.query.since,
      until: req.query.until,
      sensor_id: req.query.sensor_id,
    }),
  });
});

// GET /api/v1/analytics/system-health — backend uptime + fleet
// liveness + headline counts for the dashboard's system-status panel.
router.get('/analytics/system-health', (req, res) => {
  res.json(systemHealth());
});

module.exports = router;
