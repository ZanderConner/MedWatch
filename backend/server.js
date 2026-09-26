// MedWatch backend entrypoint: ingest API + read API + alerting, all on
// one Express app for hackathon simplicity (split into services later if
// there's ever a reason to scale them independently).
const express = require('express');
const { config } = require('./shared/config');
const { migrate } = require('./db/migrate');
const ingestRoutes = require('./ingest/routes');
const apiRoutes = require('./api/routes');
const alertingRoutes = require('./alerting/routes');
const adminRoutes = require('./admin/routes');
const analyticsRoutes = require('./analytics/routes');
const securityRoutes = require('./security/routes');
const { runCorrelation } = require('./correlation/rules');

migrate();

const app = express();
app.use(express.json({ limit: '10mb' }));

app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

// Sensor agent writes here (Authorization: ApiKey <key> required).
app.use('/api/v1', ingestRoutes);
// Frontend reads here (no auth for the hackathon demo).
app.use('/api/v1', apiRoutes);
app.use('/api/v1', alertingRoutes);
// Admin/sensor-management surface (auth required, per-route — see admin/routes.js).
app.use('/api/v1', adminRoutes);
// Analytics + Security page data (read-only, no auth — same as apiRoutes).
app.use('/api/v1', analyticsRoutes);
app.use('/api/v1', securityRoutes);

app.use((err, _req, res, _next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'malformed JSON body' });
  }
  console.error('[server] unhandled error:', err);
  res.status(500).json({ error: 'internal server error' });
});

app.listen(config.port, () => {
  console.log(`[server] MedWatch backend listening on :${config.port}`);
});

// Run a correlation pass every 30s so alerts stay reasonably fresh
// without the frontend having to poll POST /api/v1/correlate itself.
setInterval(() => {
  try {
    const newAlerts = runCorrelation();
    if (newAlerts.length > 0) {
      console.log(`[correlation] ${newAlerts.length} new alert(s)`);
    }
  } catch (err) {
    console.error('[correlation] periodic pass failed:', err);
  }
}, 30_000);
