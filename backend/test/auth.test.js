// HTTP-level auth test: confirms which routes require
// "Authorization: ApiKey <key>" and which are open, using a real
// running Express app (supertest-free — plain http requests via
// node's built-in fetch against an ephemeral port).
const test = require('node:test');
const assert = require('node:assert/strict');

process.env.MEDWATCH_DB_PATH = ':memory:';
process.env.MEDWATCH_API_KEY = 'test-key';
process.env.PORT = '0'; // ephemeral port

const express = require('express');
const { migrate } = require('../db/migrate');
const { getDb } = require('../db/connection');
const ingestRoutes = require('../ingest/routes');
const apiRoutes = require('../api/routes');
const alertingRoutes = require('../alerting/routes');
const adminRoutes = require('../admin/routes');

function buildApp() {
  migrate(getDb());
  const app = express();
  app.use(express.json());
  app.use('/api/v1', ingestRoutes);
  app.use('/api/v1', apiRoutes);
  app.use('/api/v1', alertingRoutes);
  app.use('/api/v1', adminRoutes);
  return app;
}

function withServer(app, fn) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        await fn(`http://localhost:${port}`);
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        server.close();
      }
    });
  });
}

test('auth: ingest and admin writes require ApiKey, reads do not', async () => {
  const app = buildApp();
  await withServer(app, async (base) => {
    // Ingest write, no key -> 401.
    let res = await fetch(`${base}/api/v1/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '[]',
    });
    assert.equal(res.status, 401);

    // Ingest write, wrong key -> 401.
    res = await fetch(`${base}/api/v1/assets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'ApiKey wrong' },
      body: '[]',
    });
    assert.equal(res.status, 401);

    // Ingest write, correct key -> 200.
    res = await fetch(`${base}/api/v1/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'ApiKey test-key' },
      body: '[]',
    });
    assert.equal(res.status, 200);

    // Read routes: no auth required.
    for (const path of ['/api/v1/assets', '/api/v1/events', '/api/v1/sensors', '/api/v1/stats', '/api/v1/alerts']) {
      res = await fetch(`${base}${path}`);
      assert.equal(res.status, 200, `${path} should be readable without auth`);
    }

    // Mutating alerting route requires auth.
    res = await fetch(`${base}/api/v1/correlate`, { method: 'POST' });
    assert.equal(res.status, 401, 'POST /correlate should require auth');

    res = await fetch(`${base}/api/v1/correlate`, {
      method: 'POST',
      headers: { Authorization: 'ApiKey test-key' },
    });
    assert.equal(res.status, 200);

    // Admin routes require auth for every verb.
    res = await fetch(`${base}/api/v1/admin/sensors`);
    assert.equal(res.status, 401);

    res = await fetch(`${base}/api/v1/admin/sensors`, {
      headers: { Authorization: 'ApiKey test-key' },
    });
    assert.equal(res.status, 200);
  });
});
