// Ingest routes: POST /api/v1/events and POST /api/v1/assets.
// This is the exact contract the sensor agent's shipper implements
// (agents/sensor-agent/src/shipper.rs) — do not change the request/
// response shape here without updating the agent's config/code too.
const express = require('express');
const { z } = require('zod');
const { config } = require('../shared/config');
const { requireApiKey } = require('../shared/auth');
const { NetworkEventSchema, AssetRecordSchema } = require('../shared/schemas');
const { insertEvents } = require('./events-store');
const { upsertAssets } = require('../asset-inventory/upsert');

const router = express.Router();

function validateBatch(schema, body, res) {
  if (!Array.isArray(body)) {
    res.status(400).json({ error: 'request body must be a JSON array' });
    return null;
  }
  if (body.length === 0) {
    return [];
  }
  if (body.length > config.maxBatchSize) {
    res.status(400).json({
      error: `batch too large: ${body.length} docs, max ${config.maxBatchSize}`,
    });
    return null;
  }

  const arraySchema = z.array(schema);
  const result = arraySchema.safeParse(body);
  if (!result.success) {
    res.status(400).json({
      error: 'batch failed validation',
      details: result.error.issues.slice(0, 20), // cap: don't dump huge error bodies
    });
    return null;
  }
  return result.data;
}

router.post('/events', requireApiKey, (req, res) => {
  const events = validateBatch(NetworkEventSchema, req.body, res);
  if (events === null) return;
  if (events.length === 0) return res.status(200).json({ accepted: 0 });

  try {
    insertEvents(events);
  } catch (err) {
    console.error('[ingest] failed to store events batch:', err);
    return res.status(500).json({ error: 'failed to store events batch' });
  }

  res.status(200).json({ accepted: events.length });
});

router.post('/assets', requireApiKey, (req, res) => {
  const assets = validateBatch(AssetRecordSchema, req.body, res);
  if (assets === null) return;
  if (assets.length === 0) return res.status(200).json({ accepted: 0 });

  try {
    upsertAssets(assets);
  } catch (err) {
    console.error('[ingest] failed to upsert assets batch:', err);
    return res.status(500).json({ error: 'failed to upsert assets batch' });
  }

  res.status(200).json({ accepted: assets.length });
});

module.exports = router;
