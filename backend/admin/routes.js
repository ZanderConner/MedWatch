// Admin routes for the sensor admin page: list all known sensors with
// activity + admin metadata, view one sensor's detail, label/retire a
// sensor, and purge a sensor's data. All mutating/detail routes require
// the same Authorization: ApiKey <key> the sensor agent uses — this is
// an admin surface, not a public read like api/routes.js.
const express = require('express');
const { z } = require('zod');
const { requireApiKey } = require('../shared/auth');
const {
  listSensorsAdmin,
  getSensorDetail,
  setSensorMeta,
  purgeSensor,
} = require('./sensors');

const router = express.Router();

const PatchSchema = z.object({
  label: z.string().max(200).nullable().optional(),
  notes: z.string().max(2000).nullable().optional(),
  retired: z.boolean().optional(),
});

// GET /api/v1/admin/sensors
router.get('/admin/sensors', requireApiKey, (_req, res) => {
  res.json({ sensors: listSensorsAdmin() });
});

// GET /api/v1/admin/sensors/:sensor_id
router.get('/admin/sensors/:sensor_id', requireApiKey, (req, res) => {
  const detail = getSensorDetail(req.params.sensor_id);
  if (!detail) {
    return res.status(404).json({ error: 'sensor not found (no events or assets from this sensor_id)' });
  }
  res.json(detail);
});

// PATCH /api/v1/admin/sensors/:sensor_id  body: { label?, notes?, retired? }
router.patch('/admin/sensors/:sensor_id', requireApiKey, (req, res) => {
  const result = PatchSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: 'invalid body', details: result.error.issues });
  }
  const updated = setSensorMeta(req.params.sensor_id, result.data);
  res.json(updated);
});

// DELETE /api/v1/admin/sensors/:sensor_id — destructive, purges all
// events/assets/alerts/meta for this sensor_id. Frontend should confirm.
router.delete('/admin/sensors/:sensor_id', requireApiKey, (req, res) => {
  try {
    const result = purgeSensor(req.params.sensor_id);
    res.json({ purged: true, ...result });
  } catch (err) {
    console.error('[admin] failed to purge sensor:', err);
    res.status(500).json({ error: 'failed to purge sensor' });
  }
});

module.exports = router;
