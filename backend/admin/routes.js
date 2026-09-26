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
const {
  listAssetsAdmin,
  createManualAsset,
  updateAsset,
  deleteAsset,
} = require('./assets');
const { OS_GUESSES } = require('../shared/schemas');

const router = express.Router();

const PatchSchema = z.object({
  label: z.string().max(200).nullable().optional(),
  notes: z.string().max(2000).nullable().optional(),
  retired: z.boolean().optional(),
});

const ManualAssetSchema = z.object({
  asset_id: z.string().min(1).optional(),
  device_identity_hint: z.string().min(1).max(200),
  ip_addresses: z.array(z.string()).optional(),
  mac_address: z.string().nullable().optional(),
  os_guess: z.enum(OS_GUESSES).optional(),
  observed_ports: z.array(z.number().int().min(0).max(65535)).optional(),
  observed_protocols: z.array(z.string()).optional(),
});

const AssetPatchSchema = z.object({
  confirmed: z.boolean().optional(),
  device_identity_hint: z.string().max(200).nullable().optional(),
  os_guess: z.enum(OS_GUESSES).optional(),
  ip_addresses: z.array(z.string()).optional(),
  mac_address: z.string().nullable().optional(),
  notes: z.string().max(2000).nullable().optional(),
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

// GET /api/v1/admin/assets?confirmed=true|false — Asset Inventory page:
// every asset (agent-discovered and manual), or just one confirm-state
// bucket ("Confirmed inventory" vs "Pending confirmation").
router.get('/admin/assets', requireApiKey, (req, res) => {
  let confirmed;
  if (req.query.confirmed === 'true') confirmed = true;
  else if (req.query.confirmed === 'false') confirmed = false;
  res.json({ assets: listAssetsAdmin({ confirmed }) });
});

// POST /api/v1/admin/assets — manually add an asset the agent hasn't
// discovered (or can't, e.g. an air-gapped device). Always created
// already-confirmed since an admin typed it in directly.
router.post('/admin/assets', requireApiKey, (req, res) => {
  const result = ManualAssetSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: 'invalid body', details: result.error.issues });
  }
  const created = createManualAsset(result.data);
  if (created.error) {
    return res.status(409).json(created);
  }
  res.status(201).json(created.asset);
});

// PATCH /api/v1/admin/assets/:asset_id  body: { confirmed?, device_identity_hint? }
// The primary "confirm a discovered asset" action, plus letting an
// admin name/relabel an auto-discovered device.
router.patch('/admin/assets/:asset_id', requireApiKey, (req, res) => {
  const result = AssetPatchSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: 'invalid body', details: result.error.issues });
  }
  const updated = updateAsset(req.params.asset_id, result.data);
  if (!updated) {
    return res.status(404).json({ error: 'asset not found' });
  }
  res.json(updated);
});

// DELETE /api/v1/admin/assets/:asset_id — removes the asset row. Note:
// if this asset is still actively transmitting, the agent will
// rediscover and re-insert it (unconfirmed) on its next sighting — this
// isn't a permanent block-list, just a "remove from the current list".
router.delete('/admin/assets/:asset_id', requireApiKey, (req, res) => {
  const deleted = deleteAsset(req.params.asset_id);
  if (!deleted) {
    return res.status(404).json({ error: 'asset not found' });
  }
  res.json({ deleted: true });
});

module.exports = router;
