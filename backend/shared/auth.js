// Auth middleware: requires "Authorization: ApiKey <key>" matching the
// configured MEDWATCH_API_KEY. Hackathon-simple — one shared static key,
// no per-sensor keys, no rotation. This is the sensor agent's entire auth
// surface (see agents/sensor-agent/src/shipper.rs), so don't change the
// header shape without updating the agent's config/code too.
const { config } = require('../shared/config');

const PREFIX = 'ApiKey ';

function requireApiKey(req, res, next) {
  const header = req.get('Authorization') || '';
  if (!header.startsWith(PREFIX)) {
    return res.status(401).json({ error: 'missing or malformed Authorization header, expected "ApiKey <key>"' });
  }
  const key = header.slice(PREFIX.length);
  if (key !== config.apiKey) {
    return res.status(401).json({ error: 'invalid API key' });
  }
  next();
}

module.exports = { requireApiKey };
