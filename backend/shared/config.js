// Shared runtime configuration, read from env vars (never hardcoded).
// See .env.example at the repo backend/ root for the full list.
require('dotenv').config();

function required(name, fallback) {
  const v = process.env[name];
  if (v !== undefined && v !== '') return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`missing required env var: ${name}`);
}

const config = {
  port: Number(process.env.PORT || 8080),
  // Static shared API key the sensor agent sends as
  // "Authorization: ApiKey <key>". Hackathon-simple: one shared key,
  // no per-sensor keys, no rotation. Must be set via env, never
  // committed — see backend/.env.example.
  apiKey: required('MEDWATCH_API_KEY', 'change-me'),
  // SQLite file path. ":memory:" is fine for a quick demo but loses all
  // data on restart; a file path persists across restarts.
  dbPath: process.env.MEDWATCH_DB_PATH || './data/medwatch.sqlite',
  // Max array length accepted per ingest POST, just a sanity guard
  // against a misbehaving/misconfigured sensor sending a huge batch.
  maxBatchSize: Number(process.env.MEDWATCH_MAX_BATCH_SIZE || 5000),
};

module.exports = { config };
