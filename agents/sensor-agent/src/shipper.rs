//! Ships batches of events/assets to the team's backend ingest API (JSON
//! array POST to /api/v1/events and /api/v1/assets, ApiKey auth) — NOT
//! directly to Elasticsearch.
//! Buffers in memory and flushes on size or time threshold, whichever
//! comes first; a shipper failure logs and drops the batch rather than
//! blocking the capture pipeline (a passive sensor must never backpressure
//! into dropping *packets* because the backend is briefly unreachable).

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use tracing::{error, info};

use crate::config::BackendConfig;

pub struct BackendShipper {
    client: Client,
    cfg: BackendConfig,
}

impl BackendShipper {
    pub fn new(cfg: BackendConfig) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(!cfg.verify_tls)
            .build()
            .context("building HTTP client")?;
        Ok(Self { client, cfg })
    }

    /// POST a JSON array of `docs` to `{base_url}{path}` (path is
    /// "/api/v1/events" or "/api/v1/assets" — a JSON array body,
    /// `Authorization: ApiKey <key>` header, any 2xx = success).
    /// No retry on failure: the caller drops the batch (see module docs).
    pub async fn post_batch<T: Serialize>(&self, path: &str, docs: &[T]) -> Result<()> {
        if docs.is_empty() {
            return Ok(());
        }

        let url = format!("{}{}", self.cfg.url.trim_end_matches('/'), path);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("ApiKey {}", self.cfg.api_key))
            .json(docs)
            .send()
            .await
            .with_context(|| format!("sending batch to {url}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            error!(%status, url, "ingest API rejected batch: {text}");
            anyhow::bail!("ingest API at {url} returned status {status}");
        }

        info!(url, count = docs.len(), "shipped batch to backend");
        Ok(())
    }
}
