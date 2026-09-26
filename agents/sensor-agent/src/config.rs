//! Sensor configuration: CLI flags override a TOML config file.

use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "medwatch-sensor",
    version,
    about = "MedWatch passive network sensor agent"
)]
pub struct Cli {
    /// Path to sensor-agent.toml config file.
    #[arg(short, long, default_value = "sensor-agent.toml")]
    pub config: PathBuf,

    /// Network interface to capture on (overrides config file).
    #[arg(short, long)]
    pub interface: Option<String>,

    /// List available capture interfaces and exit.
    #[arg(long)]
    pub list_interfaces: bool,

    /// Run capture/parsing/fingerprinting but do not ship events anywhere
    /// (prints counts to stdout instead). Useful for a first run on a new
    /// sensor before pointing it at the production backend.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub sensor: SensorConfig,
    pub capture: CaptureConfig,
    pub backend: BackendConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SensorConfig {
    /// Stable identifier for this sensor, stamped on every event/asset doc.
    /// Defaults to the machine hostname if left unset.
    pub id: Option<String>,
    pub site: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureConfig {
    pub interface: String,
    #[serde(default = "default_snaplen")]
    pub snaplen: i32,
    #[serde(default = "default_true")]
    pub promiscuous: bool,
    /// BPF filter applied at the kernel/Npcap level, e.g. "not port 22" to
    /// exclude the sensor's own management traffic.
    #[serde(default)]
    pub bpf_filter: Option<String>,
    #[serde(default = "default_asset_flush_secs")]
    pub asset_flush_interval_secs: u64,
    /// Extra TCP/UDP ports (beyond the protocol crates' built-in defaults
    /// 104/11112 for DICOM, 2575 for HL7) that carry DICOM on THIS site's
    /// network — many real deployments (and this demo range's simulators)
    /// don't use the IANA-registered ports. Without this, port-based
    /// fallback classification only ever matches the standard ports and
    /// everything else on a non-standard port falls through to "unknown"
    /// even when payload sniffing also can't run (e.g. a mid-flow data
    /// packet with no recognizable header of its own).
    #[serde(default)]
    pub dicom_ports: Vec<u16>,
    /// Same idea as `dicom_ports`, for HL7 (beyond the built-in default 2575).
    #[serde(default)]
    pub hl7_ports: Vec<u16>,
}

/// Points at the team's backend ingest API, NOT Elasticsearch directly.
/// The agent POSTs JSON arrays of events/assets to `{url}/api/v1/events`
/// and `{url}/api/v1/assets` with an `Authorization: ApiKey <key>` header.
#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    /// Base URL of the ingest API, e.g. "https://medwatch-backend.example:8443".
    pub url: String,
    /// Shared static API key, sent as `Authorization: ApiKey <key>`.
    pub api_key: String,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

fn default_snaplen() -> i32 {
    262144
}
fn default_true() -> bool {
    true
}
fn default_asset_flush_secs() -> u64 {
    60
}
fn default_batch_size() -> usize {
    500
}
fn default_flush_interval_secs() -> u64 {
    5
}

impl Config {
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parsing config {}: {e}", path.display()))?;
        Ok(cfg)
    }

    pub fn resolved_sensor_id(&self) -> String {
        self.sensor.id.clone().unwrap_or_else(|| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown-sensor".to_string())
        })
    }
}
