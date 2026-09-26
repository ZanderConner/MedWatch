//! Wire-format event and asset document types POSTed to the backend
//! ingest API (JSON array to /api/v1/events and /api/v1/assets) — NOT
//! Elasticsearch directly. Kept in one module so the API's JSON shape
//! (see schemas/events, schemas/asset at the repo root) has one Rust
//! source of truth to stay in sync with.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationProtocol {
    Dicom,
    Hl7,
    Http,
    Https,
    Dns,
    Dhcp,
    Ssh,
    Rdp,
    Smb,
    Arp,
    Icmp,
    Ntp,
    Snmp,
    Mdns,
    Ldap,
    Syslog,
    Ftp,
    Telnet,
    Smtp,
    Unknown,
}

impl ApplicationProtocol {
    /// The exact wire string this variant serializes to (matches the
    /// `#[serde(rename_all = "snake_case")]` on this enum). Used wherever
    /// code needs the string form without round-tripping through JSON —
    /// deliberately not `Debug`+`to_lowercase()`, which only coincidentally
    /// matches snake_case for single-word variant names and would silently
    /// diverge if a multi-word variant were ever added.
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            ApplicationProtocol::Dicom => "dicom",
            ApplicationProtocol::Hl7 => "hl7",
            ApplicationProtocol::Http => "http",
            ApplicationProtocol::Https => "https",
            ApplicationProtocol::Dns => "dns",
            ApplicationProtocol::Dhcp => "dhcp",
            ApplicationProtocol::Ssh => "ssh",
            ApplicationProtocol::Rdp => "rdp",
            ApplicationProtocol::Smb => "smb",
            ApplicationProtocol::Arp => "arp",
            ApplicationProtocol::Icmp => "icmp",
            ApplicationProtocol::Ntp => "ntp",
            ApplicationProtocol::Snmp => "snmp",
            ApplicationProtocol::Mdns => "mdns",
            ApplicationProtocol::Ldap => "ldap",
            ApplicationProtocol::Syslog => "syslog",
            ApplicationProtocol::Ftp => "ftp",
            ApplicationProtocol::Telnet => "telnet",
            ApplicationProtocol::Smtp => "smtp",
            ApplicationProtocol::Unknown => "unknown",
        }
    }
}

/// One observed flow-level event: a single packet that advanced sensor
/// state (new flow, protocol identified, TLS/HL7/DICOM handshake seen,
/// etc). This is the raw telemetry POSTed to the backend's events endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub event_id: uuid::Uuid,
    pub sensor_id: String,
    #[serde(rename = "@timestamp")]
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub src_port: Option<u16>,
    pub src_mac: Option<String>,
    pub dst_ip: IpAddr,
    pub dst_port: Option<u16>,
    pub dst_mac: Option<String>,
    pub transport: TransportProtocol,
    pub application: ApplicationProtocol,
    pub length_bytes: u32,
    /// Populated only for DICOM associations / HL7 MSH segments; deliberately
    /// excludes any patient-identifying payload fields.
    pub protocol_metadata: Option<serde_json::Value>,
}

/// A passively discovered network asset, keyed by MAC (falls back to IP for
/// routed/off-segment hosts where the MAC is actually the last-hop router's).
/// Upserted via the backend's assets endpoint on a debounce interval, not
/// per-packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRecord {
    pub asset_id: String,
    pub sensor_id: String,
    #[serde(rename = "@timestamp")]
    pub last_seen: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub vendor_oui: Option<String>,
    pub os_guess: String,
    pub observed_ports: Vec<u16>,
    pub observed_protocols: Vec<String>,
    /// e.g. DICOM AE title or HL7 sending application, when observed.
    pub device_identity_hint: Option<String>,
}
