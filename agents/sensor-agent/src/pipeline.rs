//! Turns raw captured packets into (1) network events and (2) an
//! in-memory asset table, doing lightweight application-protocol
//! identification along the way (DICOM, HL7, and port-based well-knowns).

use chrono::{TimeZone, Utc};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::capture::CapturedPacket;
use crate::events::{ApplicationProtocol, AssetRecord, NetworkEvent};
use medwatch_fingerprinting::{classify, TcpSignature};

/// Per-asset accumulator, keyed by MAC (or IP string if MAC unavailable).
/// Flushed to `AssetRecord`s on the configured interval, not per packet.
#[derive(Debug, Default)]
pub struct AssetTable {
    assets: HashMap<String, AssetAccumulator>,
}

#[derive(Debug)]
struct AssetAccumulator {
    mac_address: Option<String>,
    ip_addresses: std::collections::BTreeSet<IpAddr>,
    observed_ports: std::collections::BTreeSet<u16>,
    observed_protocols: std::collections::BTreeSet<String>,
    os_guess: String,
    device_identity_hint: Option<String>,
    first_seen_micros: i64,
    last_seen_micros: i64,
}

fn identify_application_protocol(packet: &CapturedPacket) -> ApplicationProtocol {
    if !packet.raw_payload.is_empty() {
        if medwatch_proto_dicom::looks_like_dicom(&packet.raw_payload) {
            return ApplicationProtocol::Dicom;
        }
        if medwatch_proto_hl7::looks_like_hl7(&packet.raw_payload) {
            return ApplicationProtocol::Hl7;
        }
    }

    match (packet.src_port, packet.dst_port) {
        (Some(p), _) | (_, Some(p)) if medwatch_proto_dicom::DICOM_DEFAULT_PORTS.contains(&p) => {
            ApplicationProtocol::Dicom
        }
        (Some(p), _) | (_, Some(p)) if p == medwatch_proto_hl7::HL7_DEFAULT_PORT => {
            ApplicationProtocol::Hl7
        }
        (Some(80), _) | (_, Some(80)) => ApplicationProtocol::Http,
        (Some(443), _) | (_, Some(443)) => ApplicationProtocol::Https,
        (Some(53), _) | (_, Some(53)) => ApplicationProtocol::Dns,
        (Some(67), _) | (_, Some(67)) | (Some(68), _) | (_, Some(68)) => ApplicationProtocol::Dhcp,
        (Some(22), _) | (_, Some(22)) => ApplicationProtocol::Ssh,
        (Some(3389), _) | (_, Some(3389)) => ApplicationProtocol::Rdp,
        (Some(445), _) | (_, Some(445)) => ApplicationProtocol::Smb,
        _ => ApplicationProtocol::Unknown,
    }
}

fn protocol_metadata(
    packet: &CapturedPacket,
    app: &ApplicationProtocol,
) -> Option<serde_json::Value> {
    match app {
        ApplicationProtocol::Dicom => medwatch_proto_dicom::parse_associate_rq(&packet.raw_payload)
            .ok()
            .map(|rq| {
                serde_json::json!({
                    "called_ae_title": rq.called_ae_title,
                    "calling_ae_title": rq.calling_ae_title,
                    "protocol_version": rq.protocol_version,
                })
            }),
        ApplicationProtocol::Hl7 => {
            let inner: &[u8] =
                medwatch_proto_hl7::unwrap_mllp(&packet.raw_payload).unwrap_or(&packet.raw_payload);
            medwatch_proto_hl7::parse_msh(inner).ok().map(|msh| {
                serde_json::json!({
                    "sending_application": msh.sending_application,
                    "sending_facility": msh.sending_facility,
                    "receiving_application": msh.receiving_application,
                    "receiving_facility": msh.receiving_facility,
                    "message_type": msh.message_type,
                })
            })
        }
        _ => None,
    }
}

fn micros_to_datetime(micros: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_micros(micros)
        .single()
        .unwrap_or_else(Utc::now)
}

pub fn packet_to_event(packet: &CapturedPacket, sensor_id: &str) -> NetworkEvent {
    let application = identify_application_protocol(packet);
    let metadata = protocol_metadata(packet, &application);

    NetworkEvent {
        event_id: uuid::Uuid::new_v4(),
        sensor_id: sensor_id.to_string(),
        timestamp: micros_to_datetime(packet.timestamp_micros),
        src_ip: packet.src_ip,
        src_port: packet.src_port,
        src_mac: packet.src_mac.clone(),
        dst_ip: packet.dst_ip,
        dst_port: packet.dst_port,
        dst_mac: packet.dst_mac.clone(),
        transport: packet.transport.clone(),
        application,
        length_bytes: packet.total_len,
        protocol_metadata: metadata,
    }
}

impl AssetTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update asset state from one captured packet. Tracks the packet's
    /// source side as "the asset" (the side that sent traffic) — both
    /// directions get recorded across the lifetime of a flow since every
    /// packet's source gets visited eventually.
    pub fn observe(
        &mut self,
        packet: &CapturedPacket,
        application: &ApplicationProtocol,
        identity_hint: Option<String>,
    ) {
        let key = packet
            .src_mac
            .clone()
            .unwrap_or_else(|| packet.src_ip.to_string());

        let entry = self.assets.entry(key).or_insert_with(|| AssetAccumulator {
            mac_address: packet.src_mac.clone(),
            ip_addresses: Default::default(),
            observed_ports: Default::default(),
            observed_protocols: Default::default(),
            os_guess: "unknown".to_string(),
            device_identity_hint: None,
            first_seen_micros: packet.timestamp_micros,
            last_seen_micros: packet.timestamp_micros,
        });

        entry.ip_addresses.insert(packet.src_ip);
        if let Some(p) = packet.src_port {
            entry.observed_ports.insert(p);
        }
        if !matches!(application, ApplicationProtocol::Unknown) {
            entry
                .observed_protocols
                .insert(application.as_wire_str().to_string());
        }
        entry.last_seen_micros = entry.last_seen_micros.max(packet.timestamp_micros);
        entry.first_seen_micros = entry.first_seen_micros.min(packet.timestamp_micros);

        if identity_hint.is_some() {
            entry.device_identity_hint = identity_hint;
        }

        if packet.is_syn || packet.is_syn_ack {
            if let (Some(ttl), Some(window_size)) = (packet.ttl, packet.window_size) {
                let sig = TcpSignature {
                    initial_ttl: ttl,
                    window_size,
                    mss: None,
                    window_scale: None,
                    sack_permitted: false,
                    timestamps_present: false,
                    option_order: String::new(),
                    is_syn_ack: packet.is_syn_ack,
                };
                entry.os_guess = classify(&sig).as_str().to_string();
            }
        }
    }

    pub fn drain_to_records(&mut self, sensor_id: &str) -> Vec<AssetRecord> {
        self.assets
            .drain()
            .map(|(key, acc)| AssetRecord {
                asset_id: key,
                sensor_id: sensor_id.to_string(),
                last_seen: micros_to_datetime(acc.last_seen_micros),
                first_seen: micros_to_datetime(acc.first_seen_micros),
                mac_address: acc.mac_address,
                ip_addresses: acc.ip_addresses.into_iter().collect(),
                vendor_oui: None,
                os_guess: acc.os_guess,
                observed_ports: acc.observed_ports.into_iter().collect(),
                observed_protocols: acc.observed_protocols.into_iter().collect(),
                device_identity_hint: acc.device_identity_hint,
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }
}

pub fn extract_identity_hint(
    app: &ApplicationProtocol,
    metadata: &Option<serde_json::Value>,
) -> Option<String> {
    let meta = metadata.as_ref()?;
    match app {
        ApplicationProtocol::Dicom => meta
            .get("calling_ae_title")
            .and_then(|v| v.as_str())
            .map(String::from),
        ApplicationProtocol::Hl7 => meta
            .get("sending_application")
            .and_then(|v| v.as_str())
            .map(String::from),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TransportProtocol;
    use std::net::Ipv4Addr;

    fn tcp_packet(src_port: u16, dst_port: u16, is_syn: bool) -> CapturedPacket {
        CapturedPacket {
            timestamp_micros: 1_700_000_000_000_000,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            src_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            dst_mac: Some("11:22:33:44:55:66".to_string()),
            transport: TransportProtocol::Tcp,
            ttl: Some(64),
            window_size: Some(29200),
            is_syn,
            is_syn_ack: false,
            total_len: 60,
            raw_payload: vec![],
        }
    }

    #[test]
    fn identifies_dicom_by_default_port() {
        let p = tcp_packet(51000, 104, true);
        assert!(matches!(
            identify_application_protocol(&p),
            ApplicationProtocol::Dicom
        ));
    }

    #[test]
    fn identifies_hl7_by_default_port() {
        let p = tcp_packet(51000, 2575, false);
        assert!(matches!(
            identify_application_protocol(&p),
            ApplicationProtocol::Hl7
        ));
    }

    #[test]
    fn asset_table_accumulates_ports_and_protocols() {
        let mut table = AssetTable::new();
        let p1 = tcp_packet(51000, 104, true);
        let app1 = identify_application_protocol(&p1);
        table.observe(&p1, &app1, None);

        let mut p2 = tcp_packet(51001, 443, false);
        p2.src_mac = p1.src_mac.clone();
        let app2 = identify_application_protocol(&p2);
        table.observe(&p2, &app2, None);

        let records = table.drain_to_records("sensor-1");
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.observed_ports.len(), 2);
        assert!(rec.observed_protocols.contains(&"dicom".to_string()));
        assert!(rec.observed_protocols.contains(&"https".to_string()));
    }

    #[test]
    fn asset_table_drain_empties_table() {
        let mut table = AssetTable::new();
        let p = tcp_packet(51000, 104, true);
        let app = identify_application_protocol(&p);
        table.observe(&p, &app, None);
        assert!(!table.is_empty());
        let _ = table.drain_to_records("sensor-1");
        assert!(table.is_empty());
    }
}
