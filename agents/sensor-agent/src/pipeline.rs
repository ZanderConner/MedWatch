//! Turns raw captured packets into (1) network events and (2) an
//! in-memory asset table, doing lightweight application-protocol
//! identification along the way (DICOM, HL7, and port-based well-knowns).

use chrono::{TimeZone, Utc};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::capture::CapturedPacket;
use crate::events::{ApplicationProtocol, AssetRecord, NetworkEvent};
use medwatch_fingerprinting::{classify, TcpSignature};

/// Site-specific extra ports (beyond the protocol crates' IANA-standard
/// defaults) that should be treated as DICOM/HL7 for port-based fallback
/// classification. Built once from `CaptureConfig` at startup.
#[derive(Debug, Clone, Default)]
pub struct ProtocolPorts {
    pub dicom: Vec<u16>,
    pub hl7: Vec<u16>,
}

impl ProtocolPorts {
    pub fn new(extra_dicom: &[u16], extra_hl7: &[u16]) -> Self {
        Self {
            dicom: extra_dicom.to_vec(),
            hl7: extra_hl7.to_vec(),
        }
    }

    fn is_dicom_port(&self, port: u16) -> bool {
        medwatch_proto_dicom::DICOM_DEFAULT_PORTS.contains(&port) || self.dicom.contains(&port)
    }

    fn is_hl7_port(&self, port: u16) -> bool {
        port == medwatch_proto_hl7::HL7_DEFAULT_PORT || self.hl7.contains(&port)
    }
}

/// Normalized, direction-independent flow key: a TCP/UDP flow looks the
/// same whether we're looking at the request or the response side, so
/// both (ip,port) endpoints are sorted into a stable order.
type FlowKey = ((IpAddr, u16), (IpAddr, u16));

fn flow_key(packet: &CapturedPacket) -> Option<FlowKey> {
    let (sp, dp) = (packet.src_port?, packet.dst_port?);
    let a = (packet.src_ip, sp);
    let b = (packet.dst_ip, dp);
    Some(if a <= b { (a, b) } else { (b, a) })
}

/// Remembers which application protocol a flow (5-tuple, direction
/// ignored) was identified as, so every packet in that flow gets tagged
/// correctly even when only the FIRST packet (e.g. a DICOM
/// A-ASSOCIATE-RQ, an HL7 MSH segment) carries a payload signature or a
/// well-known port on that particular packet. Without this, a real
/// multi-packet DICOM/HL7 exchange showed up as one identified packet
/// plus a long tail of "unknown" data/ACK packets in the same flow —
/// the dominant real-world cause of traffic being flagged unknown.
/// Bounded (simple FIFO eviction) so a long-running sensor doesn't grow
/// this map unboundedly on a busy network.
#[derive(Debug)]
pub struct FlowClassifier {
    flows: HashMap<FlowKey, ApplicationProtocol>,
    order: VecDeque<FlowKey>,
    capacity: usize,
}

impl FlowClassifier {
    pub fn new(capacity: usize) -> Self {
        Self {
            flows: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Given a packet and what this packet's own header/port sniffing
    /// found, return the flow's actual application protocol: if this
    /// packet was itself identified, remember it for the rest of the
    /// flow; otherwise fall back to whatever the flow was already
    /// identified as (still Unknown if never identified).
    pub fn resolve(
        &mut self,
        packet: &CapturedPacket,
        sniffed: ApplicationProtocol,
    ) -> ApplicationProtocol {
        let Some(key) = flow_key(packet) else {
            return sniffed;
        };

        if !matches!(sniffed, ApplicationProtocol::Unknown) {
            if !self.flows.contains_key(&key) {
                if self.order.len() >= self.capacity {
                    if let Some(oldest) = self.order.pop_front() {
                        self.flows.remove(&oldest);
                    }
                }
                self.order.push_back(key);
            }
            self.flows.insert(key, sniffed.clone());
            return sniffed;
        }

        self.flows
            .get(&key)
            .cloned()
            .unwrap_or(ApplicationProtocol::Unknown)
    }
}

impl Default for FlowClassifier {
    fn default() -> Self {
        Self::new(50_000)
    }
}

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

fn identify_application_protocol(
    packet: &CapturedPacket,
    ports: &ProtocolPorts,
) -> ApplicationProtocol {
    if packet.is_arp {
        return ApplicationProtocol::Arp;
    }
    if matches!(packet.transport, crate::events::TransportProtocol::Icmp) {
        return ApplicationProtocol::Icmp;
    }

    if !packet.raw_payload.is_empty() {
        if medwatch_proto_dicom::looks_like_dicom(&packet.raw_payload) {
            return ApplicationProtocol::Dicom;
        }
        if medwatch_proto_hl7::looks_like_hl7(&packet.raw_payload) {
            return ApplicationProtocol::Hl7;
        }
        // Payload-based HTTP/TLS sniffing: catches REST/web traffic on
        // ANY port, not just the well-known 80/443/8080/8443 set below.
        // This matters a lot in this range — e.g. Orthanc's REST API
        // listens on 8042, which isn't a "standard" HTTP port, so a
        // radiology-workstation browsing it would otherwise always
        // fall through to Unknown regardless of the port table.
        if looks_like_http(&packet.raw_payload) {
            return ApplicationProtocol::Http;
        }
        if looks_like_tls(&packet.raw_payload) {
            return ApplicationProtocol::Https;
        }
    }

    match (packet.src_port, packet.dst_port) {
        (Some(p), _) | (_, Some(p)) if ports.is_dicom_port(p) => ApplicationProtocol::Dicom,
        (Some(p), _) | (_, Some(p)) if ports.is_hl7_port(p) => ApplicationProtocol::Hl7,
        (Some(80), _) | (_, Some(80)) | (Some(8080), _) | (_, Some(8080)) => {
            ApplicationProtocol::Http
        }
        (Some(443), _) | (_, Some(443)) | (Some(8443), _) | (_, Some(8443)) => {
            ApplicationProtocol::Https
        }
        (Some(53), _) | (_, Some(53)) => ApplicationProtocol::Dns,
        (Some(67), _) | (_, Some(67)) | (Some(68), _) | (_, Some(68)) => ApplicationProtocol::Dhcp,
        (Some(22), _) | (_, Some(22)) => ApplicationProtocol::Ssh,
        (Some(3389), _) | (_, Some(3389)) => ApplicationProtocol::Rdp,
        (Some(445), _) | (_, Some(445)) | (Some(139), _) | (_, Some(139)) => {
            ApplicationProtocol::Smb
        }
        (Some(123), _) | (_, Some(123)) => ApplicationProtocol::Ntp,
        (Some(161), _) | (_, Some(161)) | (Some(162), _) | (_, Some(162)) => {
            ApplicationProtocol::Snmp
        }
        (Some(5353), _) | (_, Some(5353)) => ApplicationProtocol::Mdns,
        (Some(389), _) | (_, Some(389)) | (Some(636), _) | (_, Some(636)) => {
            ApplicationProtocol::Ldap
        }
        (Some(514), _) | (_, Some(514)) => ApplicationProtocol::Syslog,
        (Some(20), _) | (_, Some(20)) | (Some(21), _) | (_, Some(21)) => ApplicationProtocol::Ftp,
        (Some(23), _) | (_, Some(23)) => ApplicationProtocol::Telnet,
        (Some(25), _) | (_, Some(25)) | (Some(587), _) | (_, Some(587)) => {
            ApplicationProtocol::Smtp
        }
        _ => ApplicationProtocol::Unknown,
    }
}

/// True if `buf` starts with an HTTP/1.x request or response line.
/// Deliberately checks a handful of exact method prefixes plus the
/// response line rather than a generic "looks textual" heuristic, to
/// avoid false-positiving on arbitrary ASCII protocol chatter (HL7,
/// SMTP, etc. are also mostly-printable-ASCII).
fn looks_like_http(buf: &[u8]) -> bool {
    const REQUEST_PREFIXES: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    if REQUEST_PREFIXES.iter().any(|p| buf.starts_with(p)) {
        return true;
    }
    buf.starts_with(b"HTTP/1.")
}

/// True if `buf` looks like the start of a TLS record (any version) —
/// used to classify HTTPS/TLS-wrapped traffic on non-standard ports.
/// TLS record header (RFC 8446 §5.1): 1 byte content type (0x14
/// change_cipher_spec, 0x15 alert, 0x16 handshake, 0x17
/// application_data), 2 bytes legacy version (0x03, 0x00-0x04), 2
/// bytes length. Checking the handshake type (0x16) covers the
/// ClientHello that starts every real TLS connection; the other
/// content types alone (without ever having seen a handshake in this
/// flow) are too weak a signal to classify on their own, so this
/// intentionally only fires on 0x16.
fn looks_like_tls(buf: &[u8]) -> bool {
    if buf.len() < 5 {
        return false;
    }
    buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x04
}

fn protocol_metadata(
    packet: &CapturedPacket,
    app: &ApplicationProtocol,
) -> Option<serde_json::Value> {
    match app {
        ApplicationProtocol::Dicom => {
            medwatch_proto_dicom::parse_associate_header(&packet.raw_payload)
                .ok()
                .map(|hdr| {
                    serde_json::json!({
                        "pdu_kind": match hdr.kind {
                            medwatch_proto_dicom::PduKind::AssociateRq => "associate_rq",
                            medwatch_proto_dicom::PduKind::AssociateAc => "associate_ac",
                        },
                        "called_ae_title": hdr.called_ae_title,
                        "calling_ae_title": hdr.calling_ae_title,
                        "protocol_version": hdr.protocol_version,
                    })
                })
        }
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

pub fn packet_to_event(
    packet: &CapturedPacket,
    sensor_id: &str,
    ports: &ProtocolPorts,
    flow_classifier: &mut FlowClassifier,
) -> NetworkEvent {
    let sniffed = identify_application_protocol(packet, ports);
    let application = flow_classifier.resolve(packet, sniffed);
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
                    mss: packet.mss,
                    window_scale: packet.window_scale,
                    sack_permitted: packet.sack_permitted,
                    timestamps_present: packet.timestamps_present,
                    option_order: packet.tcp_option_order.clone(),
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
        // A-ASSOCIATE-RQ: calling_ae_title identifies the SENDER (the
        // initiator, e.g. a CT/MRI modality). A-ASSOCIATE-AC:
        // called_ae_title is the RESPONDER's own AE title — an SCP only
        // accepts associations addressed to itself, so this field
        // reliably self-identifies devices like Orthanc that never
        // initiate an association and would otherwise never appear in a
        // captured RQ (see PduKind's docs in the dicom parser crate).
        // Both branches read the field belonging to whichever side SENT
        // this particular packet, which is what AssetTable.observe()
        // keys the identity hint against (packet.src_*).
        ApplicationProtocol::Dicom => match meta.get("pdu_kind").and_then(|v| v.as_str()) {
            Some("associate_ac") => meta
                .get("called_ae_title")
                .and_then(|v| v.as_str())
                .map(String::from),
            _ => meta
                .get("calling_ae_title")
                .and_then(|v| v.as_str())
                .map(String::from),
        },
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
            mss: None,
            window_scale: None,
            sack_permitted: false,
            timestamps_present: false,
            tcp_option_order: String::new(),
            total_len: 60,
            raw_payload: vec![],
            is_arp: false,
        }
    }

    #[test]
    fn identifies_dicom_by_default_port() {
        let p = tcp_packet(51000, 104, true);
        let ports = ProtocolPorts::default();
        assert!(matches!(
            identify_application_protocol(&p, &ports),
            ApplicationProtocol::Dicom
        ));
    }

    #[test]
    fn identifies_hl7_by_default_port() {
        let p = tcp_packet(51000, 2575, false);
        let ports = ProtocolPorts::default();
        assert!(matches!(
            identify_application_protocol(&p, &ports),
            ApplicationProtocol::Hl7
        ));
    }

    #[test]
    fn identifies_dicom_by_site_specific_extra_port() {
        // Regression: a real deployment (this demo range's dicom-simulator
        // <-> orthanc traffic) uses port 4242, not the IANA-standard
        // 104/11112 — without the configurable extra-ports list this
        // falls straight through to Unknown.
        let p = tcp_packet(51000, 4242, true);
        let ports = ProtocolPorts::new(&[4242], &[]);
        assert!(matches!(
            identify_application_protocol(&p, &ports),
            ApplicationProtocol::Dicom
        ));
    }

    #[test]
    fn identifies_http_by_payload_on_a_non_standard_port() {
        // Regression: this demo range's Orthanc REST API listens on
        // 8042, not 80/8080 — before payload sniffing was added, this
        // traffic silently fell through to Unknown regardless of what
        // was actually in the payload, which is what made a big chunk
        // of the Traffic Analytics page show as "unknown" instead of
        // HTTP.
        let mut p = tcp_packet(55740, 8042, true);
        p.raw_payload = b"GET /system HTTP/1.1\r\nHost: 10.20.70.10:8042\r\n\r\n".to_vec();
        let ports = ProtocolPorts::default();
        assert!(matches!(
            identify_application_protocol(&p, &ports),
            ApplicationProtocol::Http
        ));
    }

    #[test]
    fn identifies_https_by_tls_handshake_payload_on_a_non_standard_port() {
        let mut p = tcp_packet(55741, 8443, true);
        // TLS record header: handshake (0x16), version 3.3 (TLS 1.2 wire
        // version, used even for TLS 1.3 ClientHellos), arbitrary length.
        p.raw_payload = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        let ports = ProtocolPorts::default();
        assert!(matches!(
            identify_application_protocol(&p, &ports),
            ApplicationProtocol::Https
        ));
    }

    #[test]
    fn falls_back_to_unknown_for_non_http_non_tls_payload_on_unrecognized_port() {
        let mut p = tcp_packet(55742, 9999, true);
        p.raw_payload = vec![0xde, 0xad, 0xbe, 0xef];
        let ports = ProtocolPorts::default();
        assert!(matches!(
            identify_application_protocol(&p, &ports),
            ApplicationProtocol::Unknown
        ));
    }

    #[test]
    fn flow_classifier_tags_whole_flow_from_first_identified_packet() {
        // Regression: only the first packet of a real exchange (the DICOM
        // A-ASSOCIATE-RQ / HL7 MSH) carries a recognizable signature or
        // lands on the flow's canonical port on that packet — every other
        // packet in the SAME flow (ACKs, data PDVs, the reply) was
        // previously mis-tagged Unknown because it was judged in
        // isolation. The classifier should remember the flow's protocol
        // once identified and apply it to every subsequent packet on
        // either side of that flow.
        let mut classifier = FlowClassifier::new(10);
        let ports = ProtocolPorts::default();

        // First packet: recognizable DICOM port, gets identified.
        let p1 = tcp_packet(51000, 104, true);
        let app1 = identify_application_protocol(&p1, &ports);
        assert!(matches!(
            classifier.resolve(&p1, app1),
            ApplicationProtocol::Dicom
        ));

        // Second packet: same flow, reply direction (both IP and port
        // swapped, as a real response packet would be) — simulate a
        // mid-flow data/ACK packet with no payload signature of its own
        // (pass Unknown directly, as the pipeline's own sniff would
        // produce for a packet whose payload doesn't start with a
        // recognizable header). Should still resolve to Dicom via the
        // flow's remembered classification, not this packet's own port.
        let mut p2 = tcp_packet(104, 51000, false);
        p2.src_ip = p1.dst_ip;
        p2.dst_ip = p1.src_ip;
        p2.raw_payload = vec![];
        assert!(matches!(
            classifier.resolve(&p2, ApplicationProtocol::Unknown),
            ApplicationProtocol::Dicom
        ));
    }

    #[test]
    fn asset_table_accumulates_ports_and_protocols() {
        let mut table = AssetTable::new();
        let ports = ProtocolPorts::default();
        let p1 = tcp_packet(51000, 104, true);
        let app1 = identify_application_protocol(&p1, &ports);
        table.observe(&p1, &app1, None);

        let mut p2 = tcp_packet(51001, 443, false);
        p2.src_mac = p1.src_mac.clone();
        let app2 = identify_application_protocol(&p2, &ports);
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
        let ports = ProtocolPorts::default();
        let p = tcp_packet(51000, 104, true);
        let app = identify_application_protocol(&p, &ports);
        table.observe(&p, &app, None);
        assert!(!table.is_empty());
        let _ = table.drain_to_records("sensor-1");
        assert!(table.is_empty());
    }
}
