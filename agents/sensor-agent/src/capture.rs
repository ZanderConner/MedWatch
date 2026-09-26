//! Live capture loop over libpcap (Linux) / Npcap (Windows) via the `pcap`
//! crate, parsed with `etherparse`. Runs synchronously in a dedicated
//! std::thread (libpcap's blocking capture loop doesn't play well with
//! async), forwarding parsed packets to the async pipeline over a channel.

use anyhow::{Context, Result};
use etherparse::{LinkHeader, NetHeaders, PacketHeaders, TcpOptionElement, TransportHeader};
use pcap::{Capture, Device, Linktype};
use std::net::IpAddr;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::events::TransportProtocol;

/// A parsed packet handed off from the capture thread to the async pipeline.
/// Intentionally holds only header fields, not the payload, to keep the
/// channel cheap — application-layer parsers get the raw payload separately
/// via `raw_payload` only when a dispatcher decides it's worth inspecting.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub timestamp_micros: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub transport: TransportProtocol,
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
    pub is_syn: bool,
    pub is_syn_ack: bool,
    /// TCP maximum-segment-size option, when present. `None` for non-TCP
    /// packets or a TCP packet that carried no MSS option.
    pub mss: Option<u16>,
    /// TCP window-scale option value, when present.
    pub window_scale: Option<u8>,
    /// True if the SACK-permitted option was present.
    pub sack_permitted: bool,
    /// True if the timestamps option was present.
    pub timestamps_present: bool,
    /// Options in the order they appeared on the wire, e.g.
    /// "MSS,SACK,TS,NOP,WS" — used by the passive OS fingerprinter
    /// alongside TTL/window size (see `medwatch_fingerprinting::classify`).
    /// Empty for non-TCP packets.
    pub tcp_option_order: String,
    pub total_len: u32,
    pub raw_payload: Vec<u8>,
    /// Set for ARP request/reply frames (Ethernet/IPv4 ARP only — the
    /// vast majority of what's seen on a real LAN). `src_ip`/`dst_ip`
    /// carry the ARP sender/target protocol addresses in this case;
    /// `src_port`/`dst_port` are always None and `transport` is
    /// `Other`, since ARP has no L4 concept of ports. Kept as a flag on
    /// the same struct (rather than a separate packet type) so the rest
    /// of the pipeline — flow keys, asset observation, event shipping —
    /// doesn't need a second code path.
    pub is_arp: bool,
}

/// Parse an Ethernet/IPv4 ARP packet's payload (the 28 bytes after the
/// 14-byte Ethernet header + 2-byte ethertype): hw_type(2) proto_type(2)
/// hw_len(1) proto_len(1) opcode(2) sender_mac(6) sender_ip(4)
/// target_mac(6) target_ip(4). Returns None for anything that isn't a
/// standard Ethernet/IPv4 ARP frame (hw_len=6, proto_len=4) — other ARP
/// hardware/protocol combinations are vanishingly rare on a real LAN
/// and not worth the extra complexity here.
fn parse_arp_payload(payload: &[u8]) -> Option<(IpAddr, IpAddr)> {
    if payload.len() < 28 {
        return None;
    }
    let hw_len = payload[4];
    let proto_len = payload[5];
    if hw_len != 6 || proto_len != 4 {
        return None;
    }
    let sender_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        payload[14],
        payload[15],
        payload[16],
        payload[17],
    ));
    let target_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        payload[24],
        payload[25],
        payload[26],
        payload[27],
    ));
    Some((sender_ip, target_ip))
}

fn arp_captured_packet(
    payload: &[u8],
    src_mac: Option<String>,
    dst_mac: Option<String>,
    frame_len: usize,
    timestamp_micros: i64,
) -> Option<CapturedPacket> {
    let (src_ip, dst_ip) = parse_arp_payload(payload)?;
    Some(CapturedPacket {
        timestamp_micros,
        src_ip,
        dst_ip,
        src_port: None,
        dst_port: None,
        src_mac,
        dst_mac,
        transport: TransportProtocol::Other,
        ttl: None,
        window_size: None,
        is_syn: false,
        is_syn_ack: false,
        mss: None,
        window_scale: None,
        sack_permitted: false,
        timestamps_present: false,
        tcp_option_order: String::new(),
        total_len: frame_len as u32,
        raw_payload: payload.to_vec(),
        is_arp: true,
    })
}

const ETHERTYPE_ARP: u16 = 0x0806;

pub fn list_interfaces() -> Result<Vec<Device>> {
    Device::list().context("listing capture devices (are you root/Administrator?)")
}

fn mac_to_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse one raw ethernet frame into a `CapturedPacket`, or None for
/// non-IP / unparseable frames (ARP, STP, malformed, etc — still useful for
/// asset discovery via ARP in a future pass, but out of scope here).
pub fn parse_frame(data: &[u8], timestamp_micros: i64) -> Option<CapturedPacket> {
    // Ethernet header is 14 bytes (6 dst mac + 6 src mac + 2 ethertype);
    // check the ethertype directly for ARP before handing off to
    // etherparse's IP-oriented parser, which has no ARP support.
    if data.len() >= 14 {
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype == ETHERTYPE_ARP {
            let src_mac = Some(mac_to_string([
                data[6], data[7], data[8], data[9], data[10], data[11],
            ]));
            let dst_mac = Some(mac_to_string([
                data[0], data[1], data[2], data[3], data[4], data[5],
            ]));
            if let Some(pkt) =
                arp_captured_packet(&data[14..], src_mac, dst_mac, data.len(), timestamp_micros)
            {
                return Some(pkt);
            }
        }
    }

    let headers = match PacketHeaders::from_ethernet_slice(data) {
        Ok(h) => h,
        Err(e) => {
            debug!("unparseable frame ({} bytes): {e}", data.len());
            return None;
        }
    };

    let (src_mac, dst_mac) = match &headers.link {
        Some(LinkHeader::Ethernet2(eth)) => (
            Some(mac_to_string(eth.source)),
            Some(mac_to_string(eth.destination)),
        ),
        _ => (None, None),
    };

    build_captured_packet(
        headers.net,
        headers.transport,
        headers.payload.slice(),
        src_mac,
        dst_mac,
        data.len(),
        timestamp_micros,
    )
}

/// Parse one Linux "cooked capture" (DLT_LINUX_SLL) frame, as produced by
/// the pcap pseudo-interface "any" — used when a host has multiple NICs
/// and no single one is known to carry the traffic of interest. SLL has
/// no destination MAC (the frame was never actually on that wire as
/// Ethernet) and a different fixed 16-byte header, so it needs its own
/// parse path rather than reusing `from_ethernet_slice`.
fn parse_sll_frame(data: &[u8], timestamp_micros: i64) -> Option<CapturedPacket> {
    // SLL header (RFC-less, but stable/standard libpcap layout), 16 bytes:
    //   2B packet type, 2B ARPHRD_* link type, 2B addr len, 8B addr
    //   (only the first `addr_len` bytes are meaningful), 2B ethertype.
    if data.len() < 16 {
        debug!("SLL frame too short ({} bytes)", data.len());
        return None;
    }
    let addr_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let src_mac = if addr_len == 6 {
        Some(mac_to_string([
            data[6], data[7], data[8], data[9], data[10], data[11],
        ]))
    } else {
        None
    };
    // SLL carries no destination MAC — the "any" pseudo-interface can't
    // know it (frames from many real interfaces are being merged here).
    let ether_type = u16::from_be_bytes([data[14], data[15]]);
    let inner = &data[16..];

    if ether_type == ETHERTYPE_ARP {
        if let Some(pkt) =
            arp_captured_packet(inner, src_mac.clone(), None, data.len(), timestamp_micros)
        {
            return Some(pkt);
        }
    }

    let headers = match PacketHeaders::from_ether_type(etherparse::EtherType(ether_type), inner) {
        Ok(h) => h,
        Err(e) => {
            debug!("unparseable SLL payload ({} bytes): {e}", inner.len());
            return None;
        }
    };

    build_captured_packet(
        headers.net,
        headers.transport,
        headers.payload.slice(),
        src_mac,
        None,
        data.len(),
        timestamp_micros,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_captured_packet(
    net: Option<NetHeaders>,
    transport_hdr: Option<TransportHeader>,
    payload: &[u8],
    src_mac: Option<String>,
    dst_mac: Option<String>,
    frame_len: usize,
    timestamp_micros: i64,
) -> Option<CapturedPacket> {
    let (src_ip, dst_ip, ttl) = match &net {
        Some(NetHeaders::Ipv4(ip, _)) => (
            IpAddr::V4(ip.source.into()),
            IpAddr::V4(ip.destination.into()),
            Some(ip.time_to_live),
        ),
        Some(NetHeaders::Ipv6(ip, _)) => (
            IpAddr::V6(ip.source.into()),
            IpAddr::V6(ip.destination.into()),
            Some(ip.hop_limit),
        ),
        _ => return None, // not IP (ARP etc) — skip for now
    };

    let mut src_port = None;
    let mut dst_port = None;
    let mut window_size = None;
    let mut is_syn = false;
    let mut is_syn_ack = false;
    let mut transport = TransportProtocol::Other;
    let mut mss = None;
    let mut window_scale = None;
    let mut sack_permitted = false;
    let mut timestamps_present = false;
    let mut tcp_option_order = String::new();

    match &transport_hdr {
        Some(TransportHeader::Tcp(tcp)) => {
            transport = TransportProtocol::Tcp;
            src_port = Some(tcp.source_port);
            dst_port = Some(tcp.destination_port);
            window_size = Some(tcp.window_size);
            is_syn = tcp.syn && !tcp.ack;
            is_syn_ack = tcp.syn && tcp.ack;

            // Only worth decoding options for the packets the passive OS
            // fingerprinter actually looks at (SYN/SYN-ACK) — parsing every
            // data packet's options would be wasted work on the hot path.
            if is_syn || is_syn_ack {
                let mut order_parts = Vec::new();
                for opt in tcp.options_iterator() {
                    match opt {
                        Ok(TcpOptionElement::MaximumSegmentSize(v)) => {
                            mss = Some(v);
                            order_parts.push("MSS");
                        }
                        Ok(TcpOptionElement::WindowScale(v)) => {
                            window_scale = Some(v);
                            order_parts.push("WS");
                        }
                        Ok(TcpOptionElement::SelectiveAcknowledgementPermitted) => {
                            sack_permitted = true;
                            order_parts.push("SACK");
                        }
                        Ok(TcpOptionElement::Timestamp(_, _)) => {
                            timestamps_present = true;
                            order_parts.push("TS");
                        }
                        Ok(TcpOptionElement::Noop) => order_parts.push("NOP"),
                        // A malformed/unrecognized option ends decoding for
                        // the rest of this header — same as p0f, since option
                        // boundaries can't be trusted past that point.
                        Ok(TcpOptionElement::SelectiveAcknowledgement(_, _)) | Err(_) => break,
                    }
                }
                tcp_option_order = order_parts.join(",");
            }
        }
        Some(TransportHeader::Udp(udp)) => {
            transport = TransportProtocol::Udp;
            src_port = Some(udp.source_port);
            dst_port = Some(udp.destination_port);
        }
        Some(TransportHeader::Icmpv4(_)) | Some(TransportHeader::Icmpv6(_)) => {
            transport = TransportProtocol::Icmp;
        }
        None => {}
    }

    Some(CapturedPacket {
        timestamp_micros,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        src_mac,
        dst_mac,
        transport,
        ttl,
        window_size,
        is_syn,
        is_syn_ack,
        mss,
        window_scale,
        sack_permitted,
        timestamps_present,
        tcp_option_order,
        total_len: frame_len as u32,
        raw_payload: payload.to_vec(),
        is_arp: false,
    })
}

/// Blocking capture loop. Intended to run on `tokio::task::spawn_blocking`
/// or a dedicated `std::thread`. Sends every parsed packet down `tx`;
/// drops (with a debug log) anything that fails to parse or if the
/// receiver has already shut down.
pub fn run_capture_loop(
    interface: &str,
    snaplen: i32,
    promiscuous: bool,
    bpf_filter: Option<&str>,
    tx: mpsc::Sender<CapturedPacket>,
) -> Result<()> {
    let device = Device::list()
        .context("listing capture devices")?
        .into_iter()
        .find(|d| d.name == interface)
        .with_context(|| format!("interface '{interface}' not found; use --list-interfaces"))?;

    let mut cap = Capture::from_device(device)
        .context("opening capture device")?
        .snaplen(snaplen)
        .promisc(promiscuous)
        .immediate_mode(true)
        .open()
        .context("starting capture (need root/Administrator + capture privileges)")?;

    if let Some(filter) = bpf_filter {
        cap.filter(filter, true)
            .with_context(|| format!("compiling BPF filter '{filter}'"))?;
    }

    // The "any" pseudo-interface (and some virtual/tunnel devices) emit
    // Linux "cooked capture" (SLL) frames instead of real Ethernet — a
    // different fixed header with no destination MAC. A single real NIC
    // interface always uses DLT_EN10MB (Ethernet). Pick the right parser
    // once up front rather than per-packet.
    let linktype = cap.get_datalink();
    let is_cooked = linktype == Linktype::LINUX_SLL;
    if is_cooked {
        info!(
            interface,
            ?linktype,
            "cooked-capture (SLL) link type detected"
        );
    }

    info!(interface, promiscuous, bpf_filter, "capture started");

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                // pcap's timeval fields are i64 on Linux/glibc but i32 on
                // Windows; `as i64` is a real widening conversion on one
                // platform and a same-type no-op on the other, so clippy's
                // unnecessary_cast fires depending which target we're on.
                #[allow(clippy::unnecessary_cast)]
                let ts_micros =
                    packet.header.ts.tv_sec as i64 * 1_000_000 + packet.header.ts.tv_usec as i64;
                let parsed = if is_cooked {
                    parse_sll_frame(packet.data, ts_micros)
                } else {
                    parse_frame(packet.data, ts_micros)
                };
                if let Some(parsed) = parsed {
                    if tx.blocking_send(parsed).is_err() {
                        warn!("pipeline receiver closed, stopping capture loop");
                        return Ok(());
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                warn!("capture error: {e}");
                return Err(e.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal SLL (DLT_LINUX_SLL) frame wrapping an IPv4/UDP
    /// packet, matching the wire format produced by pcap's "any"
    /// pseudo-interface (verified against a live capture in the range).
    fn sll_ipv4_udp_frame(src_mac: [u8; 6]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&0u16.to_be_bytes()); // packet type: incoming
        frame.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
        frame.extend_from_slice(&6u16.to_be_bytes()); // addr len
        frame.extend_from_slice(&src_mac); // 6 bytes address
        frame.extend_from_slice(&[0u8, 0u8]); // pad to 8-byte address field
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype: IPv4

        // Minimal IPv4 header (20 bytes, no options) + UDP header (8 bytes)
        // + 4-byte payload.
        let udp_payload = b"test";
        let udp_len = (8 + udp_payload.len()) as u16;
        let total_len = (20 + udp_len as usize) as u16;
        let mut ip = vec![
            0x45, 0x00, // version/ihl, dscp/ecn
        ];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]); // id, flags/frag
        ip.push(64); // ttl
        ip.push(17); // protocol: UDP
        ip.extend_from_slice(&[0x00, 0x00]); // checksum (unchecked by etherparse by default)
        ip.extend_from_slice(&[10, 20, 50, 21]); // src ip
        ip.extend_from_slice(&[10, 20, 50, 23]); // dst ip

        let mut udp = Vec::new();
        udp.extend_from_slice(&12345u16.to_be_bytes()); // src port
        udp.extend_from_slice(&9999u16.to_be_bytes()); // dst port
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0x00, 0x00]); // checksum

        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
        frame.extend_from_slice(udp_payload);
        frame
    }

    #[test]
    fn parses_sll_cooked_capture_frame() {
        let mac = [0x02, 0x42, 0x0a, 0x14, 0x32, 0x15];
        let frame = sll_ipv4_udp_frame(mac);

        let parsed = parse_sll_frame(&frame, 1_000_000).expect("SLL frame should parse");

        assert_eq!(parsed.src_ip.to_string(), "10.20.50.21");
        assert_eq!(parsed.dst_ip.to_string(), "10.20.50.23");
        assert_eq!(parsed.src_port, Some(12345));
        assert_eq!(parsed.dst_port, Some(9999));
        assert_eq!(parsed.transport, TransportProtocol::Udp);
        assert_eq!(parsed.src_mac.as_deref(), Some("02:42:0a:14:32:15"));
        // SLL has no destination MAC by construction.
        assert_eq!(parsed.dst_mac, None);
        assert_eq!(parsed.raw_payload, b"test");
        assert!(!parsed.is_arp);
    }

    #[test]
    fn rejects_too_short_sll_frame() {
        assert!(parse_sll_frame(&[0u8; 10], 0).is_none());
    }

    /// Builds a minimal Ethernet/IPv4 ARP request frame (dst mac
    /// broadcast, ethertype 0x0806) matching the wire format seen on a
    /// real LAN — this is the primary source of asset-discovery
    /// evidence for hosts that never send a single TCP/UDP packet
    /// (e.g. a device that's up but idle beyond periodic ARP refresh).
    fn arp_request_frame(src_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]); // dst mac: broadcast
        frame.extend_from_slice(&src_mac); // src mac
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // ethertype: ARP

        frame.extend_from_slice(&1u16.to_be_bytes()); // hw_type: ethernet
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // proto_type: IPv4
        frame.push(6); // hw_len
        frame.push(4); // proto_len
        frame.extend_from_slice(&1u16.to_be_bytes()); // opcode: request
        frame.extend_from_slice(&src_mac); // sender mac
        frame.extend_from_slice(&sender_ip); // sender ip
        frame.extend_from_slice(&[0u8; 6]); // target mac: unknown (request)
        frame.extend_from_slice(&target_ip); // target ip
        frame
    }

    #[test]
    fn parses_arp_request_frame() {
        let src_mac = [0x02, 0x42, 0x0a, 0x14, 0x46, 0x0a];
        let frame = arp_request_frame(src_mac, [10, 20, 70, 10], [10, 20, 70, 1]);

        let parsed = parse_frame(&frame, 1_000_000).expect("ARP frame should parse");

        assert!(parsed.is_arp);
        assert_eq!(parsed.src_ip.to_string(), "10.20.70.10");
        assert_eq!(parsed.dst_ip.to_string(), "10.20.70.1");
        assert_eq!(parsed.src_mac.as_deref(), Some("02:42:0a:14:46:0a"));
        assert_eq!(parsed.src_port, None);
        assert_eq!(parsed.transport, TransportProtocol::Other);
    }

    /// Builds a real Ethernet/IPv4/TCP SYN frame carrying a genuine set of
    /// TCP options (MSS, SACK-permitted, timestamps, NOP padding, window
    /// scale — a realistic modern Linux/BSD SYN) via etherparse's own
    /// `PacketBuilder`, so this test exercises the exact wire encoding a
    /// real OS's TCP stack produces, not a hand-rolled byte buffer.
    #[test]
    fn parses_real_tcp_options_from_syn_packet() {
        use etherparse::{PacketBuilder, TcpHeader, TcpOptionElement};

        let mut tcp_header = TcpHeader::new(51000, 4242, 0, 29200);
        tcp_header.syn = true;
        tcp_header.set_options(&[
            TcpOptionElement::MaximumSegmentSize(1460),
            TcpOptionElement::SelectiveAcknowledgementPermitted,
            TcpOptionElement::Timestamp(123_456, 0),
            TcpOptionElement::Noop,
            TcpOptionElement::WindowScale(7),
        ])
        .expect("options fit within the 40-byte TCP options budget");

        let builder = PacketBuilder::ethernet2([0x02, 0x42, 0x0a, 0x14, 0x46, 0x0a], [0x02, 0x42, 0x0a, 0x14, 0x46, 0x01])
            .ipv4([10, 20, 70, 21], [10, 20, 70, 10], 64)
            .tcp_header(tcp_header);

        let mut frame = Vec::with_capacity(builder.size(0));
        builder
            .write(&mut frame, &[])
            .expect("valid packet builder configuration");

        let parsed = parse_frame(&frame, 1_000_000).expect("real TCP SYN frame should parse");

        assert!(parsed.is_syn);
        assert!(!parsed.is_syn_ack);
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.window_scale, Some(7));
        assert!(parsed.sack_permitted);
        assert!(parsed.timestamps_present);
        assert_eq!(parsed.tcp_option_order, "MSS,SACK,TS,NOP,WS");
        assert_eq!(parsed.ttl, Some(64));
    }

    /// A device with a minimal TCP option set (no window scale, no
    /// timestamps, no SACK — real embedded/IoT TCP/IP stacks like lwIP
    /// commonly send exactly this) must still parse cleanly and report
    /// those fields as genuinely absent, not just defaulted — this is
    /// what lets `medwatch_fingerprinting::classify` tell a real minimal
    /// stack apart from a modern one that simply wasn't decoded.
    #[test]
    fn parses_minimal_tcp_options_from_embedded_style_syn() {
        use etherparse::{PacketBuilder, TcpHeader, TcpOptionElement};

        let mut tcp_header = TcpHeader::new(50000, 104, 0, 2048);
        tcp_header.syn = true;
        tcp_header
            .set_options(&[TcpOptionElement::MaximumSegmentSize(536)])
            .expect("single MSS option fits");

        let builder = PacketBuilder::ethernet2([0x02, 0x42, 0x0a, 0x14, 0x50, 0x0a], [0x02, 0x42, 0x0a, 0x14, 0x50, 0x01])
            .ipv4([10, 20, 80, 22], [10, 20, 80, 12], 64)
            .tcp_header(tcp_header);

        let mut frame = Vec::with_capacity(builder.size(0));
        builder.write(&mut frame, &[]).expect("valid packet builder configuration");

        let parsed = parse_frame(&frame, 1_000_000).expect("minimal TCP SYN frame should parse");

        assert_eq!(parsed.mss, Some(536));
        assert_eq!(parsed.window_scale, None);
        assert!(!parsed.sack_permitted);
        assert!(!parsed.timestamps_present);
        assert_eq!(parsed.tcp_option_order, "MSS");
    }
}
