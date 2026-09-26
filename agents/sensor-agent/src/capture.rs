//! Live capture loop over libpcap (Linux) / Npcap (Windows) via the `pcap`
//! crate, parsed with `etherparse`. Runs synchronously in a dedicated
//! std::thread (libpcap's blocking capture loop doesn't play well with
//! async), forwarding parsed packets to the async pipeline over a channel.

use anyhow::{Context, Result};
use etherparse::{LinkHeader, NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device};
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
    pub total_len: u32,
    pub raw_payload: Vec<u8>,
}

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

    let (src_ip, dst_ip, ttl) = match &headers.net {
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

    match &headers.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            transport = TransportProtocol::Tcp;
            src_port = Some(tcp.source_port);
            dst_port = Some(tcp.destination_port);
            window_size = Some(tcp.window_size);
            is_syn = tcp.syn && !tcp.ack;
            is_syn_ack = tcp.syn && tcp.ack;
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
        total_len: data.len() as u32,
        raw_payload: headers.payload.slice().to_vec(),
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
                if let Some(parsed) = parse_frame(packet.data, ts_micros) {
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
