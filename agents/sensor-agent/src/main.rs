mod capture;
mod config;
mod events;
mod pipeline;
mod shipper;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

use capture::CapturedPacket;
use config::{Cli, Config};
use events::{AssetRecord, NetworkEvent};
use pipeline::{extract_identity_hint, packet_to_event, AssetTable, FlowClassifier, ProtocolPorts};
use shipper::BackendShipper;

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    if cli.list_interfaces {
        for device in capture::list_interfaces()? {
            println!(
                "{}\t{}",
                device.name,
                device
                    .desc
                    .unwrap_or_else(|| "(no description)".to_string())
            );
        }
        return Ok(());
    }

    let mut config = Config::load(&cli.config)?;
    if let Some(iface) = cli.interface {
        config.capture.interface = iface;
    }
    let sensor_id = config.resolved_sensor_id();

    info!(sensor_id, site = %config.sensor.site, interface = %config.capture.interface, dry_run = cli.dry_run, "medwatch-sensor starting");

    let (tx, mut rx) = mpsc::channel::<CapturedPacket>(4096);

    let capture_cfg = config.capture.clone();
    let capture_handle = tokio::task::spawn_blocking(move || {
        capture::run_capture_loop(
            &capture_cfg.interface,
            capture_cfg.snaplen,
            capture_cfg.promiscuous,
            capture_cfg.bpf_filter.as_deref(),
            tx,
        )
    });

    // Ships to the team's backend ingest API (JSON array POST to
    // /api/v1/events and /api/v1/assets) — never directly to Elasticsearch.
    let shipper = if cli.dry_run {
        None
    } else {
        Some(Arc::new(BackendShipper::new(config.backend.clone())?))
    };

    let mut asset_table = AssetTable::new();
    let mut event_buffer: Vec<NetworkEvent> = Vec::new();
    let protocol_ports = ProtocolPorts::new(&config.capture.dicom_ports, &config.capture.hl7_ports);
    let mut flow_classifier = FlowClassifier::default();

    let mut flush_ticker = interval(Duration::from_secs(config.backend.flush_interval_secs));
    let mut asset_ticker = interval(Duration::from_secs(
        config.capture.asset_flush_interval_secs,
    ));

    let mut shutdown = Box::pin(tokio::signal::ctrl_c());

    loop {
        tokio::select! {
            maybe_packet = rx.recv() => {
                match maybe_packet {
                    Some(packet) => {
                        let event = packet_to_event(&packet, &sensor_id, &protocol_ports, &mut flow_classifier);
                        let identity_hint = extract_identity_hint(&event.application, &event.protocol_metadata);
                        asset_table.observe(&packet, &event.application, identity_hint);
                        event_buffer.push(event);

                        if event_buffer.len() >= config.backend.batch_size {
                            flush_events(&shipper, &mut event_buffer, cli.dry_run).await;
                        }
                    }
                    None => {
                        warn!("capture channel closed, shutting down");
                        break;
                    }
                }
            }
            _ = flush_ticker.tick() => {
                flush_events(&shipper, &mut event_buffer, cli.dry_run).await;
            }
            _ = asset_ticker.tick() => {
                if !asset_table.is_empty() {
                    let records = asset_table.drain_to_records(&sensor_id);
                    flush_assets(&shipper, records, cli.dry_run).await;
                }
            }
            _ = &mut shutdown => {
                info!("shutdown signal received, flushing remaining buffers");
                flush_events(&shipper, &mut event_buffer, cli.dry_run).await;
                let records = asset_table.drain_to_records(&sensor_id);
                flush_assets(&shipper, records, cli.dry_run).await;
                break;
            }
        }
    }

    capture_handle.abort();
    info!("medwatch-sensor stopped");
    Ok(())
}

async fn flush_events(
    shipper: &Option<Arc<BackendShipper>>,
    buffer: &mut Vec<NetworkEvent>,
    dry_run: bool,
) {
    if buffer.is_empty() {
        return;
    }
    if dry_run {
        info!(count = buffer.len(), "dry-run: would POST events batch");
        buffer.clear();
        return;
    }
    if let Some(shipper) = shipper {
        if let Err(e) = shipper.post_batch("/api/v1/events", buffer).await {
            error!("failed to ship events batch: {e:#}");
        }
    }
    buffer.clear();
}

async fn flush_assets(
    shipper: &Option<Arc<BackendShipper>>,
    records: Vec<AssetRecord>,
    dry_run: bool,
) {
    if records.is_empty() {
        return;
    }
    if dry_run {
        info!(count = records.len(), "dry-run: would POST asset records");
        return;
    }
    if let Some(shipper) = shipper {
        if let Err(e) = shipper.post_batch("/api/v1/assets", &records).await {
            error!("failed to ship asset records: {e:#}");
        }
    }
}
