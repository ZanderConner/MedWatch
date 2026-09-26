import React, { useState, useEffect, useMemo } from 'react';

const LATEST_VER = "0.4.2";
const API_URL = "http://localhost:8000";

const FALLBACK_AGENTS = [
  { sensor_id: "sensor-icu-3rdfloor", hostname: "mw-tap-icu03.clinical.local", version: "0.4.2", rust_target: "aarch64-unknown-linux-gnu", os_kernel: "Debian 12 (Linux 6.1)", interface: "eth0 (SPAN 4)", bpf_filter: "tcp port 104 or tcp port 2575 or port 443 or port 53", batch_interval_ms: 2000, uptime: "14d 06h 18m", cpu_pct: 4.2, mem_mb: 28.4, dissectors: ["dicom", "hl7", "https", "dns"] },
  { sensor_id: "sensor-er-west", hostname: "mw-tap-erwest.clinical.local", version: "0.4.1", rust_target: "x86_64-unknown-linux-musl", os_kernel: "Alpine 3.19 (Linux 6.6)", interface: "ens192 (VLAN 120)", bpf_filter: "tcp port 104 or tcp port 2575 or port 80 or port 53", batch_interval_ms: 5000, uptime: "08d 19h 42m", cpu_pct: 3.1, mem_mb: 24.0, dissectors: ["dicom", "hl7", "http", "dns"] }
];

const FALLBACK_ASSETS = [
  { asset_id: "00:1b:63:84:45:e6", sensor_id: "sensor-icu-3rdfloor", device_identity_hint: "CT Scanner (Bay 3)", os_guess: "linux", ip_addresses: ["10.0.0.5"], observed_protocols: ["dicom", "https"] },
  { asset_id: "00:14:22:01:23:45", sensor_id: "sensor-icu-3rdfloor", device_identity_hint: "Infusion Pump #04", os_guess: "embedded", ip_addresses: ["10.0.0.42"], observed_protocols: ["hl7"] },
  { asset_id: "ac:de:48:00:11:22", sensor_id: "sensor-er-west", device_identity_hint: "Bedside Monitor Rm 12", os_guess: "embedded", ip_addresses: ["10.0.0.18"], observed_protocols: ["http", "dns"] }
];

const FALLBACK_EVENTS = [
  { event_id: "3fa85f64-5717", sensor_id: "sensor-icu-3rdfloor", "@timestamp": "2026-09-25T22:18:10Z", src_ip: "10.0.0.5", src_port: 51000, dst_ip: "10.0.0.20", dst_port: 104, application: "dicom", length_bytes: 1480, protocol_metadata: { called_ae_title: "PACS_MAIN", calling_ae_title: "CT_SCANNER_3" }, is_suspicious: false },
  { event_id: "4ab19c12-1234", sensor_id: "sensor-icu-3rdfloor", "@timestamp": "2026-09-25T22:19:05Z", src_ip: "10.0.0.5", src_port: 51002, dst_ip: "10.0.0.20", dst_port: 104, application: "dicom", length_bytes: 4096, protocol_metadata: { called_ae_title: "PACS_MAIN", calling_ae_title: "CT_SCANNER_3" }, is_suspicious: false },
  { event_id: "5cd28e44-2345", sensor_id: "sensor-er-west", "@timestamp": "2026-09-25T22:20:40Z", src_ip: "10.0.0.18", src_port: 53120, dst_ip: "10.0.0.1", dst_port: 80, application: "http", length_bytes: 640, protocol_metadata: { host: "internal-ehr.local", method: "GET" }, is_suspicious: false },
  { event_id: "7bc12e91-8812", sensor_id: "sensor-icu-3rdfloor", "@timestamp": "2026-09-25T22:21:15Z", src_ip: "10.0.0.42", src_port: 49152, dst_ip: "198.51.100.14", dst_port: 2575, application: "hl7", length_bytes: 2150, protocol_metadata: { warning: "Unencrypted clinical stream to external IP", peer: "198.51.100.14" }, is_suspicious: true },
  { event_id: "8de91a04-9912", sensor_id: "sensor-icu-3rdfloor", "@timestamp": "2026-09-25T22:22:30Z", src_ip: "10.0.0.42", src_port: 49155, dst_ip: "10.0.0.30", dst_port: 2575, application: "hl7", length_bytes: 980, protocol_metadata: { message_type: "ORU^R01" }, is_suspicious: false },
  { event_id: "9cb22a01-1111", sensor_id: "sensor-er-west", "@timestamp": "2026-09-25T22:23:10Z", src_ip: "10.0.0.18", src_port: 5353, dst_ip: "8.8.8.8", dst_port: 53, application: "dns", length_bytes: 128, protocol_metadata: { query: "time.nist.gov" }, is_suspicious: false },
  { event_id: "1ef99b22-4411", sensor_id: "sensor-er-west", "@timestamp": "2026-09-25T22:24:00Z", src_ip: "10.0.0.18", src_port: 58211, dst_ip: "203.0.113.55", dst_port: 80, application: "http", length_bytes: 1820, protocol_metadata: { warning: "Unexpected outbound HTTP POST from bedside monitor" }, is_suspicious: true },
  { event_id: "2fa44c88-7721", sensor_id: "sensor-icu-3rdfloor", "@timestamp": "2026-09-25T22:25:12Z", src_ip: "10.0.0.5", src_port: 51010, dst_ip: "10.0.0.20", dst_port: 443, application: "https", length_bytes: 3120, protocol_metadata: { sni: "pacs-gateway.local" }, is_suspicious: false }
];

export default function App() {
  const [assets, setAssets] = useState(FALLBACK_ASSETS);
  const [events, setEvents] = useState(FALLBACK_EVENTS);
  const [agentMeta, setAgentMeta] = useState(FALLBACK_AGENTS);
  const [page, setPage] = useState('OVERVIEW');
  const [sensor, setSensor] = useState('ALL');
  const [filter, setFilter] = useState('ALL');
  const [modal, setModal] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [aRes, eRes] = await Promise.all([fetch(`${API_URL}/api/v1/assets`), fetch(`${API_URL}/api/v1/events`)]);
        if (aRes.ok && eRes.ok) { setAssets(await aRes.json()); setEvents(await eRes.json()); }
        const agRes = await fetch(`${API_URL}/api/v1/agents`);
        if (agRes.ok) setAgentMeta(await agRes.json());
      } catch {}
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  const activeSensors = useMemo(() => (
    Array.from(new Set([...agentMeta, ...assets, ...events].map(x => x.sensor_id).filter(Boolean)))
  ), [agentMeta, assets, events]);

  const visibleAssets = assets.filter(a => sensor === 'ALL' || a.sensor_id === sensor);
  const sensorEvents = useMemo(() => events.filter(e => sensor === 'ALL' || e.sensor_id === sensor), [events, sensor]);
  const suspiciousCount = sensorEvents.filter(e => e.is_suspicious).length;

  const filteredEvents = sensorEvents.filter(e => (
    filter === 'ALL' ? true : filter === 'SUSPICIOUS' ? e.is_suspicious : e.application === filter.toLowerCase()
  ));

  const enrichedAgents = useMemo(() => (
    activeSensors.filter(id => sensor === 'ALL' || id === sensor).map((id, i) => {
      const meta = agentMeta.find(a => a.sensor_id === id) || {
        sensor_id: id, hostname: `${id}.local`, version: LATEST_VER, rust_target: "x86_64-linux",
        os_kernel: "Linux 6.1", interface: `eth${i}`, bpf_filter: "tcp port 104 or 2575",
        batch_interval_ms: 3000, uptime: "01d 04h", cpu_pct: 2.8, mem_mb: 22.5, dissectors: ["dicom", "hl7"]
      };
      return {
        ...meta,
        eventCount: events.filter(e => e.sensor_id === id).length,
        isUpToDate: meta.version === LATEST_VER
      };
    })
  ), [activeSensors, sensor, agentMeta, events]);

  const analytics = useMemo(() => {
    const pCounts = {}, pBytes = {}, sources = {}, buckets = [];
    let totalBytes = 0;

    sensorEvents.forEach(e => {
      const proto = (e.application || 'other').toUpperCase();
      const b = e.length_bytes || 512;
      totalBytes += b;
      pCounts[proto] = (pCounts[proto] || 0) + 1;
      pBytes[proto] = (pBytes[proto] || 0) + b;

      const ip = e.src_ip || e.src?.split(':')[0] || 'Unknown';
      sources[ip] ??= { ip, name: assets.find(a => a.ip_addresses?.includes(ip))?.device_identity_hint || ip, bytes: 0, flagged: 0 };
      sources[ip].bytes += b;
      if (e.is_suspicious) sources[ip].flagged += 1;

      const time = new Date(e["@timestamp"] || e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
      const slot = buckets.find(x => x.time === time);
      if (slot) { slot.bytes += b; slot.flagged += e.is_suspicious ? 1 : 0; }
      else buckets.push({ time, bytes: b, flagged: e.is_suspicious ? 1 : 0 });
    });

    return {
      totalBytes,
      buckets,
      protocols: Object.keys(pCounts).map(k => ({
        name: k, count: pCounts[k], bytes: pBytes[k], pct: Math.round((pCounts[k] / (sensorEvents.length || 1)) * 100)
      })).sort((a, b) => b.bytes - a.bytes),
      topTalkers: Object.values(sources).sort((a, b) => b.bytes - a.bytes)
    };
  }, [sensorEvents, assets]);

  const statsStrip = page === 'AGENTS' ? [
    { label: "Target Release", val: `v${LATEST_VER}`, sub: "rust-agent" },
    { label: "Version Drift", val: `${enrichedAgents.filter(a => a.isUpToDate).length} / ${enrichedAgents.length}`, sub: "aligned" },
    { label: "Transport Auth", val: "ApiKey SHA-256", sub: "enforced", cls: "teal" },
    { label: "Tap Mode", val: "AF_PACKET", sub: "passive" }
  ] : [
    { label: "Discovered Endpoints", val: visibleAssets.length, sub: "10.0.0.0/24" },
    { label: "Captured Packets", val: sensorEvents.length, sub: "live stream" },
    { label: "Payload Volume", val: `${(analytics.totalBytes / 1024).toFixed(1)} KB`, sub: "L7 parsed" },
    { label: "Policy Violations", val: suspiciousCount, sub: suspiciousCount ? "requires review" : "clear", cls: suspiciousCount ? "danger" : "" }
  ];

  return (
    <div className="app-shell">
      {/* LEFT SIDEBAR */}
      <aside className="sidebar">
        <div>
          <div className="brand">
            <div><span className="brand-logo">M</span><strong>MedWatch</strong></div>
          </div>

          <nav style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {[['OVERVIEW', 'Overview', sensorEvents.length], ['ANALYTICS', 'Traffic Analytics'], ['AGENTS', 'Security & Agents', activeSensors.length]].map(([id, label, count]) => (
              <button key={id} onClick={() => setPage(id)} className={`nav-btn ${page === id ? 'active' : ''}`}>
                <span>{label}</span>
                {count !== undefined && <span className="muted" style={{ fontSize: 11 }}>{count}</span>}
              </button>
            ))}
          </nav>

          <div style={{ marginTop: 28 }}>
            <div className="muted" style={{ fontSize: 11, padding: '0 10px 6px' }}>Capture Nodes</div>
            <button onClick={() => setSensor('ALL')} className={`nav-btn ${sensor === 'ALL' ? 'active' : ''}`} style={{ fontSize: 12 }}>
              <span>All sensors</span><span className="muted" style={{ fontSize: 11 }}>{activeSensors.length}</span>
            </button>
            {activeSensors.map(id => (
              <button key={id} onClick={() => setSensor(id)} className={`nav-btn ${sensor === id ? 'active' : ''}`} style={{ fontSize: 12 }}>
                <span><span style={{ color: '#2dd4bf', marginRight: 6 }}>●</span>{id}</span>
              </button>
            ))}
          </div>
        </div>
      </aside>

      {/* MAIN WORKSPACE */}
      <main className="main">
        <div className="container">
          <header className="topbar">
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span className="sub">MedWatch</span><span className="muted">/</span>
              <strong>{{ OVERVIEW: "Telemetry Stream", ANALYTICS: "Traffic Analytics", AGENTS: "Sensor Fleet" }[page]}</strong>
              {sensor !== 'ALL' && (
                <>
                  <span className="muted">/</span>
                  <span className="teal" style={{ fontSize: 12 }}>{sensor}</span>
                </>
              )}
            </div>
          </header>

          {/* 4-COLUMN INSTRUMENT LEDGER */}
          <div className="ledger">
            {statsStrip.map((st, i) => (
              <div key={i} className="ledger-cell">
                <div className="sub" style={{ fontSize: 11 }}>{st.label}</div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 6 }}>
                  <span className={st.cls || ''} style={{ fontSize: 19, fontWeight: 500, color: st.cls ? undefined : '#e6e9ef' }}>{st.val}</span>
                  <span className={st.cls || 'muted'} style={{ fontSize: 11 }}>{st.sub}</span>
                </div>
              </div>
            ))}
          </div>

          {/* PAGE 1: AGENTS */}
          {page === 'AGENTS' && (
            <div className="panel">
              <table>
                <thead>
                  <tr><th>Node</th><th>Binary Version</th><th>OS / Arch</th><th>Interface & Dissectors</th><th>Load</th><th style={{ textAlign: 'right' }}>Uptime</th></tr>
                </thead>
                <tbody>
                  {enrichedAgents.map(ag => (
                    <tr key={ag.sensor_id} className="log-row" onClick={() => setModal({
                      title: `${ag.sensor_id} / sensor-agent.toml`,
                      raw: `[agent]\nsensor_id = "${ag.sensor_id}"\nversion = "${ag.version}"\n\n[capture]\ninterface = "${ag.interface.split(' ')[0]}"\nbpf_filter = "${ag.bpf_filter}"\ndissectors = ${JSON.stringify(ag.dissectors)}\n\n[ingest]\nendpoint = "${API_URL}/api/v1"\nauth_header = "Authorization: ApiKey <redacted>"`
                    })}>
                      <td>
                        <div><span className="teal">● </span><strong>{ag.sensor_id}</strong></div>
                        <div className="muted" style={{ fontSize: 11, paddingLeft: 12 }}>{ag.hostname}</div>
                      </td>
                      <td>
                        v{ag.version} {!ag.isUpToDate && <span style={{ color: '#f59e0b', fontSize: 11, marginLeft: 6 }}>v{LATEST_VER} avail</span>}
                      </td>
                      <td><div>{ag.os_kernel}</div><div className="muted" style={{ fontSize: 11 }}>{ag.rust_target}</div></td>
                      <td style={{ fontSize: 12 }}><div>{ag.interface}</div><div className="muted" style={{ fontSize: 11 }}>{ag.dissectors.join(" · ").toUpperCase()}</div></td>
                      <td className="sub" style={{ fontSize: 12 }}>{ag.cpu_pct}% / {ag.mem_mb}MB</td>
                      <td className="sub" style={{ fontSize: 12, textAlign: 'right' }}><div>{ag.uptime}</div><div className="muted" style={{ fontSize: 11 }}>{ag.eventCount} pkts</div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* PAGE 2: ANALYTICS */}
          {page === 'ANALYTICS' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              <div className="panel" style={{ padding: '18px 20px' }}>
                <div className="section-hdr"><strong>Packet Throughput & Anomalies</strong><span className="muted" style={{ fontSize: 11 }}>Teal: Volume (KB) · Red: Violation</span></div>
                {(() => {
                  const b = analytics.buckets, maxB = Math.max(...b.map(x => x.bytes), 2048);
                  const pts = b.map((x, i) => ({ ...x, x: 36 + (b.length > 1 ? (i / (b.length - 1)) * 868 : 434), y: 14 + 125 - (x.bytes / maxB) * 125 }));
                  const line = pts.map((p, i) => `${i ? 'L' : 'M'} ${p.x} ${p.y}`).join(' ');
                  return (
                    <svg viewBox="0 0 920 165" style={{ width: '100%', height: 175 }}>
                      {pts.length > 1 && <path d={`${line} L ${pts.at(-1).x} 139 L ${pts[0].x} 139 Z`} fill="rgba(45,212,191,0.08)" />}
                      {pts.length > 1 && <path d={line} fill="none" stroke="#2dd4bf" strokeWidth="1.5" />}
                      {pts.map((p, i) => (
                        <g key={i}>
                          <circle cx={p.x} cy={p.y} r={p.flagged ? 4 : 2.5} fill={p.flagged ? '#e5484d' : '#0e1013'} stroke={p.flagged ? '#e5484d' : '#2dd4bf'} strokeWidth="1.5" />
                          <text x={p.x} y="158" textAnchor="middle" fill="#636975" fontSize="10">{p.time}</text>
                        </g>
                      ))}
                    </svg>
                  );
                })()}
              </div>

              <div className="split-grid">
                <div style={{ padding: '18px 20px', borderRight: '1px solid #1c1f26' }}>
                  <div className="section-hdr"><strong>Application Protocols</strong><span className="muted" style={{ fontSize: 11 }}>PKTS / VOL</span></div>
                  {analytics.protocols.map(p => (
                    <div key={p.name} className="bar-row">
                      <div className="bar-fill" style={{ width: `${p.pct}%`, background: 'rgba(45,212,191,0.06)', borderLeft: '2px solid #2dd4bf' }} />
                      <span style={{ position: 'relative' }}>{p.name}</span>
                      <span className="sub" style={{ position: 'relative', fontSize: 12 }}>{p.count} · {(p.bytes / 1024).toFixed(1)} KB</span>
                    </div>
                  ))}
                </div>
                <div style={{ padding: '18px 20px' }}>
                  <div className="section-hdr"><strong>Top Source Endpoints</strong><span className="muted" style={{ fontSize: 11 }}>STATUS / VOL</span></div>
                  {analytics.topTalkers.map(d => {
                    const pct = Math.round((d.bytes / Math.max(...analytics.topTalkers.map(x => x.bytes), 1)) * 100);
                    return (
                      <div key={d.ip} className="bar-row">
                        <div className="bar-fill" style={{ width: `${pct}%`, background: d.flagged ? 'rgba(229,72,77,0.07)' : 'rgba(138,143,152,0.06)', borderLeft: `2px solid ${d.flagged ? '#e5484d' : '#636975'}` }} />
                        <span style={{ position: 'relative' }}>{d.name} <span className="muted" style={{ fontSize: 11.5, marginLeft: 4 }}>{d.ip}</span></span>
                        <span style={{ position: 'relative', fontSize: 12 }}>
                          <span className={d.flagged ? 'danger' : 'muted'} style={{ marginRight: 14 }}>{d.flagged ? `${d.flagged} flagged` : 'ok'}</span>
                          {(d.bytes / 1024).toFixed(1)} KB
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* PAGE 3: OVERVIEW */}
          {page === 'OVERVIEW' && (
            <>
              <div className="section-hdr"><strong>Clinical Asset Inventory</strong><span className="muted" style={{ fontSize: 11 }}>{visibleAssets.length} active</span></div>
              <div className="asset-grid">
                {visibleAssets.map(a => (
                  <div key={a.asset_id} className="asset-cell">
                    <div className="section-hdr" style={{ marginBottom: 6 }}><strong>{a.device_identity_hint || a.asset_id}</strong><span className="muted" style={{ fontSize: 11 }}>{a.os_guess}</span></div>
                    <div className="sub" style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                      <span>{a.ip_addresses?.join(", ")}</span><span className="muted" style={{ fontSize: 11 }}>{a.observed_protocols?.join(" · ").toUpperCase()}</span>
                    </div>
                  </div>
                ))}
              </div>

              <div className="section-hdr">
                <strong>Packet Stream</strong>
                <div style={{ display: 'flex', gap: 4 }}>
                  {['ALL', 'SUSPICIOUS', 'DICOM', 'HL7'].map(f => (
                    <button key={f} onClick={() => setFilter(f)} className={`pill-btn ${filter === f ? 'active' : ''}`} style={{ fontSize: 11 }}>{f}</button>
                  ))}
                </div>
              </div>

              <div className="panel">
                <table>
                  <thead><tr><th>State</th><th>Timestamp</th><th>Sensor</th><th>Source → Destination</th><th>Proto</th><th>Decoded Payload</th></tr></thead>
                  <tbody>
                    {filteredEvents.map(e => {
                      const flow = `${e.src || `${e.src_ip}:${e.src_port ?? ''}`} → ${e.dst || `${e.dst_ip}:${e.dst_port ?? ''}`}`;
                      const meta = e.protocol_metadata || e.metadata;
                      return (
                        <tr key={e.event_id} className={`log-row ${e.is_suspicious ? 'flagged' : ''}`} onClick={() => setModal({
                          title: `Packet Inspection (${e.event_id})`,
                          raw: `Sensor: ${e.sensor_id}\nFlow:   ${flow}\nBytes:  ${e.length_bytes || 512} B\n\n${JSON.stringify(meta, null, 2)}`
                        })}>
                          <td className={e.is_suspicious ? 'danger' : 'sub'} style={{ fontSize: 11.5, borderLeft: e.is_suspicious ? '2px solid #e5484d' : 'none' }}>{e.is_suspicious ? 'Flagged' : 'Pass'}</td>
                          <td className="muted" style={{ fontSize: 12 }}>{new Date(e["@timestamp"] || e.timestamp).toLocaleTimeString([], { hour12: false })}</td>
                          <td className="sub" style={{ fontSize: 12 }}>{e.sensor_id}</td>
                          <td style={{ fontSize: 12 }}>{flow}</td>
                          <td className="teal" style={{ fontSize: 11.5 }}>{e.application?.toUpperCase()}</td>
                          <td className="muted" style={{ fontSize: 11.5, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{meta ? JSON.stringify(meta) : '—'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </main>

      {/* UNIFIED MODAL INSPECTOR */}
      {modal && (
        <div className="modal-overlay" onClick={() => setModal(null)}>
          <div className="modal-box" onClick={e => e.stopPropagation()}>
            <div className="section-hdr" style={{ borderBottom: '1px solid #1c1f26', paddingBottom: 10 }}>
              <strong>{modal.title}</strong>
              <button onClick={() => setModal(null)} className="pill-btn">ESC</button>
            </div>
            <pre className="modal-pre">{modal.raw}</pre>
          </div>
        </div>
      )}
    </div>
  );
}