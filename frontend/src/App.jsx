import React, { useState, useEffect, useMemo } from 'react';

// Base URL of the MedWatch backend's read API. Configurable via Vite env
// (VITE_API_URL) so a build can point at a different backend without
// code changes; defaults to the backend's own default port (see
// backend/shared/config.js and backend/.env.example — 8080, or whatever
// the demo range publishes it as on the host, e.g. 9000).
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

// Shared admin API key, baked in at build time (see frontend/Dockerfile
// and demo/docker-compose.yml's frontend service — must match the
// backend's MEDWATCH_API_KEY). Hackathon-simple: one static key, same
// pattern the sensor agent itself uses (backend/shared/auth.js). Only
// needed for the Asset Inventory page's write actions (manual add /
// confirm / delete) — every read in this app stays unauthenticated.
const ADMIN_API_KEY = import.meta.env.VITE_ADMIN_API_KEY || 'change-me';

async function adminFetch(path, options = {}) {
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `ApiKey ${ADMIN_API_KEY}`,
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `${path} -> ${res.status}`);
  }
  return res.status === 204 ? null : res.json();
}

// Fallback data shown before the first successful fetch (or if the
// backend is unreachable) so the UI never renders empty/broken on load.
const FALLBACK_SENSORS = [
  { sensor_id: "sensor-icu-3rdfloor", last_seen: null, event_count: 0, asset_count: 0, active: false }
];

const FALLBACK_ASSETS = [
  { asset_id: "00:1b:63:84:45:e6", sensor_id: "sensor-icu-3rdfloor", device_identity_hint: "CT Scanner (Bay 3)", os_guess: "linux", ip_addresses: ["10.0.0.5"], observed_protocols: ["dicom", "https"] },
  { asset_id: "00:14:22:01:23:45", sensor_id: "sensor-icu-3rdfloor", device_identity_hint: "Infusion Pump #04", os_guess: "embedded-or-iot", ip_addresses: ["10.0.0.42"], observed_protocols: ["hl7"] }
];

const FALLBACK_EVENTS = [
  { event_id: "3fa85f64-5717", sensor_id: "sensor-icu-3rdfloor", "@timestamp": "2026-09-25T22:18:10Z", src_ip: "10.0.0.5", src_port: 51000, dst_ip: "10.0.0.20", dst_port: 104, application: "dicom", length_bytes: 1480, protocol_metadata: { called_ae_title: "PACS_MAIN", calling_ae_title: "CT_SCANNER_3" } }
];

const FALLBACK_ALERTS = [];

// GET helper: unwraps the backend's { <key>: [...] } envelope shape
// (every list endpoint wraps its array — see backend/api/routes.js,
// backend/alerting/routes.js, backend/api/sensors.js) and never throws
// on a network/parse error, so a down backend degrades to the fallback
// data above instead of crashing the page.
async function fetchList(path, key) {
  const res = await fetch(`${API_URL}${path}`);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  const body = await res.json();
  return body[key] ?? [];
}

export default function App() {
  const [assets, setAssets] = useState(FALLBACK_ASSETS);
  const [events, setEvents] = useState(FALLBACK_EVENTS);
  const [sensors, setSensors] = useState(FALLBACK_SENSORS);
  const [alerts, setAlerts] = useState(FALLBACK_ALERTS);
  const [stats, setStats] = useState(null);
  const [inventory, setInventory] = useState([]);
  const [inventoryError, setInventoryError] = useState(null);
  const [inventoryFilter, setInventoryFilter] = useState('PENDING');
  const [addForm, setAddForm] = useState({ device_identity_hint: '', ip_addresses: '', mac_address: '', os_guess: 'unknown' });
  const [page, setPage] = useState('OVERVIEW');
  const [sensor, setSensor] = useState('ALL');
  const [filter, setFilter] = useState('ALL');
  const [modal, setModal] = useState(null);

  const loadInventory = async () => {
    try {
      const body = await adminFetch('/api/v1/admin/assets');
      setInventory(body.assets ?? []);
      setInventoryError(null);
    } catch (err) {
      setInventoryError(err.message);
    }
  };

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [a, e, s, al, st] = await Promise.all([
          fetchList('/api/v1/assets?limit=500', 'assets'),
          fetchList('/api/v1/events?limit=500', 'events'),
          fetchList('/api/v1/sensors', 'sensors'),
          fetchList('/api/v1/alerts?limit=200', 'alerts'),
          fetch(`${API_URL}/api/v1/stats`).then((r) => (r.ok ? r.json() : null)),
        ]);
        if (!cancelled) {
          setAssets(a);
          setEvents(e);
          setSensors(s);
          setAlerts(al);
          if (st) setStats(st);
        }
      } catch {
        // Backend unreachable or returned an error — keep whatever data
        // is already on screen (fallback or last-good fetch) rather than
        // clearing it.
      }
    };
    load();
    loadInventory();
    const id = setInterval(() => { load(); loadInventory(); }, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const confirmAsset = async (assetId) => {
    try {
      await adminFetch(`/api/v1/admin/assets/${encodeURIComponent(assetId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ confirmed: true }),
      });
      loadInventory();
    } catch (err) {
      setInventoryError(err.message);
    }
  };

  const removeAsset = async (assetId) => {
    try {
      await adminFetch(`/api/v1/admin/assets/${encodeURIComponent(assetId)}`, { method: 'DELETE' });
      loadInventory();
    } catch (err) {
      setInventoryError(err.message);
    }
  };

  const submitManualAsset = async (ev) => {
    ev.preventDefault();
    if (!addForm.device_identity_hint.trim()) return;
    try {
      await adminFetch('/api/v1/admin/assets', {
        method: 'POST',
        body: JSON.stringify({
          device_identity_hint: addForm.device_identity_hint.trim(),
          ip_addresses: addForm.ip_addresses.split(',').map(s => s.trim()).filter(Boolean),
          mac_address: addForm.mac_address.trim() || null,
          os_guess: addForm.os_guess,
        }),
      });
      setAddForm({ device_identity_hint: '', ip_addresses: '', mac_address: '', os_guess: 'unknown' });
      loadInventory();
    } catch (err) {
      setInventoryError(err.message);
    }
  };

  const pendingCount = inventory.filter(a => !a.confirmed).length;
  const visibleInventory = inventory.filter(a => (
    inventoryFilter === 'ALL' ? true : inventoryFilter === 'PENDING' ? !a.confirmed : a.confirmed
  ));

  // asset_id is how alerts are keyed (see backend/db/migrations/001_init.sql);
  // an event has no direct alert relationship, so "is this event
  // suspicious" is approximated as "does its src or dst IP belong to an
  // asset that currently has at least one alert".
  const alertedAssetIds = useMemo(() => new Set(alerts.map((al) => al.asset_id)), [alerts]);
  const alertedIps = useMemo(() => {
    const ips = new Set();
    for (const a of assets) {
      if (alertedAssetIds.has(a.asset_id)) {
        for (const ip of a.ip_addresses || []) ips.add(ip);
      }
    }
    return ips;
  }, [assets, alertedAssetIds]);

  const isSuspiciousEvent = useMemo(
    () => (e) => alertedIps.has(e.src_ip) || alertedIps.has(e.dst_ip),
    [alertedIps]
  );

  const activeSensors = useMemo(() => (
    Array.from(new Set([...sensors, ...assets, ...events].map(x => x.sensor_id).filter(Boolean)))
  ), [sensors, assets, events]);

  const visibleAssets = assets.filter(a => sensor === 'ALL' || a.sensor_id === sensor);
  const sensorEvents = useMemo(() => events.filter(e => sensor === 'ALL' || e.sensor_id === sensor), [events, sensor]);
  const suspiciousCount = sensorEvents.filter(isSuspiciousEvent).length;

  const filteredEvents = sensorEvents.filter(e => (
    filter === 'ALL' ? true : filter === 'SUSPICIOUS' ? isSuspiciousEvent(e) : e.application === filter.toLowerCase()
  ));

  // Sensor fleet table: real fields only (sensor_id, last_seen,
  // event_count, asset_count, active — see backend/api/sensors.js).
  // The sensor agent itself has no telemetry endpoint for hostname/
  // version/CPU/etc, so this page reports what the backend actually
  // knows rather than fabricating hardware stats.
  const enrichedAgents = useMemo(() => (
    activeSensors.filter(id => sensor === 'ALL' || id === sensor).map((id) => {
      const meta = sensors.find(s => s.sensor_id === id) || {
        sensor_id: id, last_seen: null,
        event_count: events.filter(e => e.sensor_id === id).length,
        asset_count: assets.filter(a => a.sensor_id === id).length,
        active: false
      };
      const sensorAlerts = alerts.filter(al => assets.some(a => a.sensor_id === id && a.asset_id === al.asset_id));
      return { ...meta, alertCount: sensorAlerts.length };
    })
  ), [activeSensors, sensor, sensors, events, assets, alerts]);

  const analytics = useMemo(() => {
    const pCounts = {}, pBytes = {}, sources = {}, buckets = [];
    let totalBytes = 0;

    sensorEvents.forEach(e => {
      const proto = (e.application || 'other').toUpperCase();
      const b = e.length_bytes || 512;
      totalBytes += b;
      pCounts[proto] = (pCounts[proto] || 0) + 1;
      pBytes[proto] = (pBytes[proto] || 0) + b;

      const ip = e.src_ip || 'Unknown';
      const flagged = isSuspiciousEvent(e);
      sources[ip] ??= { ip, name: assets.find(a => a.ip_addresses?.includes(ip))?.device_identity_hint || ip, bytes: 0, flagged: 0 };
      sources[ip].bytes += b;
      if (flagged) sources[ip].flagged += 1;

      const time = new Date(e["@timestamp"]).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
      const slot = buckets.find(x => x.time === time);
      if (slot) { slot.bytes += b; slot.flagged += flagged ? 1 : 0; }
      else buckets.push({ time, bytes: b, flagged: flagged ? 1 : 0 });
    });

    return {
      totalBytes,
      buckets,
      protocols: Object.keys(pCounts).map(k => ({
        name: k, count: pCounts[k], bytes: pBytes[k], pct: Math.round((pCounts[k] / (sensorEvents.length || 1)) * 100)
      })).sort((a, b) => b.bytes - a.bytes),
      topTalkers: Object.values(sources).sort((a, b) => b.bytes - a.bytes)
    };
  }, [sensorEvents, assets, isSuspiciousEvent]);

  const statsStrip = page === 'AGENTS' ? [
    { label: "Known Sensors", val: enrichedAgents.length, sub: "reporting" },
    { label: "Active Sensors", val: enrichedAgents.filter(a => a.active).length, sub: `of ${enrichedAgents.length}` },
    { label: "Transport Auth", val: "ApiKey", sub: "enforced", cls: "teal" },
    { label: "Open Alerts", val: alerts.length, sub: alerts.length ? "needs review" : "clear", cls: alerts.length ? "danger" : "" }
  ] : page === 'INVENTORY' ? [
    { label: "Total Assets", val: inventory.length, sub: "in inventory" },
    { label: "Confirmed", val: inventory.filter(a => a.confirmed).length, sub: "vetted" },
    { label: "Pending Review", val: pendingCount, sub: pendingCount ? "needs confirmation" : "clear", cls: pendingCount ? "danger" : "" },
    { label: "Manually Added", val: inventory.filter(a => a.source === 'manual').length, sub: "admin-entered" }
  ] : [
    { label: "Discovered Endpoints", val: visibleAssets.length, sub: "assets" },
    { label: "Captured Packets", val: sensor === 'ALL' ? (stats?.total_events ?? sensorEvents.length) : (enrichedAgents.find(a => a.sensor_id === sensor)?.event_count ?? sensorEvents.length), sub: "total, live" },
    { label: "Payload Volume", val: `${(analytics.totalBytes / 1024).toFixed(1)} KB`, sub: `last ${sensorEvents.length} pkts` },
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
            {[['OVERVIEW', 'Overview', sensor === 'ALL' ? (stats?.total_events ?? sensorEvents.length) : sensorEvents.length], ['INVENTORY', 'Asset Inventory', pendingCount || undefined], ['ANALYTICS', 'Traffic Analytics'], ['AGENTS', 'Security & Agents', activeSensors.length]].map(([id, label, count]) => (
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
              <strong>{{ OVERVIEW: "Telemetry Stream", INVENTORY: "Asset Inventory", ANALYTICS: "Traffic Analytics", AGENTS: "Sensor Fleet" }[page]}</strong>
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

          {/* PAGE 1: AGENTS / SECURITY */}
          {page === 'AGENTS' && (
            <div className="panel">
              <table>
                <thead>
                  <tr><th>Sensor</th><th>Status</th><th>Events</th><th>Assets</th><th style={{ textAlign: 'right' }}>Last Seen</th></tr>
                </thead>
                <tbody>
                  {enrichedAgents.map(ag => (
                    <tr key={ag.sensor_id} className="log-row" onClick={() => setModal({
                      title: ag.sensor_id,
                      raw: JSON.stringify(ag, null, 2)
                    })}>
                      <td><span className="teal">● </span><strong>{ag.sensor_id}</strong></td>
                      <td className={ag.active ? 'teal' : 'muted'} style={{ fontSize: 12 }}>{ag.active ? 'active' : 'inactive'}</td>
                      <td className="sub" style={{ fontSize: 12 }}>{ag.event_count}</td>
                      <td className="sub" style={{ fontSize: 12 }}>{ag.asset_count}</td>
                      <td className="sub" style={{ fontSize: 12, textAlign: 'right' }}>
                        <div>{ag.last_seen ? new Date(ag.last_seen).toLocaleString() : '—'}</div>
                        {ag.alertCount > 0 && <div className="danger" style={{ fontSize: 11 }}>{ag.alertCount} alert{ag.alertCount === 1 ? '' : 's'}</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* PAGE: ASSET INVENTORY */}
          {page === 'INVENTORY' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {inventoryError && (
                <div className="panel" style={{ padding: '10px 16px', borderLeft: '2px solid #e5484d' }}>
                  <span className="danger" style={{ fontSize: 12 }}>{inventoryError}</span>
                </div>
              )}

              {/* Manual add form */}
              <div className="panel" style={{ padding: '16px 20px' }}>
                <div className="section-hdr" style={{ marginBottom: 10 }}><strong>Add Asset Manually</strong><span className="muted" style={{ fontSize: 11 }}>for devices the agent can't auto-detect</span></div>
                <form onSubmit={submitManualAsset} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                  <input
                    placeholder="Device name (required)"
                    value={addForm.device_identity_hint}
                    onChange={e => setAddForm({ ...addForm, device_identity_hint: e.target.value })}
                    style={{ flex: '1 1 220px', background: '#0e1013', border: '1px solid #1c1f26', borderRadius: 4, padding: '8px 10px', color: '#e6e9ef', fontSize: 12 }}
                  />
                  <input
                    placeholder="IP address(es), comma-separated"
                    value={addForm.ip_addresses}
                    onChange={e => setAddForm({ ...addForm, ip_addresses: e.target.value })}
                    style={{ flex: '1 1 220px', background: '#0e1013', border: '1px solid #1c1f26', borderRadius: 4, padding: '8px 10px', color: '#e6e9ef', fontSize: 12 }}
                  />
                  <input
                    placeholder="MAC address (optional)"
                    value={addForm.mac_address}
                    onChange={e => setAddForm({ ...addForm, mac_address: e.target.value })}
                    style={{ flex: '1 1 160px', background: '#0e1013', border: '1px solid #1c1f26', borderRadius: 4, padding: '8px 10px', color: '#e6e9ef', fontSize: 12 }}
                  />
                  <select
                    value={addForm.os_guess}
                    onChange={e => setAddForm({ ...addForm, os_guess: e.target.value })}
                    style={{ background: '#0e1013', border: '1px solid #1c1f26', borderRadius: 4, padding: '8px 10px', color: '#e6e9ef', fontSize: 12 }}
                  >
                    {['unknown', 'windows', 'linux', 'bsd', 'network-appliance', 'embedded-or-iot'].map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                  <button type="submit" className="pill-btn active" style={{ fontSize: 12, padding: '8px 16px' }}>Add Asset</button>
                </form>
              </div>

              <div className="section-hdr">
                <strong>Inventory</strong>
                <div style={{ display: 'flex', gap: 4 }}>
                  {[['PENDING', `Pending (${pendingCount})`], ['CONFIRMED', 'Confirmed'], ['ALL', 'All']].map(([id, label]) => (
                    <button key={id} onClick={() => setInventoryFilter(id)} className={`pill-btn ${inventoryFilter === id ? 'active' : ''}`} style={{ fontSize: 11 }}>{label}</button>
                  ))}
                </div>
              </div>

              <div className="panel">
                <table>
                  <thead>
                    <tr><th>Device</th><th>Source</th><th>IP / MAC</th><th>OS Guess</th><th>Status</th><th style={{ textAlign: 'right' }}>Actions</th></tr>
                  </thead>
                  <tbody>
                    {visibleInventory.map(a => (
                      <tr key={a.asset_id} className="log-row">
                        <td onClick={() => setModal({ title: a.asset_id, raw: JSON.stringify(a, null, 2) })}>
                          <strong>{a.device_identity_hint || a.asset_id}</strong>
                        </td>
                        <td className="sub" style={{ fontSize: 12 }}>
                          <span className={a.source === 'manual' ? 'teal' : 'muted'}>{a.source === 'manual' ? 'Manual' : 'Auto-detected'}</span>
                        </td>
                        <td className="sub" style={{ fontSize: 12 }}>{[...(a.ip_addresses || []), a.mac_address].filter(Boolean).join(', ') || '—'}</td>
                        <td className="sub" style={{ fontSize: 12 }}>{a.os_guess}</td>
                        <td style={{ fontSize: 11.5 }}>
                          <span className={a.confirmed ? 'teal' : 'danger'}>{a.confirmed ? 'Confirmed' : 'Pending review'}</span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                            {!a.confirmed && (
                              <button onClick={() => confirmAsset(a.asset_id)} className="pill-btn active" style={{ fontSize: 11 }}>Confirm</button>
                            )}
                            <button onClick={() => removeAsset(a.asset_id)} className="pill-btn" style={{ fontSize: 11 }}>Remove</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                    {visibleInventory.length === 0 && (
                      <tr><td colSpan={6} className="muted" style={{ fontSize: 12, textAlign: 'center', padding: 20 }}>No assets in this view.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
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
                      const flow = `${e.src_ip}:${e.src_port ?? ''} → ${e.dst_ip}:${e.dst_port ?? ''}`;
                      const flagged = isSuspiciousEvent(e);
                      const meta = e.protocol_metadata;
                      return (
                        <tr key={e.event_id} className={`log-row ${flagged ? 'flagged' : ''}`} onClick={() => setModal({
                          title: `Packet Inspection (${e.event_id})`,
                          raw: `Sensor: ${e.sensor_id}\nFlow:   ${flow}\nBytes:  ${e.length_bytes || 512} B\n\n${JSON.stringify(meta, null, 2)}`
                        })}>
                          <td className={flagged ? 'danger' : 'sub'} style={{ fontSize: 11.5, borderLeft: flagged ? '2px solid #e5484d' : 'none' }}>{flagged ? 'Flagged' : 'Pass'}</td>
                          <td className="muted" style={{ fontSize: 12 }}>{new Date(e["@timestamp"]).toLocaleTimeString([], { hour12: false })}</td>
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