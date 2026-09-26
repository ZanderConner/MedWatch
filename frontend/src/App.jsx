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

// Formats a whole-seconds uptime as "2d 4h 12m" (drops leading zero
// units so a freshly-booted backend shows "12m" not "0d 0h 12m").
function formatUptime(seconds) {
  if (seconds == null) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (d || h) parts.push(`${h}h`);
  if (d || h || m) parts.push(`${m}m`);
  if (!d && !h) parts.push(`${s}s`);
  return parts.join(' ');
}

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
  const [inventoryFilter, setInventoryFilter] = useState('ALL');
  const [addForm, setAddForm] = useState({ device_identity_hint: '', ip_addresses: '', mac_address: '', os_guess: 'unknown' });
  const [page, setPage] = useState('OVERVIEW');
  const [sensor, setSensor] = useState('ALL');
  const [filter, setFilter] = useState('ALL');
  const [modal, setModal] = useState(null);
  const [editingAsset, setEditingAsset] = useState(null);
  const [editForm, setEditForm] = useState({ device_identity_hint: '', os_guess: 'unknown', ip_addresses: '', mac_address: '', notes: '' });
  // Analytics lookback window, in minutes (0 = no lower bound / all time).
  // Drives every /api/v1/analytics/* fetch below so the Analytics page can
  // be scoped to "last 15 min" through "all time" instead of being stuck
  // showing whatever's in the last (capped) 500-event fetch.
  const [lookbackMinutes, setLookbackMinutes] = useState(60);
  const [analyticsData, setAnalyticsData] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);
  // Traffic Analysis page: server-paginated/filtered view over the FULL
  // events table (not the 500-row cap used for the live stream widgets).
  const [trafficRows, setTrafficRows] = useState([]);
  const [trafficTotal, setTrafficTotal] = useState(0);
  const [trafficPage, setTrafficPage] = useState(0);
  const [trafficFilters, setTrafficFilters] = useState({ application: '', transport: '', search: '' });
  const TRAFFIC_PAGE_SIZE = 50;
  // Security page: severity breakdown + flagged (alerted) assets, each
  // asset carrying its own list of triggered alert rules/messages.
  const [securityData, setSecurityData] = useState(null);

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
    // Poll every few seconds — analytics/alerts/inventory should feel
    // live for a security-monitoring dashboard, not update once a minute.
    const id = setInterval(() => { load(); loadInventory(); }, 3000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  // System-health snapshot (backend uptime, per-sensor liveness,
  // headline counts) backs the Overview page's "System Status" panel.
  // Fetched independently of the analytics-page effect below since the
  // Overview page needs it even when the Analytics page has never been
  // opened.
  useEffect(() => {
    let cancelled = false;
    const fetchHealth = async () => {
      try {
        const res = await fetch(`${API_URL}/api/v1/analytics/system-health`);
        if (res.ok && !cancelled) setSystemHealth(await res.json());
      } catch {
        // backend unreachable — keep whatever's already on screen
      }
    };
    fetchHealth();
    const id = setInterval(fetchHealth, 3000);
    return () => { cancelled = true; clearInterval(id); };
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

  const unconfirmAsset = async (assetId) => {
    try {
      await adminFetch(`/api/v1/admin/assets/${encodeURIComponent(assetId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ confirmed: false }),
      });
      loadInventory();
    } catch (err) {
      setInventoryError(err.message);
    }
  };

  const startEditAsset = (asset) => {
    setEditingAsset(asset.asset_id);
    setEditForm({
      device_identity_hint: asset.device_identity_hint || '',
      os_guess: asset.os_guess || 'unknown',
      ip_addresses: (asset.ip_addresses || []).join(', '),
      mac_address: asset.mac_address || '',
      notes: asset.notes || '',
    });
  };

  const saveEditAsset = async (assetId) => {
    try {
      await adminFetch(`/api/v1/admin/assets/${encodeURIComponent(assetId)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          device_identity_hint: editForm.device_identity_hint.trim() || null,
          os_guess: editForm.os_guess,
          ip_addresses: editForm.ip_addresses.split(',').map(s => s.trim()).filter(Boolean),
          mac_address: editForm.mac_address.trim() || null,
          notes: editForm.notes.trim() || null,
        }),
      });
      setEditingAsset(null);
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

  // Server-side analytics: aggregated directly by the backend over the
  // FULL events table (not capped to the last 500 rows the rest of this
  // app fetches for the live packet stream), scoped by the selected
  // lookback window and capture-node filter. This is what actually
  // backs the Analytics page's charts — the client-side `analytics`
  // object above only ever sees a capped recent slice and stays for the
  // Overview page's live "last N packets" widgets.
  useEffect(() => {
    if (page !== 'ANALYTICS') return;
    let cancelled = false;
    const fetchAnalytics = async () => {
      const since = lookbackMinutes > 0
        ? new Date(Date.now() - lookbackMinutes * 60_000).toISOString()
        : undefined;
      const qs = new URLSearchParams();
      if (since) qs.set('since', since);
      if (sensor !== 'ALL') qs.set('sensor_id', sensor);
      const qsInterval = new URLSearchParams(qs);
      qsInterval.set('interval', 'minute');
      try {
        const [ts, proto, transport, os, talkers] = await Promise.all([
          fetch(`${API_URL}/api/v1/analytics/events-timeseries?${qsInterval}`).then(r => r.json()),
          fetch(`${API_URL}/api/v1/analytics/protocol-distribution?${qs}`).then(r => r.json()),
          fetch(`${API_URL}/api/v1/analytics/transport-distribution?${qs}`).then(r => r.json()),
          fetch(`${API_URL}/api/v1/analytics/os-distribution?${qs}`).then(r => r.json()),
          fetch(`${API_URL}/api/v1/analytics/top-talkers?limit=10&${qs}`).then(r => r.json()),
        ]);
        if (!cancelled) {
          setAnalyticsData({
            timeseries: ts.buckets || [],
            protocols: proto.distribution || [],
            transports: transport.distribution || [],
            osBreakdown: os.distribution || [],
            topTalkers: talkers.top_talkers || [],
          });
        }
      } catch {
        // backend unreachable — keep whatever's already on screen
      }
    };
    fetchAnalytics();
    const id = setInterval(fetchAnalytics, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, [page, lookbackMinutes, sensor]);

  // Traffic Analysis page fetch: server-side filter/search/paginate over
  // the full events table via GET /api/v1/events (see backend/api/routes.js).
  useEffect(() => {
    if (page !== 'TRAFFIC') return;
    let cancelled = false;
    const fetchTraffic = async () => {
      const qs = new URLSearchParams();
      qs.set('limit', TRAFFIC_PAGE_SIZE);
      qs.set('offset', trafficPage * TRAFFIC_PAGE_SIZE);
      if (sensor !== 'ALL') qs.set('sensor_id', sensor);
      if (trafficFilters.application) qs.set('application', trafficFilters.application);
      if (trafficFilters.transport) qs.set('transport', trafficFilters.transport);
      if (trafficFilters.search) qs.set('search', trafficFilters.search);
      try {
        const body = await fetch(`${API_URL}/api/v1/events?${qs}`).then(r => r.json());
        if (!cancelled) {
          setTrafficRows(body.events || []);
          setTrafficTotal(body.total ?? 0);
        }
      } catch {
        // backend unreachable — keep whatever's already on screen
      }
    };
    fetchTraffic();
    const id = setInterval(fetchTraffic, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, [page, trafficPage, trafficFilters, sensor]);

  // Reset to page 0 whenever a filter changes so you're not stranded on
  // an out-of-range offset for the new (smaller) result set.
  useEffect(() => { setTrafficPage(0); }, [trafficFilters, sensor]);

  // Security page fetch: severity breakdown + flagged assets + policy
  // violations (alerts) bucketed over time for the "Policy Violations
  // Over Time" chart. Always all-time/hourly — the Security page has no
  // lookback-window control (that's the Analytics page's job).
  useEffect(() => {
    if (page !== 'SECURITY') return;
    let cancelled = false;
    const fetchSecurity = async () => {
      try {
        const [breakdown, flagged, violations] = await Promise.all([
          fetch(`${API_URL}/api/v1/security/severity-breakdown`).then(r => r.json()),
          fetch(`${API_URL}/api/v1/security/flagged-assets`).then(r => r.json()),
          fetch(`${API_URL}/api/v1/security/violations-timeseries?interval=minute`).then(r => r.json()),
        ]);
        if (!cancelled) {
          setSecurityData({
            breakdown: breakdown.breakdown || [],
            flaggedAssets: flagged.assets || [],
            violationsTimeseries: violations.buckets || [],
          });
        }
      } catch {
        // backend unreachable — keep whatever's already on screen
      }
    };
    fetchSecurity();
    const id = setInterval(fetchSecurity, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, [page]);


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
            {[['OVERVIEW', 'Overview', sensor === 'ALL' ? (stats?.total_events ?? sensorEvents.length) : sensorEvents.length], ['INVENTORY', 'Asset Inventory', pendingCount || undefined], ['TRAFFIC', 'Traffic Analysis'], ['ANALYTICS', 'Traffic Analytics'], ['SECURITY', 'Security', alertedAssetIds.size || undefined], ['AGENTS', 'Sensors', activeSensors.length]].map(([id, label, count]) => (
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
              <strong>{{ OVERVIEW: "Dashboard", INVENTORY: "Asset Inventory", TRAFFIC: "Traffic Analysis", ANALYTICS: "Traffic Analytics", SECURITY: "Security", AGENTS: "Sensors" }[page]}</strong>
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
                      <td style={{ fontSize: 12 }}><span className={`badge ${ag.active ? 'badge-ok' : 'badge-muted'}`}>{ag.active ? 'Active' : 'Inactive'}</span></td>
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
                  {[['ALL', 'All'], ['CONFIRMED', `Confirmed (${inventory.filter(a => a.confirmed).length})`], ['PENDING', `Pending (${pendingCount})`]].map(([id, label]) => (
                    <button key={id} onClick={() => setInventoryFilter(id)} className={`pill-btn ${inventoryFilter === id ? 'active' : ''}`} style={{ fontSize: 11 }}>{label}</button>
                  ))}
                </div>
              </div>

              <div className="panel">
                <table>
                  <thead>
                    <tr><th>Device</th><th>Source</th><th>IP / MAC</th><th>OS Guess</th><th>Observed Endpoints</th><th>Status</th><th style={{ textAlign: 'right' }}>Actions</th></tr>
                  </thead>
                  <tbody>
                    {visibleInventory.map(a => (
                      <tr key={a.asset_id} className="log-row">
                        {editingAsset === a.asset_id ? (
                          <td colSpan={7} style={{ padding: '14px 16px' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                <input
                                  autoFocus
                                  value={editForm.device_identity_hint}
                                  onChange={e => setEditForm({ ...editForm, device_identity_hint: e.target.value })}
                                  placeholder="Device name"
                                  style={{ flex: '1 1 220px', background: '#0e1013', border: '1px solid #1c1f26', borderRadius: 4, padding: '6px 8px', color: '#e6e9ef', fontSize: 12 }}
                                />
                                <input
                                  value={editForm.ip_addresses}
                                  onChange={e => setEditForm({ ...editForm, ip_addresses: e.target.value })}
                                  placeholder="IP address(es), comma-separated"
                                  style={{ flex: '1 1 220px', background: '#0e1013', border: '1px solid #1c1f26', borderRadius: 4, padding: '6px 8px', color: '#e6e9ef', fontSize: 12 }}
                                />
                                <input
                                  value={editForm.mac_address}
                                  onChange={e => setEditForm({ ...editForm, mac_address: e.target.value })}
                                  placeholder="MAC address"
                                  style={{ flex: '1 1 160px', background: '#0e1013', border: '1px solid #1c1f26', borderRadius: 4, padding: '6px 8px', color: '#e6e9ef', fontSize: 12 }}
                                />
                                <select
                                  value={editForm.os_guess}
                                  onChange={e => setEditForm({ ...editForm, os_guess: e.target.value })}
                                  style={{ background: '#0e1013', border: '1px solid #1c1f26', borderRadius: 4, padding: '6px 8px', color: '#e6e9ef', fontSize: 12 }}
                                >
                                  {['unknown', 'windows', 'linux', 'bsd', 'network-appliance', 'embedded-or-iot'].map(o => <option key={o} value={o}>{o}</option>)}
                                </select>
                              </div>
                              <input
                                value={editForm.notes}
                                onChange={e => setEditForm({ ...editForm, notes: e.target.value })}
                                placeholder='Notes (e.g. "biomed-owned, ticket #412")'
                                style={{ background: '#0e1013', border: '1px solid #1c1f26', borderRadius: 4, padding: '6px 8px', color: '#e6e9ef', fontSize: 12 }}
                              />
                              <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                                <button onClick={() => saveEditAsset(a.asset_id)} className="pill-btn active" style={{ fontSize: 11 }}>Save</button>
                                <button onClick={() => setEditingAsset(null)} className="pill-btn" style={{ fontSize: 11 }}>Cancel</button>
                              </div>
                            </div>
                          </td>
                        ) : (
                          <>
                            <td onClick={() => setModal({ title: a.device_identity_hint || a.asset_id, raw: JSON.stringify(a, null, 2) })}>
                              <strong>{a.device_identity_hint || a.asset_id}</strong>
                              {a.notes && <div className="muted" style={{ fontSize: 10.5, marginTop: 2 }}>{a.notes}</div>}
                            </td>
                            <td className="sub" style={{ fontSize: 12 }}>
                              <span className={a.source === 'manual' ? 'teal' : 'muted'}>{a.source === 'manual' ? 'Manual' : 'Auto-detected'}</span>
                            </td>
                            <td className="sub mono-data" style={{ fontSize: 12 }}>{[...(a.ip_addresses || []), a.mac_address].filter(Boolean).join(', ') || '—'}</td>
                            <td className="sub" style={{ fontSize: 12 }}>{a.os_guess}</td>
                            <td className="sub" style={{ fontSize: 11.5, maxWidth: 220 }}>
                              <div>{(a.observed_protocols || []).map(p => p.toUpperCase()).join(', ') || '—'}</div>
                              <div className="muted mono-data" style={{ fontSize: 10.5 }}>ports: {(a.observed_ports || []).slice(0, 8).join(', ') || '—'}{(a.observed_ports || []).length > 8 ? ` +${a.observed_ports.length - 8} more` : ''}</div>
                            </td>
                            <td style={{ fontSize: 11.5 }}>
                              <span className={`badge ${a.confirmed ? 'badge-ok' : 'badge-warn'}`}>{a.confirmed ? 'Confirmed' : 'Pending'}</span>
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                                {!a.confirmed && (
                                  <button onClick={() => confirmAsset(a.asset_id)} className="pill-btn active" style={{ fontSize: 11 }}>Confirm</button>
                                )}
                                {a.confirmed && a.source !== 'manual' && (
                                  <button onClick={() => unconfirmAsset(a.asset_id)} className="pill-btn" style={{ fontSize: 11 }}>Unconfirm</button>
                                )}
                                <button onClick={() => startEditAsset(a)} className="pill-btn" style={{ fontSize: 11 }}>Edit</button>
                                <button onClick={() => removeAsset(a.asset_id)} className="pill-btn" style={{ fontSize: 11 }}>Remove</button>
                              </div>
                            </td>
                          </>
                        )}
                      </tr>
                    ))}
                    {visibleInventory.length === 0 && (
                      <tr><td colSpan={7} className="muted" style={{ fontSize: 12, textAlign: 'center', padding: 20 }}>No assets in this view.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* PAGE 2: ANALYTICS */}
          {page === 'ANALYTICS' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              <div className="section-hdr">
                <strong>Lookback Window</strong>
                <div style={{ display: 'flex', gap: 4 }}>
                  {[[15, '15m'], [60, '1h'], [360, '6h'], [1440, '24h'], [10080, '7d'], [0, 'All time']].map(([mins, label]) => (
                    <button key={mins} onClick={() => setLookbackMinutes(mins)} className={`pill-btn ${lookbackMinutes === mins ? 'active' : ''}`} style={{ fontSize: 11 }}>{label}</button>
                  ))}
                </div>
              </div>

              <div className="panel" style={{ padding: '18px 20px' }}>
                <div className="section-hdr"><strong>Network Traffic Over Time</strong><span className="muted" style={{ fontSize: 11 }}>server-aggregated, full history in window</span></div>
                {(() => {
                  const b = analyticsData?.timeseries || [];
                  const maxB = Math.max(...b.map(x => x.count), 1);
                  const pts = b.map((x, i) => ({ ...x, x: 36 + (b.length > 1 ? (i / (b.length - 1)) * 868 : 434), y: 14 + 125 - (x.count / maxB) * 125 }));
                  const line = pts.map((p, i) => `${i ? 'L' : 'M'} ${p.x} ${p.y}`).join(' ');
                  return (
                    <svg viewBox="0 0 920 165" style={{ width: '100%', height: 175 }}>
                      {pts.length > 1 && <path d={`${line} L ${pts.at(-1).x} 139 L ${pts[0].x} 139 Z`} fill="rgba(45,212,191,0.08)" />}
                      {pts.length > 1 && <path d={line} fill="none" stroke="#2dd4bf" strokeWidth="1.5" />}
                      {pts.map((p, i) => (
                        <g key={i}>
                          <circle cx={p.x} cy={p.y} r={2.5} fill="#0e1013" stroke="#2dd4bf" strokeWidth="1.5" />
                          <text x={p.x} y="158" textAnchor="middle" fill="#636975" fontSize="9">{p.bucket?.slice(5, 16).replace('T', ' ')}</text>
                        </g>
                      ))}
                      {pts.length === 0 && <text x="460" y="80" textAnchor="middle" fill="#636975" fontSize="12">No events in this window</text>}
                    </svg>
                  );
                })()}
              </div>

              <div className="split-grid">
                <div style={{ padding: '18px 20px', borderRight: '1px solid #1c1f26' }}>
                  <div className="section-hdr"><strong>Application Protocols</strong><span className="muted" style={{ fontSize: 11 }}>EVENTS</span></div>
                  {(() => {
                    const dist = analyticsData?.protocols || [];
                    const total = dist.reduce((s, d) => s + d.count, 0) || 1;
                    return dist.map(p => (
                      <div key={p.application} className="bar-row">
                        <div className="bar-fill" style={{ width: `${Math.round((p.count / total) * 100)}%`, background: 'rgba(45,212,191,0.06)', borderLeft: '2px solid #2dd4bf' }} />
                        <span style={{ position: 'relative' }}>{(p.application || 'unknown').toUpperCase()}</span>
                        <span className="sub" style={{ position: 'relative', fontSize: 12 }}>{p.count}</span>
                      </div>
                    ));
                  })()}
                </div>
                <div style={{ padding: '18px 20px' }}>
                  <div className="section-hdr"><strong>Transport</strong><span className="muted" style={{ fontSize: 11 }}>EVENTS</span></div>
                  {(() => {
                    const dist = analyticsData?.transports || [];
                    const total = dist.reduce((s, d) => s + d.count, 0) || 1;
                    return dist.map(t => (
                      <div key={t.transport} className="bar-row">
                        <div className="bar-fill" style={{ width: `${Math.round((t.count / total) * 100)}%`, background: 'rgba(138,143,152,0.06)', borderLeft: '2px solid #636975' }} />
                        <span style={{ position: 'relative' }}>{(t.transport || 'other').toUpperCase()}</span>
                        <span className="sub" style={{ position: 'relative', fontSize: 12 }}>{t.count}</span>
                      </div>
                    ));
                  })()}
                </div>
              </div>

              <div className="split-grid">
                <div style={{ padding: '18px 20px', borderRight: '1px solid #1c1f26' }}>
                  <div className="section-hdr"><strong>Asset OS Classification</strong><span className="muted" style={{ fontSize: 11 }}>ASSETS</span></div>
                  {(() => {
                    const dist = analyticsData?.osBreakdown || [];
                    const total = dist.reduce((s, d) => s + d.count, 0) || 1;
                    return dist.map(o => (
                      <div key={o.os_guess} className="bar-row">
                        <div className="bar-fill" style={{ width: `${Math.round((o.count / total) * 100)}%`, background: 'rgba(45,212,191,0.06)', borderLeft: '2px solid #2dd4bf' }} />
                        <span style={{ position: 'relative' }}>{o.os_guess}</span>
                        <span className="sub" style={{ position: 'relative', fontSize: 12 }}>{o.count}</span>
                      </div>
                    ));
                  })()}
                </div>
                <div style={{ padding: '18px 20px' }}>
                  <div className="section-hdr"><strong>Top Source Endpoints</strong><span className="muted" style={{ fontSize: 11 }}>EVENTS</span></div>
                  {(() => {
                    const talkers = analyticsData?.topTalkers || [];
                    const maxCount = Math.max(...talkers.map(t => t.event_count), 1);
                    return talkers.map(t => {
                      const asset = assets.find(a => a.asset_id === t.asset_id);
                      const flagged = t.asset_id && alertedAssetIds.has(t.asset_id);
                      const pct = Math.round((t.event_count / maxCount) * 100);
                      return (
                        <div key={t.ip} className="bar-row">
                          <div className="bar-fill" style={{ width: `${pct}%`, background: flagged ? 'rgba(229,72,77,0.07)' : 'rgba(138,143,152,0.06)', borderLeft: `2px solid ${flagged ? '#e5484d' : '#636975'}` }} />
                          <span style={{ position: 'relative' }}>{asset?.device_identity_hint || t.ip} <span className="muted" style={{ fontSize: 11.5, marginLeft: 4 }}>{t.ip}</span></span>
                          <span style={{ position: 'relative', fontSize: 12 }}>
                            <span className={flagged ? 'danger' : 'muted'} style={{ marginRight: 14 }}>{flagged ? 'flagged' : 'ok'}</span>
                            {t.event_count} evts
                          </span>
                        </div>
                      );
                    });
                  })()}
                </div>
              </div>
            </div>
          )}

          {/* PAGE: TRAFFIC ANALYSIS — full, server-filtered/searched/paginated events */}
          {page === 'TRAFFIC' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="panel" style={{ padding: '14px 18px', display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
                <input
                  placeholder="Search IP / MAC..."
                  value={trafficFilters.search}
                  onChange={(e) => setTrafficFilters(f => ({ ...f, search: e.target.value }))}
                  style={{ flex: '1 1 220px', minWidth: 160 }}
                />
                <select value={trafficFilters.application} onChange={(e) => setTrafficFilters(f => ({ ...f, application: e.target.value }))}>
                  <option value="">All protocols</option>
                  {['dicom', 'hl7', 'http', 'https', 'dns', 'dhcp', 'ssh', 'rdp', 'smb', 'arp', 'icmp', 'ntp', 'snmp', 'mdns', 'ldap', 'syslog', 'ftp', 'telnet', 'smtp', 'unknown'].map(a => (
                    <option key={a} value={a}>{a.toUpperCase()}</option>
                  ))}
                </select>
                <select value={trafficFilters.transport} onChange={(e) => setTrafficFilters(f => ({ ...f, transport: e.target.value }))}>
                  <option value="">All transports</option>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
                {(trafficFilters.search || trafficFilters.application || trafficFilters.transport) && (
                  <button className="pill-btn" onClick={() => setTrafficFilters({ application: '', transport: '', search: '' })}>Clear filters</button>
                )}
                <span className="muted" style={{ fontSize: 11, marginLeft: 'auto' }}>{trafficTotal.toLocaleString()} packets matched</span>
              </div>

              <div className="panel">
                <table>
                  <thead>
                    <tr>
                      <th>Time</th><th>Sensor</th><th>Protocol</th><th>Transport</th>
                      <th>Source</th><th>Destination</th><th style={{ textAlign: 'right' }}>Bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trafficRows.map(ev => (
                      <tr key={ev.event_id}>
                        <td className="mono-data" style={{ fontSize: 11.5 }}>{(ev['@timestamp'] || '').replace('T', ' ').slice(0, 19)}</td>
                        <td className="sub">{ev.sensor_id}</td>
                        <td><span className="badge badge-ok" style={{ fontSize: 10.5 }}>{(ev.application || 'unknown').toUpperCase()}</span></td>
                        <td className="sub">{(ev.transport || '').toUpperCase()}</td>
                        <td className="mono-data">{ev.src_ip}{ev.src_port ? `:${ev.src_port}` : ''}</td>
                        <td className="mono-data">{ev.dst_ip}{ev.dst_port ? `:${ev.dst_port}` : ''}</td>
                        <td style={{ textAlign: 'right' }} className="sub">{ev.length_bytes}</td>
                      </tr>
                    ))}
                    {trafficRows.length === 0 && (
                      <tr><td colSpan={7} className="muted" style={{ textAlign: 'center', padding: 24 }}>No packets match these filters</td></tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <button className="pill-btn" disabled={trafficPage === 0} onClick={() => setTrafficPage(p => Math.max(0, p - 1))}>Prev</button>
                <span className="muted" style={{ fontSize: 11 }}>
                  Page {trafficPage + 1} of {Math.max(1, Math.ceil(trafficTotal / TRAFFIC_PAGE_SIZE))}
                </span>
                <button className="pill-btn" disabled={(trafficPage + 1) * TRAFFIC_PAGE_SIZE >= trafficTotal} onClick={() => setTrafficPage(p => p + 1)}>Next</button>
              </div>
            </div>
          )}

          {/* PAGE: SECURITY — violations + severity stats */}
          {page === 'SECURITY' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              <div>
                <div className="section-hdr"><strong>Alert Severity Breakdown</strong><span className="muted" style={{ fontSize: 11 }}>all-time</span></div>
                <div className="ledger">
                  {['critical', 'warning', 'info'].map(sev => {
                    const row = (securityData?.breakdown || []).find(b => b.severity === sev);
                    return (
                      <div key={sev} className="ledger-cell">
                        <div className="sub" style={{ fontSize: 11 }}>{sev.toUpperCase()}</div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 6 }}>
                          <span className={sev === 'critical' ? 'danger' : ''} style={{ fontSize: 19, fontWeight: 500, color: sev !== 'critical' ? '#e6e9ef' : undefined }}>{row?.count ?? 0}</span>
                          <span className={sev === 'critical' && row?.count ? 'danger' : 'muted'} style={{ fontSize: 11 }}>alerts</span>
                        </div>
                      </div>
                    );
                  })}
                  <div className="ledger-cell">
                    <div className="sub" style={{ fontSize: 11 }}>Flagged Assets</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 6 }}>
                      <span className={(securityData?.flaggedAssets?.length ?? 0) ? 'danger' : ''} style={{ fontSize: 19, fontWeight: 500, color: (securityData?.flaggedAssets?.length ?? 0) ? undefined : '#e6e9ef' }}>{securityData?.flaggedAssets?.length ?? 0}</span>
                      <span className={(securityData?.flaggedAssets?.length ?? 0) ? 'danger' : 'muted'} style={{ fontSize: 11 }}>{(securityData?.flaggedAssets?.length ?? 0) ? 'needs review' : 'clear'}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="panel" style={{ padding: '18px 20px' }}>
                <div className="section-hdr"><strong>Policy Violations Over Time</strong><span className="muted" style={{ fontSize: 11 }}>alerts raised per minute, all-time</span></div>
                {(() => {
                  const b = securityData?.violationsTimeseries || [];
                  const maxB = Math.max(...b.map(x => x.count), 1);
                  const pts = b.map((x, i) => ({ ...x, x: 36 + (b.length > 1 ? (i / (b.length - 1)) * 868 : 434), y: 14 + 125 - (x.count / maxB) * 125 }));
                  const line = pts.map((p, i) => `${i ? 'L' : 'M'} ${p.x} ${p.y}`).join(' ');
                  return (
                    <svg viewBox="0 0 920 165" style={{ width: '100%', height: 175 }}>
                      {pts.length > 1 && <path d={`${line} L ${pts.at(-1).x} 139 L ${pts[0].x} 139 Z`} fill="rgba(229,72,77,0.08)" />}
                      {pts.length > 1 && <path d={line} fill="none" stroke="#e5484d" strokeWidth="1.5" />}
                      {pts.map((p, i) => (
                        <g key={i}>
                          <circle cx={p.x} cy={p.y} r={2.5} fill="#0e1013" stroke="#e5484d" strokeWidth="1.5" />
                          <text x={p.x} y="158" textAnchor="middle" fill="#636975" fontSize="9">{p.bucket?.slice(5, 16).replace('T', ' ')}</text>
                        </g>
                      ))}
                      {pts.length === 0 && <text x="460" y="80" textAnchor="middle" fill="#636975" fontSize="12">No violations recorded</text>}
                    </svg>
                  );
                })()}
              </div>

              <div>
                <div className="section-hdr"><strong>Policy Violations</strong><span className="muted" style={{ fontSize: 11 }}>assets with active correlation alerts</span></div>
                <div className="panel">
                  {(securityData?.flaggedAssets || []).length === 0 && (
                    <div className="muted" style={{ textAlign: 'center', padding: 32 }}>No active violations — fleet is clear.</div>
                  )}
                  {(securityData?.flaggedAssets || []).map(asset => (
                    <div key={asset.asset_id} style={{ padding: '16px 20px', borderBottom: '1px solid #1c1f26' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                        <div>
                          <strong>{asset.device_identity_hint || asset.asset_id}</strong>
                          <span className="muted mono-data" style={{ fontSize: 11.5, marginLeft: 8 }}>{(asset.ip_addresses || []).join(', ')}</span>
                        </div>
                        <span className="sub" style={{ fontSize: 11 }}>{asset.os_guess}</span>
                      </div>
                      <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {asset.alerts.map(al => (
                          <div key={al.alert_id} style={{ display: 'flex', gap: 10, alignItems: 'baseline', fontSize: 12.5 }}>
                            <span className={`badge ${al.severity === 'critical' ? 'badge-danger' : al.severity === 'warning' ? 'badge-warn' : 'badge-muted'}`} style={{ fontSize: 10 }}>{al.severity.toUpperCase()}</span>
                            <span>{al.message}</span>
                            <span className="muted" style={{ fontSize: 10.5, marginLeft: 'auto', whiteSpace: 'nowrap' }}>{(al.created_at || '').replace('T', ' ').slice(0, 19)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* PAGE 3: OVERVIEW / DASHBOARD */}
          {page === 'OVERVIEW' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              {/* System status / uptime */}
              <div>
                <div className="section-hdr"><strong>System Status</strong><span className="muted" style={{ fontSize: 11 }}>backend + sensor fleet</span></div>
                <div className="ledger">
                  <div className="ledger-cell">
                    <div className="sub" style={{ fontSize: 11 }}>Backend Uptime</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 6 }}>
                      <span style={{ fontSize: 19, fontWeight: 500, color: '#e6e9ef' }}>{formatUptime(systemHealth?.backend_uptime_seconds)}</span>
                      <span className="teal" style={{ fontSize: 11 }}>online</span>
                    </div>
                  </div>
                  <div className="ledger-cell">
                    <div className="sub" style={{ fontSize: 11 }}>Sensor Fleet</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 6 }}>
                      <span style={{ fontSize: 19, fontWeight: 500, color: '#e6e9ef' }}>{systemHealth?.sensors_active ?? 0}/{systemHealth?.sensors_total ?? 0}</span>
                      <span className="muted" style={{ fontSize: 11 }}>active</span>
                    </div>
                  </div>
                  <div className="ledger-cell">
                    <div className="sub" style={{ fontSize: 11 }}>Confirmed Assets</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 6 }}>
                      <span style={{ fontSize: 19, fontWeight: 500, color: '#e6e9ef' }}>{systemHealth?.confirmed_assets ?? 0}/{systemHealth?.total_assets ?? 0}</span>
                      <span className="muted" style={{ fontSize: 11 }}>vetted</span>
                    </div>
                  </div>
                  <div className="ledger-cell">
                    <div className="sub" style={{ fontSize: 11 }}>Open Alerts</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 6 }}>
                      <span className={systemHealth?.open_alerts ? 'danger' : ''} style={{ fontSize: 19, fontWeight: 500, color: systemHealth?.open_alerts ? undefined : '#e6e9ef' }}>{systemHealth?.open_alerts ?? 0}</span>
                      <span className={systemHealth?.open_alerts ? 'danger' : 'muted'} style={{ fontSize: 11 }}>{systemHealth?.open_alerts ? 'needs review' : 'clear'}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Live stream snippet — most recent events only, full log lives on... nowhere else, this IS the stream, just capped short here */}
              <div>
                <div className="section-hdr">
                  <strong>Live Packet Stream</strong>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {['ALL', 'SUSPICIOUS', 'DICOM', 'HL7', 'HTTP', 'HTTPS', 'DNS', 'ARP', 'ICMP', 'DHCP'].map(f => (
                      <button key={f} onClick={() => setFilter(f)} className={`pill-btn ${filter === f ? 'active' : ''}`} style={{ fontSize: 11 }}>{f}</button>
                    ))}
                  </div>
                </div>
                <div className="panel">
                  <table>
                    <thead><tr><th>State</th><th>Timestamp</th><th>Sensor</th><th>Source → Destination</th><th>Proto</th><th>Decoded Payload</th></tr></thead>
                    <tbody>
                      {filteredEvents.slice(0, 12).map(e => {
                        const flow = `${e.src_ip}${e.src_port ? ':' + e.src_port : ''} → ${e.dst_ip}${e.dst_port ? ':' + e.dst_port : ''}`;
                        const flagged = isSuspiciousEvent(e);
                        const meta = e.protocol_metadata;
                        return (
                          <tr key={e.event_id} className={`log-row ${flagged ? 'flagged' : ''}`} onClick={() => setModal({
                            title: `Packet Inspection (${e.event_id})`,
                            raw: `Sensor: ${e.sensor_id}\nFlow:   ${flow}\nBytes:  ${e.length_bytes || 512} B\n\n${JSON.stringify(meta, null, 2)}`
                          })}>
                            <td className={flagged ? 'danger' : 'sub'} style={{ fontSize: 11.5, borderLeft: flagged ? '2px solid #e5484d' : 'none' }}>
                              <span className={`badge ${flagged ? 'badge-danger' : 'badge-ok'}`}>{flagged ? 'Flagged' : 'Pass'}</span>
                            </td>
                            <td className="muted" style={{ fontSize: 12 }}>{new Date(e["@timestamp"]).toLocaleTimeString([], { hour12: false })}</td>
                            <td className="sub" style={{ fontSize: 12 }}>{e.sensor_id}</td>
                            <td className="mono-data" style={{ fontSize: 12 }}>{flow}</td>
                            <td className="teal" style={{ fontSize: 11.5 }}>{e.application?.toUpperCase()}</td>
                            <td className="muted" style={{ fontSize: 11.5, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{meta ? JSON.stringify(meta) : '—'}</td>
                          </tr>
                        );
                      })}
                      {filteredEvents.length === 0 && (
                        <tr><td colSpan={6} className="muted" style={{ fontSize: 12, textAlign: 'center', padding: 20 }}>No packets seen yet — waiting for sensor traffic.</td></tr>
                      )}
                    </tbody>
                  </table>
                  {filteredEvents.length > 12 && (
                    <div className="muted" style={{ fontSize: 11, textAlign: 'center', padding: '8px 0' }}>
                      showing latest 12 of {filteredEvents.length} — see <span className="teal" style={{ cursor: 'pointer' }} onClick={() => setPage('ANALYTICS')}>Traffic Analytics</span> for full history
                    </div>
                  )}
                </div>
              </div>

              {/* At-a-glance analytics snapshot */}
              <div className="split-grid">
                <div style={{ padding: '18px 20px', borderRight: '1px solid #1c1f26' }}>
                  <div className="section-hdr"><strong>Protocol Mix</strong><span className="muted" style={{ fontSize: 11 }}>last {sensorEvents.length} pkts</span></div>
                  {analytics.protocols.slice(0, 8).map(p => (
                    <div key={p.name} className="bar-row">
                      <div className="bar-fill" style={{ width: `${p.pct}%`, background: 'rgba(45,212,191,0.06)', borderLeft: '2px solid #2dd4bf' }} />
                      <span style={{ position: 'relative' }}>{p.name}</span>
                      <span className="sub" style={{ position: 'relative', fontSize: 12 }}>{p.count}</span>
                    </div>
                  ))}
                  {analytics.protocols.length === 0 && <div className="muted" style={{ fontSize: 12, padding: '10px 0' }}>No traffic yet.</div>}
                </div>
                <div style={{ padding: '18px 20px' }}>
                  <div className="section-hdr"><strong>Top Talkers</strong><span className="muted" style={{ fontSize: 11 }}>by volume</span></div>
                  {analytics.topTalkers.slice(0, 8).map(t => (
                    <div key={t.ip} className="bar-row">
                      <div className="bar-fill" style={{ width: `${Math.round((t.bytes / (analytics.topTalkers[0]?.bytes || 1)) * 100)}%`, background: t.flagged ? 'rgba(229,72,77,0.07)' : 'rgba(138,143,152,0.06)', borderLeft: `2px solid ${t.flagged ? '#e5484d' : '#636975'}` }} />
                      <span style={{ position: 'relative' }}>{t.name}</span>
                      <span className="sub" style={{ position: 'relative', fontSize: 12 }}>{(t.bytes / 1024).toFixed(1)} KB</span>
                    </div>
                  ))}
                  {analytics.topTalkers.length === 0 && <div className="muted" style={{ fontSize: 12, padding: '10px 0' }}>No traffic yet.</div>}
                </div>
              </div>
            </div>
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