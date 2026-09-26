import React, { useState } from 'react';

const INITIAL_ASSETS = [
  {
    asset_id: "aa:bb:cc:dd:ee:ff",
    device_identity_hint: "CT_SCANNER_3",
    os_guess: "linux",
    ip_addresses: ["10.0.0.5"],
    observed_protocols: ["dicom", "https"],
    observed_ports: [51000, 104]
  },
  {
    asset_id: "11:22:33:44:55:66",
    device_identity_hint: "ICU_INFUSION_PUMP_04",
    os_guess: "embedded-or-iot",
    ip_addresses: ["10.0.0.42"],
    observed_protocols: ["hl7"],
    observed_ports: [2575]
  },
  {
    asset_id: "22:33:44:55:66:77",
    device_identity_hint: "PATIENT_MONITOR_RM12",
    os_guess: "embedded-or-iot",
    ip_addresses: ["10.0.0.18"],
    observed_protocols: ["http", "dns"],
    observed_ports: [80, 53]
  }
];

const INITIAL_EVENTS = [
  {
    event_id: "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    timestamp: "2026-09-25T22:21:02.293Z",
    src: "10.0.0.5:51000",
    dst: "10.0.0.20:104",
    application: "dicom",
    metadata: { called_ae_title: "PACS_MAIN", calling_ae_title: "CT_SCANNER_3" },
    is_suspicious: false
  },
  {
    event_id: "7bc12e91-8812-4112-a1bc-1d892e55bca2",
    timestamp: "2026-09-25T22:23:15.000Z",
    src: "10.0.0.42:49152",
    dst: "198.51.100.14:2575",
    application: "hl7",
    metadata: { note: "Unencrypted clinical telemetry to external IP" },
    is_suspicious: true
  },
  {
    event_id: "9cb22a01-1111-4882-b3fc-8c963f66cce3",
    timestamp: "2026-09-25T22:25:00.000Z",
    src: "10.0.0.18:5353",
    dst: "8.8.8.8:53",
    application: "dns",
    metadata: { query: "time.nist.gov" },
    is_suspicious: false
  }
];

export default function App() {
  const [assets] = useState(INITIAL_ASSETS);
  const [events] = useState(INITIAL_EVENTS);
  const [selectedFilter, setSelectedFilter] = useState('ALL');
  const [activeTab, setActiveTab] = useState('DASHBOARD'); // 'DASHBOARD' | 'KIBANA'

  // Filter events based on UI selection
  const filteredEvents = events.filter(e => {
    if (selectedFilter === 'SUSPICIOUS') return e.is_suspicious;
    if (selectedFilter === 'DICOM') return e.application === 'dicom';
    if (selectedFilter === 'HL7') return e.application === 'hl7';
    return true;
  });

  const suspiciousCount = events.filter(e => e.is_suspicious).length;

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#0b0f19',
      color: '#e2e8f0',
      padding: '32px',
      fontFamily: 'system-ui, sans-serif'
    }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        
        {/* Navigation & Header */}
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <div>
            <h1 style={{ margin: 0, fontSize: '26px' }}>MedWatch IoMT Center</h1>
            <p style={{ margin: '6px 0 0 0', color: '#8392a7', fontSize: '14px' }}>
              Passive Sensor Telemetry & Protocol Threat Monitor
            </p>
          </div>
          
          <div style={{ display: 'flex', gap: '10px' }}>
            <button 
              onClick={() => setActiveTab('DASHBOARD')}
              style={{
                background: activeTab === 'DASHBOARD' ? '#38bdf8' : '#151d30',
                color: activeTab === 'DASHBOARD' ? '#0b0f19' : '#e2e8f0',
                border: '1px solid #232f48',
                padding: '8px 16px',
                borderRadius: '6px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              SOC View
            </button>
            <button 
              onClick={() => setActiveTab('KIBANA')}
              style={{
                background: activeTab === 'KIBANA' ? '#38bdf8' : '#151d30',
                color: activeTab === 'KIBANA' ? '#0b0f19' : '#e2e8f0',
                border: '1px solid #232f48',
                padding: '8px 16px',
                borderRadius: '6px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Kibana Logs
            </button>
          </div>
        </header>

        {activeTab === 'KIBANA' ? (
          /* Kibana / Logstash Integration Tab */
          <div style={{ background: '#151d30', border: '1px solid #232f48', borderRadius: '8px', padding: '24px', textAlign: 'center' }}>
            <h3>Elasticsearch / Kibana Raw Log Stream</h3>
            <p style={{ color: '#8392a7', fontSize: '14px', marginBottom: '20px' }}>
              Connected to middle layer Logstash ingestion pipeline.
            </p>
            {/* When your teammate launches Kibana, put their URL here (e.g., http://localhost:5601) */}
            <iframe 
              src="http://localhost:5601" 
              title="Kibana Embed"
              style={{ width: '100%', height: '600px', border: '1px solid #232f48', borderRadius: '6px', background: '#0b0f19' }}
            />
          </div>
        ) : (
          /* Main SOC Dashboard View */
          <>
            {/* Metrics Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '32px' }}>
              <div style={{ background: '#151d30', border: '1px solid #232f48', borderRadius: '8px', padding: '20px' }}>
                <h4 style={{ margin: '0 0 8px 0', color: '#8392a7', fontSize: '13px', textTransform: 'uppercase' }}>Discovered Devices</h4>
                <div style={{ fontSize: '32px', fontWeight: '700', color: '#38bdf8' }}>{assets.length}</div>
              </div>
              <div style={{ background: '#151d30', border: '1px solid #232f48', borderRadius: '8px', padding: '20px' }}>
                <h4 style={{ margin: '0 0 8px 0', color: '#8392a7', fontSize: '13px', textTransform: 'uppercase' }}>Ingested Events</h4>
                <div style={{ fontSize: '32px', fontWeight: '700', color: '#e2e8f0' }}>{events.length}</div>
              </div>
              <div style={{ background: '#151d30', border: '1px solid #232f48', borderRadius: '8px', padding: '20px' }}>
                <h4 style={{ margin: '0 0 8px 0', color: '#8392a7', fontSize: '13px', textTransform: 'uppercase' }}>Suspicious Anomalies</h4>
                <div style={{ fontSize: '32px', fontWeight: '700', color: '#f87171' }}>{suspiciousCount}</div>
              </div>
            </div>

            {/* Active Medical Devices */}
            <h2 style={{ fontSize: '18px', marginBottom: '16px' }}>Active Clinical Assets</h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '16px', marginBottom: '40px' }}>
              {assets.map(a => (
                <div key={a.asset_id} style={{ background: '#151d30', border: '1px solid #232f48', borderRadius: '8px', padding: '16px' }}>
                  <div style={{ fontWeight: '700', fontSize: '15px', color: '#38bdf8' }}>{a.device_identity_hint}</div>
                  <div style={{ fontSize: '13px', color: '#8392a7', marginTop: '6px' }}><strong>OS:</strong> {a.os_guess}</div>
                  <div style={{ fontSize: '13px', color: '#8392a7' }}><strong>IPs:</strong> {a.ip_addresses.join(", ")}</div>
                  <div style={{ fontSize: '13px', color: '#8392a7' }}><strong>Protocols:</strong> {a.observed_protocols.join(", ")}</div>
                </div>
              ))}
            </div>

            {/* Event Table Section with Filter Pills */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h2 style={{ fontSize: '18px', margin: 0 }}>Protocol Stream Feed</h2>
              <div style={{ display: 'flex', gap: '8px' }}>
                {['ALL', 'SUSPICIOUS', 'DICOM', 'HL7'].map(filter => (
                  <button
                    key={filter}
                    onClick={() => setSelectedFilter(filter)}
                    style={{
                      background: selectedFilter === filter ? '#38bdf8' : '#151d30',
                      color: selectedFilter === filter ? '#0b0f19' : '#8392a7',
                      border: '1px solid #232f48',
                      padding: '4px 10px',
                      borderRadius: '4px',
                      fontSize: '12px',
                      fontWeight: '600',
                      cursor: 'pointer'
                    }}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            </div>

            <table style={{ width: '100%', borderCollapse: 'collapse', background: '#151d30', border: '1px solid #232f48', borderRadius: '8px', overflow: 'hidden', fontSize: '13px' }}>
              <thead>
                <tr style={{ background: '#111726', textAlign: 'left', color: '#8392a7' }}>
                  <th style={{ padding: '12px 16px' }}>Status</th>
                  <th style={{ padding: '12px 16px' }}>Timestamp</th>
                  <th style={{ padding: '12px 16px' }}>Source</th>
                  <th style={{ padding: '12px 16px' }}>Destination</th>
                  <th style={{ padding: '12px 16px' }}>Protocol</th>
                  <th style={{ padding: '12px 16px' }}>Metadata</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map(e => (
                  <tr key={e.event_id} style={{
                    borderBottom: '1px solid #232f48',
                    backgroundColor: e.is_suspicious ? 'rgba(248, 113, 113, 0.1)' : 'transparent'
                  }}>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{
                        padding: '3px 8px',
                        borderRadius: '4px',
                        fontWeight: '700',
                        fontSize: '11px',
                        background: e.is_suspicious ? 'rgba(248, 113, 113, 0.2)' : 'rgba(74, 222, 128, 0.15)',
                        color: e.is_suspicious ? '#f87171' : '#4ade80'
                      }}>
                        {e.is_suspicious ? 'ALERT: SUSPICIOUS' : 'NORMAL'}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px' }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                    <td style={{ padding: '12px 16px' }}><code>{e.src}</code></td>
                    <td style={{ padding: '12px 16px' }}><code>{e.dst}</code></td>
                    <td style={{ padding: '12px 16px', fontWeight: '600' }}>{e.application.toUpperCase()}</td>
                    <td style={{ padding: '12px 16px' }}><code>{JSON.stringify(e.metadata)}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  );
}