import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  Tooltip as RechartsTooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';
import {
  Activity, ShieldAlert, Cpu, Globe, Search,
  Database, Download, Wifi, WifiOff, Shield,
  BarChart3, Network, AlertTriangle, TrendingUp,
} from 'lucide-react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls, Stars } from '@react-three/drei';
import './index.css';

/* ═══════════════════════════════════════════════════════
   3D BACKGROUND SCENE
   ═══════════════════════════════════════════════════════ */
const Scene = () => (
  <Canvas camera={{ position: [0, 0, 10] }}>
    <ambientLight intensity={0.3} />
    <pointLight position={[10, 10, 10]} intensity={0.5} />
    <Stars
      radius={120}
      depth={60}
      count={3000}
      factor={5}
      saturation={0}
      fade
      speed={0.8}
    />
    <OrbitControls
      autoRotate
      autoRotateSpeed={0.4}
      enableZoom={false}
      enablePan={false}
    />
    <mesh rotation={[0.3, 0, 0]}>
      <sphereGeometry args={[3, 48, 48]} />
      <meshStandardMaterial
        color="#0ea5e9"
        wireframe
        transparent
        opacity={0.12}
      />
    </mesh>
    <mesh rotation={[0.3, 0.5, 0]} scale={1.3}>
      <icosahedronGeometry args={[3, 1]} />
      <meshStandardMaterial
        color="#a78bfa"
        wireframe
        transparent
        opacity={0.06}
      />
    </mesh>
  </Canvas>
);

/* ═══════════════════════════════════════════════════════
   HELPER: Protocol colors
   ═══════════════════════════════════════════════════════ */
const PROTOCOL_COLORS = {
  TCP: '#38bdf8',
  UDP: '#a78bfa',
  HTTP: '#34d399',
  HTTPS: '#6ee7b7',
  DNS: '#fbbf24',
  ICMP: '#fb7185',
  ARP: '#c4b5fd',
  SSH: '#f472b6',
  OTHER: '#94a3b8',
};

const PIE_COLORS = ['#38bdf8', '#a78bfa', '#fb7185', '#fbbf24', '#94a3b8', '#34d399', '#c4b5fd'];

/* ═══════════════════════════════════════════════════════
   HELPER: IP tag classification
   ═══════════════════════════════════════════════════════ */
function getTagClass(info) {
  if (!info) return '';
  const lower = info.toLowerCase();
  if (lower === 'local') return 'local';
  if (lower === 'public') return 'public';
  if (lower === 'multicast') return 'multicast';
  if (lower === 'loopback') return 'loopback';
  if (lower === 'reserved') return 'reserved';
  return '';
}

/* ═══════════════════════════════════════════════════════
   CUSTOM TOOLTIP FOR PIE CHART
   ═══════════════════════════════════════════════════════ */
const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload || !payload.length) return null;
  const { name, value } = payload[0];
  return (
    <div style={{
      background: 'rgba(10, 15, 30, 0.9)',
      backdropFilter: 'blur(10px)',
      border: '1px solid rgba(56, 189, 248, 0.2)',
      borderRadius: '10px',
      padding: '10px 14px',
      color: '#f1f5f9',
      fontSize: '0.8rem',
      boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
    }}>
      <div style={{ fontWeight: 700 }}>{name}</div>
      <div style={{ color: '#94a3b8', marginTop: 2 }}>{value.toLocaleString()} packets</div>
    </div>
  );
};

/* ═══════════════════════════════════════════════════════
   MAIN APP COMPONENT
   ═══════════════════════════════════════════════════════ */
export default function App() {
  const [packets, setPackets] = useState([]);
  const [connected, setConnected] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    total: 0, tcp: 0, udp: 0, dns: 0, http: 0, https: 0,
    icmp: 0, arp: 0,
    protocolData: [], topIps: [],
  });
  const [filter, setFilter] = useState('');
  const tableRef = useRef(null);

  /* ── Connect to SSE stream ── */
  useEffect(() => {
    const source = new EventSource('/stream');

    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);

    source.onmessage = (e) => {
      const data = JSON.parse(e.data);
      const p = data.packet;

      setStats({
        total: data.total_packets,
        tcp: data.stats.TCP || 0,
        udp: data.stats.UDP || 0,
        dns: data.stats.DNS || 0,
        http: data.stats.HTTP || 0,
        https: data.stats.HTTPS || 0,
        icmp: data.stats.ICMP || 0,
        arp: data.stats.ARP || 0,
        protocolData: [
          { name: 'TCP', value: data.stats.TCP || 0 },
          { name: 'UDP', value: data.stats.UDP || 0 },
          { name: 'ICMP', value: data.stats.ICMP || 0 },
          { name: 'ARP', value: data.stats.ARP || 0 },
          { name: 'DNS', value: data.stats.DNS || 0 },
          { name: 'HTTP', value: data.stats.HTTP || 0 },
          { name: 'HTTPS', value: data.stats.HTTPS || 0 },
        ].filter(d => d.value > 0),
        topIps: data.stats.top_ips || [],
      });

      if (p.alert) {
        setAlerts(prev => [
          { id: Date.now() + Math.random(), time: p.time, text: p.alert },
          ...prev,
        ].slice(0, 20));
      }

      setPackets(prev => {
        const next = [p, ...prev];
        if (next.length > 100) next.length = 100;
        return next;
      });
    };

    return () => source.close();
  }, []);

  /* ── Filtered packets ── */
  const filteredPackets = useMemo(() => {
    if (!filter) return packets;
    const q = filter.toLowerCase();
    return packets.filter(p =>
      p.src?.toLowerCase().includes(q) ||
      p.dst?.toLowerCase().includes(q) ||
      p.protocol?.toLowerCase().includes(q) ||
      p.info?.toLowerCase().includes(q)
    );
  }, [packets, filter]);

  /* ── Max IP count for bars ── */
  const maxIpCount = useMemo(() => {
    if (!stats.topIps.length) return 1;
    return Math.max(...stats.topIps.map(ip => ip.count), 1);
  }, [stats.topIps]);

  /* ── KPI data ── */
  const kpiItems = [
    { label: 'Total Captured', val: stats.total, color: '#38bdf8', accent: 'cyan', Icon: Database },
    { label: 'TCP Segments', val: stats.tcp, color: '#38bdf8', accent: 'cyan', Icon: Activity },
    { label: 'UDP Datagrams', val: stats.udp, color: '#a78bfa', accent: 'violet', Icon: Globe },
    { label: 'DNS Queries', val: stats.dns, color: '#fbbf24', accent: 'amber', Icon: Search },
    { label: 'Alerts', val: alerts.length, color: '#fb7185', accent: 'rose', Icon: ShieldAlert },
  ];

  return (
    <div className="app-root">
      {/* Ambient backgrounds */}
      <div className="ambient-bg" />
      <div className="grid-pattern" />
      <div className="three-bg">
        <Scene />
      </div>

      <div className="main-content">
        {/* ═══ NAV BAR ═══ */}
        <nav className="nav-bar" id="nav-bar">
          <div className="nav-brand">
            <div className="nav-logo">
              <Shield size={24} color="#38bdf8" />
            </div>
            <div>
              <div className="nav-title">SystemSniffer</div>
              <div className="nav-subtitle">Network Monitor & IDS</div>
            </div>
          </div>
          <div className="nav-actions">
            <a
              className="btn-download"
              href="/download"
              id="download-btn"
            >
              <Download size={16} />
              Export Logs
            </a>
            <div
              className={`status-pill ${connected ? 'live' : 'offline'}`}
              id="status-indicator"
            >
              <div className="status-dot" />
              {connected ? 'Stream Live' : 'Disconnected'}
            </div>
          </div>
        </nav>

        {/* ═══ KPI STRIP ═══ */}
        <div className="kpi-strip" id="kpi-strip">
          {kpiItems.map((kpi, i) => (
            <div key={i} className={`kpi-card ${kpi.accent}`} id={`kpi-${kpi.accent}`}>
              <div>
                <p className="kpi-label">{kpi.label}</p>
                <p className="kpi-value" style={{ color: kpi.color }}>
                  {kpi.val.toLocaleString()}
                </p>
              </div>
              <div className={`kpi-icon-wrap ${kpi.accent}`}>
                <kpi.Icon size={22} color={kpi.color} />
              </div>
            </div>
          ))}
        </div>

        {/* ═══ DASHBOARD GRID ═══ */}
        <div className="dashboard-grid">
          {/* ── Left sidebar ── */}
          <div className="sidebar-stack">
            {/* ALERTS */}
            <div className="panel alert-panel" id="alerts-panel">
              <div className="panel-head">
                <div className="panel-title">
                  <ShieldAlert size={18} color="#ef4444" />
                  <span>Intrusion Alerts</span>
                </div>
                <span className="panel-badge" style={{
                  background: 'rgba(239, 68, 68, 0.1)',
                  color: '#ef4444',
                }}>
                  {alerts.length}
                </span>
              </div>
              <div className="panel-body" style={{ maxHeight: 260 }}>
                {alerts.length === 0 ? (
                  <div className="alert-empty">
                    <Shield size={36} className="alert-empty-icon" />
                    <p className="alert-empty-text">All clear — no threats detected</p>
                  </div>
                ) : (
                  alerts.map(a => (
                    <div key={a.id} className="alert-item">
                      <span className="alert-time">{a.time}</span>
                      {a.text}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* PIE CHART */}
            <div className="panel chart-panel" id="protocol-chart">
              <div className="panel-head">
                <div className="panel-title">
                  <BarChart3 size={18} color="#38bdf8" />
                  <span>Protocol Distribution</span>
                </div>
              </div>
              <div className="chart-body">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={stats.protocolData}
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={80}
                      paddingAngle={4}
                      dataKey="value"
                      stroke="none"
                    >
                      {stats.protocolData.map((entry, idx) => (
                        <Cell
                          key={idx}
                          fill={PROTOCOL_COLORS[entry.name] || PIE_COLORS[idx % PIE_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <RechartsTooltip content={<CustomTooltip />} />
                    <Legend
                      wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }}
                      iconType="circle"
                      iconSize={8}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* TOP IPs */}
            <div className="panel" id="top-ips-panel">
              <div className="panel-head">
                <div className="panel-title">
                  <TrendingUp size={18} color="#a78bfa" />
                  <span>Top Active IPs</span>
                </div>
                <span className="panel-badge">{stats.topIps.length}</span>
              </div>
              <div className="ip-list">
                {stats.topIps.length === 0 ? (
                  <div className="alert-empty" style={{ padding: '24px' }}>
                    <Network size={28} style={{ opacity: 0.2 }} />
                    <p className="alert-empty-text">Awaiting traffic…</p>
                  </div>
                ) : (
                  stats.topIps.map((ip, i) => (
                    <div key={i} className="ip-row">
                      <div className="ip-rank">
                        <span className="ip-rank-num">{i + 1}</span>
                        <span className="ip-addr">{ip.ip}</span>
                      </div>
                      <div className="ip-bar-wrap">
                        <div
                          className="ip-bar"
                          style={{ width: `${(ip.count / maxIpCount) * 100}%` }}
                        />
                      </div>
                      <span className="ip-count">{ip.count.toLocaleString()}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* ── Live Traffic Feed ── */}
          <div className="panel feed-panel" id="traffic-feed">
            <div className="panel-head">
              <div className="panel-title">
                <Activity size={18} color="#38bdf8" />
                <h2 style={{ fontSize: '0.9rem', fontWeight: 600 }}>Live Traffic Feed</h2>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{
                  position: 'relative',
                  display: 'flex',
                  alignItems: 'center',
                }}>
                  <Search
                    size={14}
                    color="#64748b"
                    style={{ position: 'absolute', left: 10, pointerEvents: 'none' }}
                  />
                  <input
                    id="filter-input"
                    type="text"
                    placeholder="Filter…"
                    value={filter}
                    onChange={e => setFilter(e.target.value)}
                    style={{
                      background: 'rgba(0,0,0,0.3)',
                      border: '1px solid rgba(55,65,81,0.3)',
                      borderRadius: 8,
                      padding: '7px 10px 7px 30px',
                      color: '#f1f5f9',
                      fontSize: '0.78rem',
                      fontFamily: "'JetBrains Mono', monospace",
                      outline: 'none',
                      width: 180,
                      transition: 'border-color 0.2s',
                    }}
                    onFocus={e => (e.target.style.borderColor = 'rgba(56,189,248,0.4)')}
                    onBlur={e => (e.target.style.borderColor = 'rgba(55,65,81,0.3)')}
                  />
                </div>
                <span className="feed-meta">{filteredPackets.length} packets</span>
              </div>
            </div>
            <div className="table-container" ref={tableRef}>
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 80 }}>Time</th>
                    <th style={{ width: 180 }}>Source</th>
                    <th style={{ width: 180 }}>Destination</th>
                    <th style={{ width: 90 }}>Protocol</th>
                    <th>Payload / Info</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPackets.map((p, i) => (
                    <tr key={p.id + '-' + i} className={p.alert ? 'row-alert' : ''}>
                      <td className="col-time">{p.time}</td>
                      <td>
                        <div className="col-ip">{p.src}</div>
                        {p.src_info && (
                          <span className={`ip-tag ${getTagClass(p.src_info)}`}>
                            {p.src_info}
                          </span>
                        )}
                      </td>
                      <td>
                        <div className="col-ip">{p.dst}</div>
                        {p.dst_info && (
                          <span className={`ip-tag ${getTagClass(p.dst_info)}`}>
                            {p.dst_info}
                          </span>
                        )}
                      </td>
                      <td className="col-proto">
                        <span className={`proto-badge proto-${p.protocol}`}>
                          {p.protocol}
                        </span>
                      </td>
                      <td className="col-payload">
                        {p.port !== '-' && (
                          <div className="port-routing">
                            Port <span style={{ color: '#cbd5e1' }}>{p.port}</span>
                          </div>
                        )}
                        <div className="info-text" title={p.info}>{p.info}</div>
                        {p.alert && (
                          <div className="alert-indicator">
                            <AlertTriangle size={11} /> THREAT
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
