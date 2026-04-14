import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend } from 'recharts';
import { Activity, ShieldAlert, Cpu, Globe, Search, Database } from 'lucide-react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls, Stars } from '@react-three/drei';
import './index.css';

const Scene = () => {
    return (
        <Canvas camera={{ position: [0, 0, 8] }}>
            <ambientLight intensity={0.5} />
            <pointLight position={[10, 10, 10]} />
            <Stars radius={100} depth={50} count={5000} factor={4} saturation={0} fade speed={1} />
            <OrbitControls autoRotate autoRotateSpeed={1} enableZoom={false} />
            <mesh>
                <sphereGeometry args={[2.5, 32, 32]} />
                <meshStandardMaterial color="#0ea5e9" wireframe />
            </mesh>
            <mesh scale={1.2}>
                <sphereGeometry args={[2.5, 16, 16]} />
                <meshStandardMaterial color="#38bdf8" wireframe transparent opacity={0.15} />
            </mesh>
        </Canvas>
    );
};

export default function App() {
    const [packets, setPackets] = useState([]);
    const [connected, setConnected] = useState(false);
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState({
        total: 0, tcp: 0, udp: 0, dns: 0, protocolData: [], topIps: []
    });

    useEffect(() => {
        const source = new EventSource('http://localhost:5000/stream');
        
        source.onopen = () => setConnected(true);
        source.onerror = () => setConnected(false);
        
        source.onmessage = (e) => {
            const data = JSON.parse(e.data);
            const p = data.packet;

            setStats({
                total: data.total_packets,
                tcp: data.stats.TCP,
                udp: data.stats.UDP,
                dns: data.stats.DNS,
                protocolData: [
                    { name: 'TCP', value: data.stats.TCP },
                    { name: 'UDP', value: data.stats.UDP },
                    { name: 'ICMP', value: data.stats.ICMP || 0 },
                    { name: 'ARP', value: data.stats.ARP || 0 },
                    { name: 'OTHER', value: data.stats.OTHER || 0 }
                ].filter(d => d.value > 0),
                topIps: data.stats.top_ips || []
            });

            if (p.alert) {
                setAlerts(prev => [{id: Date.now() + Math.random(), time: p.time, text: p.alert}, ...prev].slice(0, 15));
            }

            setPackets(prev => {
                const newArr = [p, ...prev];
                if (newArr.length > 50) newArr.pop(); 
                return newArr;
            });
        };

        return () => source.close();
    }, []);

    const COLORS = ['#38bdf8', '#8b5cf6', '#ef4444', '#f59e0b', '#94a3b8'];

    return (
        <div className="app-layout">
            <div className="three-background">
                <Scene />
            </div>

            <div className="main-content">
                <header className="header-glass">
                    <div className="logo">
                        <Cpu size={32} color="#38bdf8" />
                        <h1>System<span style={{color: '#38bdf8'}}>Sniffer</span></h1>
                    </div>
                    <div className={`status-badge ${connected ? 'status-connected' : 'status-disconnected'}`}>
                        <div className="status-dot"></div>
                        {connected ? 'Live Stream Active' : 'Disconnected'}
                    </div>
                </header>

                <div className="kpi-grid">
                    {[
                        { label: 'Total Capture', val: stats.total, color: '#38bdf8', Icon: Database },
                        { label: 'TCP Segments', val: stats.tcp, color: '#f8fafc', Icon: Activity },
                        { label: 'UDP Datagrams', val: stats.udp, color: '#f8fafc', Icon: Globe },
                        { label: 'DNS Queries', val: stats.dns, color: '#f8fafc', Icon: Search },
                    ].map((s, i) => (
                        <div key={i} className="card-glass kpi-card">
                            <div>
                                <p className="kpi-label">{s.label}</p>
                                <p className="kpi-value" style={{color: s.color}}>{s.val.toLocaleString()}</p>
                            </div>
                            <s.Icon size={40} color="rgba(255,255,255,0.1)" />
                        </div>
                    ))}
                </div>

                <div className="dashboard-grid">
                    <div className="sidebar">
                        <div className="card-glass alert-card">
                            <div className="card-header alert-header">
                                <ShieldAlert size={20} color="#ef4444" />
                                <h2>Intrusion Alerts</h2>
                            </div>
                            <div className="alert-body">
                                {alerts.length === 0 ? <p style={{color:'#64748b', textAlign:'center', marginTop:'15px'}}>No suspicious events.</p> : 
                                alerts.map(a => (
                                    <div key={a.id} className="alert-item">
                                        <strong>{a.time}</strong> {a.text}
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="card-glass chart-card">
                            <div className="card-header">Protocol Distribution</div>
                            <div className="chart-body">
                                <ResponsiveContainer width="100%" height="100%">
                                    <PieChart>
                                        <Pie data={stats.protocolData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                                            {stats.protocolData.map((e, index) => <Cell key={index} fill={COLORS[index % COLORS.length]} />)}
                                        </Pie>
                                        <RechartsTooltip contentStyle={{backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px'}} />
                                        <Legend />
                                    </PieChart>
                                </ResponsiveContainer>
                            </div>
                        </div>
                    </div>

                    <div className="card-glass feed-card">
                        <div className="card-header flex-between">
                            <h2>Live Traffic Feed</h2>
                            <span className="last-packets-label">Last 50 packets</span>
                        </div>
                        <div className="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Source</th>
                                        <th>Destination</th>
                                        <th>Proto</th>
                                        <th>Payload Info</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {packets.map((p, index) => (
                                        <tr key={index} className={p.alert ? 'row-alert' : ''}>
                                            <td className="time-col">{p.time}</td>
                                            <td>
                                                <div className="ip-text">{p.src}</div>
                                                {p.src_info && <span className="ip-tag">{p.src_info}</span>}
                                            </td>
                                            <td>
                                                <div className="ip-text">{p.dst}</div>
                                                {p.dst_info && <span className="ip-tag">{p.dst_info}</span>}
                                            </td>
                                            <td className="proto-col">{p.protocol}</td>
                                            <td className="payload-col">
                                                {p.port !== '-' && <div className="port-text">Port <span style={{color:'#cbd5e1'}}>{p.port}</span></div>}
                                                <div className="info-text" title={p.info}>{p.info}</div>
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
