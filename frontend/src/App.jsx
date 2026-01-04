import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    ShieldCheck,
    LayoutDashboard,
    Users,
    History,
    Settings,
    Search,
    Bell,
    Cpu,
    Lock,
    Zap,
    MoreVertical,
    ArrowUpRight,
    TrendingUp,
    Fingerprint,
    BookOpen,
    Activity,
    CheckCircle2,
    AlertTriangle,
    XCircle,
    FileSearch,
    Database,
    Play,
    RotateCcw,
    ShieldAlert
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const API_BASE = "http://localhost:8000";

const Dashboard = () => {
    const [currentView, setCurrentView] = useState('Control Center');
    const [agents, setAgents] = useState([]);
    const [stats, setStats] = useState({
        active_nodes: 0,
        avg_trust: '0%',
        interventions: 0,
        pending: 0
    });
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [newId, setNewId] = useState('');
    const [lockdown, setLockdown] = useState(false);
    const [notification, setNotification] = useState(null);

    // Fetch Data Routine
    const fetchData = async () => {
        try {
            const [agentsRes, statsRes, logsRes] = await Promise.all([
                axios.get(`${API_BASE}/agents`),
                axios.get(`${API_BASE}/stats`),
                axios.get(`${API_BASE}/logs`)
            ]);
            setAgents(agentsRes.data);
            setStats(statsRes.data);
            setLogs(logsRes.data);
            setLoading(false);

            // Check if any agent is isolated/revoked to show lockdown state
            const isLocked = agentsRes.data.some(a => a.status === 'REVOKED');
            setLockdown(isLocked);
        } catch (err) {
            console.error("API Fetch Error:", err);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 3000);
        return () => clearInterval(interval);
    }, []);

    const handleIssueId = async () => {
        if (!newId) return;
        try {
            await axios.post(`${API_BASE}/identity/issue/${newId}`);
            setNotification(`✅ Issued identity for ${newId}`);
            setNewId('');
            fetchData();
            setTimeout(() => setNotification(null), 5000);
        } catch (err) {
            setNotification('❌ Issue identity failed');
            setTimeout(() => setNotification(null), 5000);
        }
    };

    const handleGlobalPurge = async () => {
        if (!window.confirm("CRITICAL: This will isolate all agents and revoke all keys. Proceed?")) return;
        try {
            await axios.post(`${API_BASE}/governance/purge`);
            setNotification('⚠️ Global purge executed. All agents isolated.');
            setLockdown(true);
            fetchData();
            setTimeout(() => setNotification(null), 10000);
        } catch (err) {
            setNotification('❌ Global purge failed');
            setTimeout(() => setNotification(null), 5000);
        }
    };

    const handleReset = async () => {
        if (!window.confirm("Wipe all audit trails and agent records?")) return;
        try {
            await axios.post(`${API_BASE}/simulator/reset`);
            setNotification('🧹 Database reset complete.');
            fetchData();
            setTimeout(() => setNotification(null), 5000);
        } catch (err) {
            setNotification('❌ Reset failed');
            setTimeout(() => setNotification(null), 5000);
        }
    };

    const renderControlCenter = () => (
        <div className="space-y-10">
            {/* KPI Cards */}
            <div className="grid grid-cols-4 gap-6">
                {[
                    { label: 'Protected Instances', value: stats.active_nodes, diff: '+0', icon: Cpu, color: 'text-blue-400' },
                    { label: 'Avg Trust Integrity', value: stats.avg_trust, diff: '+0', icon: ShieldCheck, color: 'text-emerald-400' },
                    { label: 'Risk Interventions', value: stats.interventions, diff: '+0', icon: Lock, color: 'text-orange-400' },
                    { label: 'Pending Reviews', value: stats.pending, diff: '0', icon: Zap, color: 'text-purple-400' },
                ].map((kpi) => (
                    <div key={kpi.label} className="bg-[#11141b] border border-slate-800/80 p-6 rounded-[2rem] shadow-sm hover:shadow-emerald-900/5 transition-all group">
                        <div className="flex items-center justify-between mb-4">
                            <div className={`p-3 rounded-2xl bg-slate-900 border border-slate-800 ${kpi.color}`}>
                                <kpi.icon className="w-5 h-5" />
                            </div>
                            <div className="flex items-center gap-1 text-emerald-400 text-xs font-bold font-mono">
                                <TrendingUp className="w-3 h-3" />
                                {kpi.diff}
                            </div>
                        </div>
                        <p className="text-3xl font-black text-white mb-1">{kpi.value}</p>
                        <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">{kpi.label}</p>
                    </div>
                ))}
            </div>

            <div className="grid grid-cols-3 gap-10">
                <div className="col-span-2 space-y-6">
                    <div className="flex items-center justify-between">
                        <h2 className="text-xl font-bold">Node Infrastructure</h2>
                        <button onClick={() => setCurrentView('Workload Nodes')} className="text-xs font-bold text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
                            View Full Registry <ArrowUpRight className="w-3 h-3" />
                        </button>
                    </div>
                    <div className="space-y-4">
                        {agents.length > 0 ? agents.slice(0, 4).map((agent) => (
                            <div key={agent.id} className="bg-[#11141b] border border-slate-800/60 p-5 rounded-2xl flex items-center justify-between group hover:bg-slate-800/20 transition-all">
                                <div className="flex items-center gap-5">
                                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center bg-slate-900 border border-slate-800 ${agent.trust > 70 ? 'text-emerald-500' : 'text-orange-500'}`}>
                                        <Fingerprint className="w-6 h-6" />
                                    </div>
                                    <div>
                                        <h3 className="font-bold text-slate-100">{agent.id}</h3>
                                        <p className="text-xs text-slate-500 font-medium">Mode: <span className="text-slate-300 font-mono italic">{agent.mode}</span></p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-8">
                                    <div className="w-32 text-right">
                                        <span className="text-xs font-bold font-mono">{agent.trust.toFixed(1)}%</span>
                                        <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden mt-1">
                                            <div className={`h-full ${agent.trust > 70 ? 'bg-emerald-500' : 'bg-orange-500'}`} style={{ width: `${agent.trust}%` }}></div>
                                        </div>
                                    </div>
                                    <span className={`text-[10px] font-black uppercase px-2 py-1 rounded border ${agent.status === 'Active' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 'bg-red-500/10 text-red-500 border-red-500/20'}`}>
                                        {agent.status}
                                    </span>
                                </div>
                            </div>
                        )) : <div className="text-slate-600 italic text-xs py-20 text-center border-2 border-dashed border-slate-800 rounded-3xl uppercase tracking-widest font-bold opacity-30">Infrastructure Offline - Start Simulator</div>}
                    </div>
                </div>

                <div className="space-y-6">
                    <h2 className="text-xl font-bold">Recent Forensics</h2>
                    <div className="bg-[#11141b] border border-slate-800/80 rounded-[2rem] p-6 space-y-6">
                        <div className="max-h-[400px] overflow-y-auto pr-2 space-y-6">
                            {logs.length > 0 ? [...logs].map((log, i) => (
                                <div key={i} className="flex gap-4 group">
                                    <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${log.data.decision === 'ALLOW' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]'}`}></div>
                                    <div className="flex-1 min-w-0">
                                        <p className="text-[13px] font-bold text-slate-200 uppercase tracking-tight truncate">{log.data.intent}</p>
                                        <p className="text-[10px] text-slate-500 mb-1">{log.data.ai_id} • {log.data.decision}</p>
                                        <p className="text-[10px] text-slate-400 bg-slate-900/50 p-2 rounded border border-slate-800/50 italic leading-relaxed">
                                            {log.data.reason}
                                        </p>
                                    </div>
                                </div>
                            )) : <div className="text-slate-600 italic text-xs py-10 text-center">No active audit stream</div>}
                        </div>
                        <button onClick={() => setCurrentView('Audit Archives')} className="w-full py-3 rounded-2xl bg-slate-800/50 hover:bg-slate-800 text-slate-300 text-xs font-bold transition-all border border-slate-800">
                            VIEW ALL ARCHIVES
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );

    const renderIdentityRegistry = () => (
        <div className="space-y-10">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-3xl font-bold">Identity Registry</h2>
                    <p className="text-slate-500">Cryptographically verified AI entity identities (ED25519 Certs)</p>
                </div>
                <div className="flex gap-4">
                    <input
                        type="text"
                        placeholder="Agent Name (e.g. AX-01)"
                        value={newId}
                        onChange={e => setNewId(e.target.value)}
                        className="bg-slate-900 border border-slate-800 rounded-xl px-4 py-2 text-sm focus:border-emerald-500 focus:outline-none"
                    />
                    <button onClick={handleIssueId} className="px-6 py-3 emerald-gradient rounded-xl font-bold text-sm shadow-lg shadow-emerald-900/40">ISSUE NEW ID</button>
                </div>
            </div>

            <div className="grid grid-cols-1 gap-4">
                {agents.map(agent => (
                    <div key={agent.id} className="bg-[#11141b] border border-slate-800 p-6 rounded-2xl flex items-center justify-between hover:border-emerald-500/30 transition-all">
                        <div className="flex items-center gap-6">
                            <div className="p-4 bg-slate-900 rounded-2xl text-emerald-500 border border-slate-800"><Users className="w-6 h-6" /></div>
                            <div>
                                <h4 className="text-lg font-bold">{agent.id}</h4>
                                <p className="text-xs font-mono text-slate-500 uppercase tracking-tighter italic">CERT_STATUS: VERIFIED_ED25519</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-10">
                            <div className="text-right">
                                <p className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-1">Authorization</p>
                                <span className="text-xs font-black text-emerald-400 font-mono">INTENT_SCOPE_ACTIVE</span>
                            </div>
                            <div className={`px-4 py-2 rounded-xl border ${agent.status === 'Active' ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-500' : 'bg-red-500/5 border-red-500/20 text-red-500'} font-bold text-[10px]`}>
                                {agent.status === 'Active' ? 'SECURE_ENTITY' : 'BREACH_DETECTED'}
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );

    const renderSimulator = () => (
        <div className="space-y-10">
            <div className="flex items-center justify-between">
                <h2 className="text-3xl font-bold">Simulator Orchestrator</h2>
                <div className="flex gap-4">
                    <button onClick={handleReset} className="flex items-center gap-2 px-6 py-3 bg-slate-900 border border-slate-800 rounded-xl font-bold text-sm hover:bg-slate-800 transition-all">
                        <RotateCcw className="w-4 h-4" /> RESET ALL DATA
                    </button>
                    <div className="px-6 py-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 rounded-xl font-black text-xs uppercase tracking-widest flex items-center gap-3">
                        <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div> Local Engine Operational
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-2 gap-10">
                <div className="bg-[#11141b] border border-slate-800 p-10 rounded-[3rem] space-y-8">
                    <h3 className="text-xl font-bold flex items-center gap-3 text-emerald-500"><Zap className="w-6 h-6" /> Operational Guide</h3>
                    <ul className="space-y-4 text-slate-400 text-sm list-disc pl-5">
                        <li>Run <code className="bg-black px-2 py-1 rounded">make simulate</code> in your terminal to start the autonomous fleet.</li>
                        <li>The simulator will boot 5 agents with distinct behavioral profiles.</li>
                        <li>Security lapses, PII leaks, and constitutional breaches are randomly generated.</li>
                        <li>Watch the 'Recent Forensics' panel in real-time to see AEGIS intercepting threats.</li>
                    </ul>
                    <div className="p-6 bg-slate-900/50 border border-slate-800 rounded-2xl italic text-xs text-slate-500 leading-relaxed">
                        "The simulator replicates real-world AI goal drift by detaching intent from supporting reasoning blocks, forcing the AEGIS Reason Monitor to intervene."
                    </div>
                </div>

                <div className="grid grid-cols-1 gap-6">
                    <div className="bg-emerald-500/5 border border-emerald-500/20 p-8 rounded-[3rem] space-y-4">
                        <h4 className="font-bold text-emerald-500 tracking-widest uppercase text-xs">Environment Status</h4>
                        <div className="flex items-center justify-between">
                            <span className="text-3xl font-black">{agents.length} Nodes</span>
                            <Play className="text-emerald-500 w-10 h-10 opacity-20" />
                        </div>
                        <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full bg-emerald-500 w-[75%]"></div>
                        </div>
                    </div>

                    <div className="bg-red-500/5 border border-red-500/20 p-8 rounded-[3rem] space-y-4 cursor-pointer hover:bg-red-500/10 transition-all" onClick={handleGlobalPurge}>
                        <h4 className="font-bold text-red-500 tracking-widest uppercase text-xs">Emergency Lockdown</h4>
                        <div className="flex items-center justify-between">
                            <span className="text-3xl font-black">Global Purge</span>
                            <ShieldAlert className="text-red-500 w-10 h-10 opacity-30" />
                        </div>
                        <p className="text-xs text-red-500/60 font-medium italic">Instantly transition all nodes to L0 Isolation.</p>
                    </div>
                </div>
            </div>
        </div>
    );

    const sidebarItems = [
        { icon: LayoutDashboard, label: 'Control Center' },
        { icon: Users, label: 'Identity Registry' },
        { icon: Cpu, label: 'Workload Nodes' },
        { icon: History, label: 'Audit Archives' },
        { icon: Zap, label: 'Simulator Orchestrator' },
        { icon: BookOpen, label: 'Connectivity Guide' },
    ];

    return (
        <div className="flex h-screen bg-[#0a0c10] text-slate-100 font-sans overflow-hidden">
            {/* Sidebar */}
            <aside className="w-72 border-r border-slate-800 flex flex-col bg-[#0d1016] flex-shrink-0">
                <div className="p-8 flex items-center gap-3">
                    <div className="w-10 h-10 emerald-gradient rounded-xl flex items-center justify-center shadow-lg shadow-emerald-900/20">
                        <ShieldCheck className="text-white w-6 h-6" />
                    </div>
                    <span className="text-xl font-bold tracking-tight">AEGIS <span className="text-emerald-500 font-black tracking-widest italic">PRO</span></span>
                </div>

                <nav className="flex-1 px-4 space-y-1 overflow-y-auto mt-4">
                    {sidebarItems.map((item) => (
                        <button
                            key={item.label}
                            onClick={() => setCurrentView(item.label)}
                            className={`w-full flex items-center gap-4 px-4 py-3.5 rounded-xl transition-all font-bold text-sm tracking-tight ${currentView === item.label ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.1)]' : 'text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'}`}
                        >
                            <item.icon className="w-5 h-5" />
                            <span>{item.label}</span>
                        </button>
                    ))}
                </nav>

                <div className="p-6 mt-auto">
                    <div className="bg-slate-900/50 rounded-2xl p-5 border border-slate-800 flex items-center gap-4 hover:border-emerald-500/30 transition-all cursor-pointer">
                        <div className="relative">
                            <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700">
                                <Fingerprint className="w-5 h-5 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.3)]" />
                            </div>
                            <div className="absolute -bottom-1 -right-1 w-3 h-3 bg-emerald-500 rounded-full border-2 border-[#0d1016]"></div>
                        </div>
                        <div>
                            <p className="text-[10px] text-slate-500 font-black uppercase tracking-widest">SEC-ADMIN-ROOT</p>
                            <p className="text-sm font-bold text-slate-200">System Guardian</p>
                        </div>
                    </div>
                </div>
            </aside>

            {/* Main Area */}
            <main className="flex-1 flex flex-col overflow-hidden relative">
                {/* Global Lockdown Banner */}
                {notification && (
                    <div className="bg-emerald-600 text-white text-[10px] font-bold uppercase tracking-wide text-center py-2 flex items-center justify-center gap-4">
                        {notification}
                    </div>
                )}
                {lockdown && (
                    <div className="bg-red-600 text-white text-[10px] font-black uppercase tracking-[0.5em] text-center py-2 animate-pulse flex items-center justify-center gap-4">
                        <ShieldAlert className="w-3 h-3" /> L0 ISOLATION ACTIVE - SYSTEM LOCKDOWN <ShieldAlert className="w-3 h-3" />
                    </div>
                )}

                {/* Top Header */}
                <header className="h-20 px-10 border-b border-slate-800 flex items-center justify-between bg-[#0a0c10]/80 backdrop-blur-xl z-20">
                    <div className="relative w-96 group">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-emerald-500 transition-colors" />
                        <input type="text" placeholder="Omni Search: IDs, Policies, Intents..." className="w-full bg-slate-900/40 border border-slate-800 rounded-2xl py-3 pl-11 pr-4 text-xs focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500/50 transition-all font-bold tracking-tight text-slate-300" />
                    </div>

                    <div className="flex items-center gap-8">
                        <div className="flex items-center gap-3 px-4 py-2 bg-emerald-500/5 border border-emerald-500/10 rounded-full shadow-[inset_0_0_10px_rgba(16,185,129,0.05)]">
                            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]"></div>
                            <span className="text-[10px] font-black text-emerald-500 uppercase tracking-[0.2em] italic">Mesh Status: {lockdown ? 'ERROR' : 'SECURE'}</span>
                        </div>
                        <div className="flex items-center gap-4">
                            <button className="relative p-3 bg-slate-900 rounded-xl border border-slate-800 text-slate-400 hover:text-white transition-all">
                                <Bell className="w-5 h-5" />
                                <span className="absolute top-2.5 right-2.5 w-2 h-2 bg-emerald-500 rounded-full shadow-[0_0_5px_#10b981]"></span>
                            </button>
                            <button onClick={() => setCurrentView('Governance Setup')} className="p-3 bg-slate-900 rounded-xl border border-slate-800 text-slate-400 hover:text-white transition-all">
                                <Settings className="w-5 h-5" />
                            </button>
                        </div>
                    </div>
                </header>

                {/* Content View Switching */}
                <div className="flex-1 overflow-y-auto p-12 relative">
                    <AnimatePresence mode="wait">
                        <motion.div
                            key={currentView}
                            initial={{ opacity: 0, x: 20 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -20 }}
                            transition={{ duration: 0.3, ease: "easeInOut" }}
                        >
                            {currentView === 'Control Center' && renderControlCenter()}
                            {currentView === 'Identity Registry' && renderIdentityRegistry()}
                            {currentView === 'Workload Nodes' && (
                                <div className="space-y-10">
                                    <h2 className="text-3xl font-bold">Workload Nodes</h2>
                                    <div className="grid grid-cols-2 gap-8">
                                        {agents.map(agent => (
                                            <div key={agent.id} className="bg-[#11141b] border border-slate-800 p-8 rounded-[2rem] space-y-6">
                                                <div className="flex items-center justify-between">
                                                    <div className="flex items-center gap-4">
                                                        <div className="p-4 bg-slate-900 rounded-2xl text-blue-400"><Cpu className="w-8 h-8" /></div>
                                                        <div>
                                                            <h3 className="text-xl font-bold">{agent.id}</h3>
                                                            <p className="text-sm text-slate-500 italic">L{agent.level} — {agent.mode}</p>
                                                        </div>
                                                    </div>
                                                    <div className="text-right">
                                                        <p className="text-2xl font-black text-white">{agent.trust.toFixed(1)}%</p>
                                                        <p className="text-[10px] text-slate-500 font-bold uppercase">Integrity</p>
                                                    </div>
                                                </div>
                                                <div className="grid grid-cols-3 gap-4 font-bold text-[10px] uppercase">
                                                    <div className="p-4 bg-slate-900/50 rounded-2xl border border-slate-800 text-emerald-500">DLP: PASS</div>
                                                    <div className="p-4 bg-slate-900/50 rounded-2xl border border-slate-800 text-emerald-400">REASON: STABLE</div>
                                                    <div className="p-4 bg-slate-900/50 rounded-2xl border border-slate-800 text-blue-400">STATE: {agent.status}</div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                            {currentView === 'Audit Archives' && (
                                <div className="space-y-10">
                                    <h2 className="text-3xl font-bold">Global Audit Ledger</h2>
                                    <div className="bg-[#11141b] border border-slate-800 rounded-[2rem] p-8 space-y-4">
                                        {logs.reverse().map((log, i) => (
                                            <div key={i} className="flex gap-6 p-6 bg-slate-900/40 border border-slate-800/60 rounded-2xl">
                                                <div className="w-12 h-12 rounded-xl flex items-center justify-center bg-slate-900 border border-slate-800 text-slate-400">
                                                    <History className="w-6 h-6" />
                                                </div>
                                                <div className="flex-1 grid grid-cols-4 gap-6 items-center">
                                                    <div><p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Entity</p><p className="font-bold">{log.data.ai_id}</p></div>
                                                    <div><p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Intent</p><p className="font-bold text-slate-300">{log.data.intent}</p></div>
                                                    <div><p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Decision</p><p className={`font-black uppercase ${log.data.decision === 'ALLOW' ? 'text-emerald-500' : 'text-red-500'}`}>{log.data.decision}</p></div>
                                                    <div className="text-right font-mono text-[9px] text-slate-500 truncate">SIG: {log.current_hash}</div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                            {currentView === 'Simulator Orchestrator' && renderSimulator()}
                            {currentView === 'Connectivity Guide' && (
                                <div className="space-y-10 max-w-4xl mx-auto pb-20">
                                    <div className="space-y-4">
                                        <h2 className="text-4xl font-black">Agent Integration Hub</h2>
                                        <p className="text-slate-400 text-lg">Deploy the AEGIS Sidecar to enforce Zero‑Trust at the edge of your AI workloads.</p>
                                    </div>

                                    <div className="grid gap-6">
                                        <div className="bg-[#11141b] border border-slate-800 rounded-3xl p-8 space-y-6">
                                            <div className="flex items-center gap-4 text-emerald-500 font-bold">
                                                <Zap className="w-6 h-6" /> Step 1: Workload Registration
                                            </div>
                                            <p className="text-sm text-slate-400">Assign a unique identity string to your agent. This creates a cryptographic record in the registry.</p>
                                            <pre className="bg-black/50 p-4 rounded-xl text-xs font-mono text-emerald-400 border border-emerald-900/30">
                                                <code>curl -X POST {API_BASE}/identity/issue/MY-AI-AGENT</code>
                                            </pre>
                                        </div>

                                        <div className="bg-[#11141b] border border-slate-800 rounded-3xl p-8 space-y-6">
                                            <div className="flex items-center gap-4 text-blue-500 font-bold">
                                                <Cpu className="w-6 h-6" /> Step 2: Deploy Sidecar Proxy
                                            </div>
                                            <p className="text-sm text-slate-400">Launch the AEGIS proxy container. It intercepts all outbound traffic from your agent, signs it, and validates it against central policy.</p>
                                            <pre className="bg-black/50 p-4 rounded-xl text-xs font-mono text-blue-400 border border-blue-900/30 overflow-x-auto">
                                                <code>{`docker run -d \\
  --name aegis-proxy \\
  -e AGENT_ID="MY-AI-AGENT" \\
  -e CONTROL_PLANE_URL="${API_BASE}" \\
  -p 3000:3000 \\
  aegis/governance-proxy:latest`}</code>
                                            </pre>
                                        </div>

                                        <div className="bg-[#11141b] border border-slate-800 rounded-3xl p-8 space-y-6">
                                            <div className="flex items-center gap-4 text-purple-500 font-bold">
                                                <Lock className="w-6 h-6" /> Step 3: Configure Outbound SDK
                                            </div>
                                            <p className="text-sm text-slate-400">Update your AI agent to route its external requests (OpenAI API, Database, etc.) through the local proxy.</p>
                                            <pre className="bg-black/50 p-4 rounded-xl text-xs font-mono text-purple-400 border border-purple-900/30">
                                                <code>{`# Python Example
os.environ["HTTP_PROXY"] = "http://localhost:3000"
openai.api_base = "http://localhost:3000/v1"`}</code>
                                            </pre>
                                        </div>
                                    </div>
                                </div>
                            )}
                            {currentView === 'Governance Setup' && (
                                <div className="space-y-10">
                                    <h2 className="text-3xl font-bold">Governance & Policy Guardrails</h2>
                                    <div className="grid grid-cols-2 gap-10">
                                        <div className="bg-[#11141b] border border-slate-800 rounded-[3rem] p-10 space-y-8">
                                            <h3 className="text-lg font-bold flex items-center gap-3"><ShieldAlert className="w-5 h-5 text-orange-400" /> Active Guardrails</h3>
                                            <div className="space-y-6">
                                                {[
                                                    { name: "Zero-Trust Enforcement", status: "ENABLED", desc: "Require Ed25519 signatures for all requests." },
                                                    { name: "PII Redaction Engine", status: "STRICT", desc: "Anonymize sensitive data in outbound payloads." },
                                                    { name: "Adaptive Trust Decay", status: "ENABLED", desc: "Automatically degrade trust scores of inactive nodes." },
                                                    { name: "L0 Isolation Trigger", status: "STANDBY", desc: "Automated full lockdown if integrity drops < 40%." },
                                                ].map(item => (
                                                    <div key={item.name} className="flex items-center justify-between p-4 bg-slate-900/50 rounded-2xl border border-slate-800">
                                                        <div>
                                                            <p className="font-bold text-slate-200">{item.name}</p>
                                                            <p className="text-[10px] text-slate-500">{item.desc}</p>
                                                        </div>
                                                        <span className="text-[10px] font-black text-emerald-500 bg-emerald-500/10 px-3 py-1 rounded-full border border-emerald-500/20">{item.status}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>

                                        <div className="bg-[#11141b] border border-slate-800 rounded-[3rem] p-10 space-y-8">
                                            <h3 className="text-lg font-bold flex items-center gap-3"><Database className="w-5 h-5 text-blue-400" /> System State</h3>
                                            <div className="p-8 bg-slate-900 border border-slate-800 rounded-[2rem] flex flex-col items-center justify-center text-center space-y-4">
                                                <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center border border-emerald-500/20 shadow-[0_0_20px_rgba(16,185,129,0.1)]">
                                                    <div className="w-3 h-3 bg-emerald-500 rounded-full animate-ping"></div>
                                                </div>
                                                <div>
                                                    <p className="text-sm font-black uppercase text-slate-200">SQLite Layer Online</p>
                                                    <p className="text-xs text-slate-500 italic mt-1">All governance policies are currently persisted in the local SQL instance.</p>
                                                </div>
                                            </div>
                                            <div className="p-6 bg-orange-500/5 border border-orange-500/10 rounded-2xl">
                                                <p className="text-[10px] font-bold text-orange-500 flex items-center gap-2">
                                                    <AlertTriangle className="w-3 h-3" /> PERSISTENCE VERIFIED
                                                </p>
                                                <p className="text-xs text-slate-500 mt-2 leading-relaxed">The AEGIS Control Plane is running in Single-Cluster Mode with shared persistent volumes enabled.</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </motion.div>
                    </AnimatePresence>
                </div>
            </main>
        </div>
    );
};

const App = () => {
    return <Dashboard />;
};

export default App;
