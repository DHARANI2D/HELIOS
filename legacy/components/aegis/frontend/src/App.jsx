import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert } from 'lucide-react';

// Components
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import ControlCenter from './components/ControlCenter';
import IdentityRegistry from './components/IdentityRegistry';
import WorkloadNodes from './components/WorkloadNodes';
import AuditArchives from './components/AuditArchives';
import SimulatorOrchestrator from './components/SimulatorOrchestrator';
import ConnectivityHub from './components/ConnectivityHub';
import GovernanceSetup from './components/GovernanceSetup';

const API_BASE = "http://localhost:8000";

const App = () => {
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

    const [showPurgeConfirm, setShowPurgeConfirm] = useState(false);

    const handleGlobalPurge = async () => {
        try {
            await axios.post(`${API_BASE}/governance/purge`);
            setNotification('⚠️ Global purge executed. All agents isolated.');
            setLockdown(true);
            setShowPurgeConfirm(false);
            // Force immediate data refresh
            await fetchData();
            setTimeout(() => setNotification(null), 10000);
        } catch (err) {
            setNotification('❌ Global purge failed');
            setShowPurgeConfirm(false);
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

    return (
        <div className="flex h-screen bg-[#0a0c10] text-slate-100 font-sans overflow-hidden">
            <Sidebar currentView={currentView} setCurrentView={setCurrentView} />

            <main className="flex-1 flex flex-col overflow-hidden relative">
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

                <Header lockdown={lockdown} setCurrentView={setCurrentView} />

                <div className="flex-1 overflow-y-auto p-12 relative">
                    <AnimatePresence mode="wait">
                        <motion.div
                            key={currentView}
                            initial={{ opacity: 0, x: 20 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -20 }}
                            transition={{ duration: 0.3, ease: "easeInOut" }}
                        >
                            {currentView === 'Control Center' && (
                                <ControlCenter stats={stats} agents={agents} logs={logs} setCurrentView={setCurrentView} />
                            )}
                            {currentView === 'Identity Registry' && (
                                <IdentityRegistry agents={agents} newId={newId} setNewId={setNewId} handleIssueId={handleIssueId} />
                            )}
                            {currentView === 'Workload Nodes' && (
                                <WorkloadNodes agents={agents} />
                            )}
                            {currentView === 'Audit Archives' && (
                                <AuditArchives logs={logs} />
                            )}
                            {currentView === 'Simulator Orchestrator' && (
                                <SimulatorOrchestrator
                                    agents={agents}
                                    handleReset={handleReset}
                                    handleGlobalPurge={handleGlobalPurge}
                                    showPurgeConfirm={showPurgeConfirm}
                                    setShowPurgeConfirm={setShowPurgeConfirm}
                                />
                            )}
                            {currentView === 'Connectivity Guide' && (
                                <ConnectivityHub API_BASE={API_BASE} />
                            )}
                            {currentView === 'Governance Setup' && (
                                <GovernanceSetup />
                            )}
                        </motion.div>
                    </AnimatePresence>
                </div>
            </main>
        </div>
    );
};

export default App;
