import React, { useState } from 'react';
import { Cpu, ShieldAlert, AlertTriangle, Search } from 'lucide-react';
import InvestigationModal from './InvestigationModal';
import axios from 'axios';

const WorkloadNodes = ({ agents }) => {
    const [selectedAgent, setSelectedAgent] = useState(null);
    const [investigation, setInvestigation] = useState(null);
    const [loading, setLoading] = useState(false);

    const API_BASE = "http://localhost:8000";

    const getTrustColor = (trust) => {
        if (trust === 0) return 'text-red-500';
        if (trust < 50) return 'text-orange-500';
        if (trust < 80) return 'text-yellow-500';
        return 'text-emerald-500';
    };

    const getStatusColor = (status) => {
        if (status === 'REVOKED' || status === 'BREACH_DETECTED') return 'bg-red-500/10 border-red-500/20 text-red-500';
        if (status === 'Active') return 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500';
        return 'bg-blue-500/10 border-blue-500/20 text-blue-400';
    };

    const getStatusIcon = (status) => {
        if (status === 'REVOKED' || status === 'BREACH_DETECTED') return <ShieldAlert className="w-4 h-4" />;
        if (status === 'ISOLATED') return <AlertTriangle className="w-4 h-4" />;
        return null;
    };

    const handleAgentClick = async (agent) => {
        if (agent.status !== 'REVOKED') return;

        setLoading(true);
        try {
            const response = await axios.get(`${API_BASE}/agents/${agent.id}/investigation`);
            setSelectedAgent(agent);
            setInvestigation(response.data);
        } catch (err) {
            console.error("Failed to load investigation:", err);
        } finally {
            setLoading(false);
        }
    };

    const handleRestore = async (agentId) => {
        try {
            await axios.post(`${API_BASE}/agents/${agentId}/restore`, {}, {
                params: { justification: "Reviewed and determined to be false positive" }
            });
            setSelectedAgent(null);
            setInvestigation(null);
            window.location.reload(); // Refresh to show updated state
        } catch (err) {
            console.error("Failed to restore agent:", err);
        }
    };

    const handleConfirmBreach = async (agentId) => {
        try {
            await axios.post(`${API_BASE}/agents/${agentId}/confirm-breach`, {}, {
                params: { notes: "Breach confirmed by security team" }
            });
            setSelectedAgent(null);
            setInvestigation(null);
            window.location.reload();
        } catch (err) {
            console.error("Failed to confirm breach:", err);
        }
    };

    return (
        <div className="space-y-10">
            <h2 className="text-3xl font-bold">Workload Nodes</h2>
            {agents.length === 0 ? (
                <div className="bg-[#11141b] border border-slate-800 p-20 rounded-[2rem] text-center">
                    <p className="text-slate-400 font-bold text-lg">No active workload nodes</p>
                    <p className="text-slate-600 text-sm mt-2">Issue new identities from the Identity Registry to see nodes here</p>
                </div>
            ) : (
                <div className="grid grid-cols-2 gap-8">
                    {agents.map(agent => {
                        const isRevoked = agent.status === 'REVOKED' || agent.trust === 0;
                        const isIsolated = agent.mode === 'ISOLATED' || agent.level === 0;

                        return (
                            <div
                                key={agent.id}
                                onClick={() => handleAgentClick(agent)}
                                className={`bg-[#11141b] border rounded-[2rem] p-8 space-y-6 transition-all ${isRevoked
                                        ? 'border-red-500/30 cursor-pointer hover:border-red-500/50 hover:bg-red-500/5'
                                        : 'border-slate-800'
                                    }`}
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div className={`p-4 rounded-2xl ${isRevoked ? 'bg-red-500/10 text-red-500' : 'bg-slate-900 text-blue-400'
                                            }`}>
                                            <Cpu className="w-8 h-8" />
                                        </div>
                                        <div>
                                            <h3 className="text-xl font-bold">{agent.id}</h3>
                                            <p className="text-sm text-slate-500 italic">
                                                L{agent.level} — {agent.mode}
                                                {isRevoked && <span className="ml-2 text-red-500 font-bold">⚠ REVOKED</span>}
                                            </p>
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <p className={`text-2xl font-black ${getTrustColor(agent.trust)}`}>
                                            {agent.trust.toFixed(1)}%
                                        </p>
                                        <p className="text-[10px] text-slate-500 font-bold uppercase">Integrity</p>
                                    </div>
                                </div>
                                <div className="grid grid-cols-3 gap-4 font-bold text-[10px] uppercase">
                                    <div className={`p-4 rounded-2xl border flex items-center justify-center gap-2 ${isRevoked
                                            ? 'bg-red-500/10 border-red-500/20 text-red-500'
                                            : 'bg-slate-900/50 border-slate-800 text-emerald-500'
                                        }`}>
                                        {isRevoked ? 'DLP: FAIL' : 'DLP: PASS'}
                                    </div>
                                    <div className={`p-4 rounded-2xl border flex items-center justify-center gap-2 ${isRevoked
                                            ? 'bg-red-500/10 border-red-500/20 text-red-500'
                                            : 'bg-slate-900/50 border-slate-800 text-emerald-400'
                                        }`}>
                                        {isRevoked ? 'REASON: FAULT' : 'REASON: STABLE'}
                                    </div>
                                    <div className={`p-4 rounded-2xl border flex items-center justify-center gap-2 ${getStatusColor(agent.status)}`}>
                                        {getStatusIcon(agent.status)}
                                        STATE: {agent.status}
                                    </div>
                                </div>
                                {isRevoked && (
                                    <div className="pt-4 border-t border-red-500/20 flex items-center justify-center gap-2 text-red-400 text-sm">
                                        <Search className="w-4 h-4" />
                                        <span>Click to view investigation details</span>
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}

            {selectedAgent && investigation && (
                <InvestigationModal
                    agent={{ ...selectedAgent, investigation }}
                    onClose={() => {
                        setSelectedAgent(null);
                        setInvestigation(null);
                    }}
                    onRestore={handleRestore}
                    onConfirmBreach={handleConfirmBreach}
                />
            )}
        </div>
    );
};

export default WorkloadNodes;
