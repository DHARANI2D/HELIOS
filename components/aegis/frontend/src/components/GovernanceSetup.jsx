import React from 'react';
import { ShieldAlert, Database, AlertTriangle } from 'lucide-react';

const GovernanceSetup = () => {
    const guardrails = [
        { name: "Zero-Trust Enforcement", status: "ENABLED", desc: "Require Ed25519 signatures for all requests." },
        { name: "PII Redaction Engine", status: "STRICT", desc: "Anonymize sensitive data in outbound payloads." },
        { name: "Adaptive Trust Decay", status: "ENABLED", desc: "Automatically degrade trust scores of inactive nodes." },
        { name: "L0 Isolation Trigger", status: "STANDBY", desc: "Automated full lockdown if integrity drops < 40%." },
    ];

    return (
        <div className="space-y-10">
            <h2 className="text-3xl font-bold">Governance & Policy Guardrails</h2>
            <div className="grid grid-cols-2 gap-10">
                <div className="bg-[#11141b] border border-slate-800 rounded-[3rem] p-10 space-y-8">
                    <h3 className="text-lg font-bold flex items-center gap-3"><ShieldAlert className="w-5 h-5 text-orange-400" /> Active Guardrails</h3>
                    <div className="space-y-6">
                        {guardrails.map(item => (
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
    );
};

export default GovernanceSetup;
