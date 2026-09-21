import React from 'react';
import {
    Cpu,
    ShieldCheck,
    Lock,
    Zap,
    TrendingUp,
    ArrowUpRight,
    Fingerprint
} from 'lucide-react';

const ControlCenter = ({ stats, agents, logs, setCurrentView }) => {
    return (
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
                                    <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${log.decision === 'ALLOW' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]'}`}></div>
                                    <div className="flex-1 min-w-0">
                                        <p className="text-[13px] font-bold text-slate-200 uppercase tracking-tight truncate">{log.intent}</p>
                                        <p className="text-[10px] text-slate-500 mb-1">{log.ai_id} • {log.decision}</p>
                                        <p className="text-[10px] text-slate-400 bg-slate-900/50 p-2 rounded border border-slate-800/50 italic leading-relaxed">
                                            {log.reason}
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
};

export default ControlCenter;
