import React from 'react';
import {
    ShieldCheck,
    LayoutDashboard,
    Users,
    History,
    Zap,
    BookOpen,
    Cpu,
    Fingerprint
} from 'lucide-react';

const Sidebar = ({ currentView, setCurrentView }) => {
    const sidebarItems = [
        { icon: LayoutDashboard, label: 'Control Center' },
        { icon: Users, label: 'Identity Registry' },
        { icon: Cpu, label: 'Workload Nodes' },
        { icon: History, label: 'Audit Archives' },
        { icon: Zap, label: 'Simulator Orchestrator' },
        { icon: BookOpen, label: 'Connectivity Guide' },
    ];

    return (
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
    );
};

export default Sidebar;
