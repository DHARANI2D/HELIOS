import React from 'react';
import { Search, Bell, Settings } from 'lucide-react';

const Header = ({ lockdown, setCurrentView }) => {
    return (
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
    );
};

export default Header;
