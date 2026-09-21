import React, { useState } from 'react';
import { History, ChevronDown, ChevronUp, Shield, Search, FileSearch } from 'lucide-react';

const AuditArchives = ({ logs }) => {
    const [expandedLog, setExpandedLog] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');

    const filteredLogs = logs.filter(log =>
        log.ai_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.intent?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const formatTimestamp = (timestamp) => {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    return (
        <div className="space-y-10">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-3xl font-bold">Global Audit Ledger</h2>
                    <p className="text-slate-500 mt-1">Immutable hash-chained decision log with cryptographic integrity</p>
                </div>
                <div className="flex items-center gap-3 px-4 py-2 bg-emerald-500/5 border border-emerald-500/10 rounded-full">
                    <Shield className="w-4 h-4 text-emerald-500" />
                    <span className="text-[10px] font-black text-emerald-500 uppercase tracking-widest">CHAIN VERIFIED</span>
                </div>
            </div>

            {/* Search Bar */}
            <div className="relative">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                    type="text"
                    placeholder="Search by Agent ID or Intent..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full bg-slate-900/40 border border-slate-800 rounded-xl py-3 pl-11 pr-4 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500/50 transition-all"
                />
            </div>

            {/* Logs Display */}
            <div className="bg-[#11141b] border border-slate-800 rounded-[2rem] p-8 space-y-4">
                {filteredLogs.length > 0 ? (
                    filteredLogs.map((log, i) => (
                        <div key={i} className="bg-slate-900/40 border border-slate-800/60 rounded-2xl overflow-hidden">
                            <div
                                className="flex gap-6 p-6 cursor-pointer hover:bg-slate-800/30 transition-all"
                                onClick={() => setExpandedLog(expandedLog === i ? null : i)}
                            >
                                <div className="w-12 h-12 rounded-xl flex items-center justify-center bg-slate-900 border border-slate-800 text-slate-400">
                                    <History className="w-6 h-6" />
                                </div>
                                <div className="flex-1 grid grid-cols-5 gap-6 items-center">
                                    <div>
                                        <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Entity</p>
                                        <p className="font-bold">{log.ai_id}</p>
                                    </div>
                                    <div>
                                        <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Intent</p>
                                        <p className="font-bold text-slate-300">{log.intent}</p>
                                    </div>
                                    <div>
                                        <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Decision</p>
                                        <p className={`font-black uppercase ${log.decision === 'ALLOW' ? 'text-emerald-500' : 'text-red-500'}`}>
                                            {log.decision}
                                        </p>
                                    </div>
                                    <div>
                                        <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Timestamp</p>
                                        <p className="text-xs text-slate-400 font-mono">{formatTimestamp(log.timestamp)}</p>
                                    </div>
                                    <div className="flex items-center justify-end">
                                        {expandedLog === i ? (
                                            <ChevronUp className="w-5 h-5 text-slate-500" />
                                        ) : (
                                            <ChevronDown className="w-5 h-5 text-slate-500" />
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Expanded Details */}
                            {expandedLog === i && (
                                <div className="px-6 pb-6 space-y-4 border-t border-slate-800/50">
                                    <div className="pt-4 grid grid-cols-2 gap-6">
                                        <div>
                                            <p className="text-[10px] text-slate-500 font-bold uppercase mb-2">Reason</p>
                                            <p className="text-sm text-slate-300 bg-slate-900/50 p-3 rounded-lg border border-slate-800/50 leading-relaxed">
                                                {log.reason || 'No reason provided'}
                                            </p>
                                        </div>
                                        <div>
                                            <p className="text-[10px] text-slate-500 font-bold uppercase mb-2">Cryptographic Hash</p>
                                            <p className="text-xs text-slate-400 font-mono bg-slate-900/50 p-3 rounded-lg border border-slate-800/50 break-all">
                                                {log.current_hash}
                                            </p>
                                            <p className="text-[10px] text-slate-500 font-bold uppercase mt-3 mb-2">Previous Hash</p>
                                            <p className="text-xs text-slate-400 font-mono bg-slate-900/50 p-3 rounded-lg border border-slate-800/50 break-all">
                                                {log.prev_hash}
                                            </p>
                                        </div>
                                    </div>
                                    <div>
                                        <p className="text-[10px] text-slate-500 font-bold uppercase mb-2">Digital Signature</p>
                                        <p className="text-xs text-slate-400 font-mono bg-slate-900/50 p-3 rounded-lg border border-slate-800/50 break-all">
                                            {log.signature}
                                        </p>
                                    </div>
                                </div>
                            )}
                        </div>
                    ))
                ) : (
                    <div className="py-20 text-center space-y-4">
                        <div className="w-16 h-16 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto">
                            <FileSearch className="w-8 h-8 text-slate-600" />
                        </div>
                        <div>
                            <p className="text-slate-400 font-bold text-lg">
                                {searchTerm ? 'No matching logs found' : 'No audit logs yet'}
                            </p>
                            <p className="text-slate-600 text-sm mt-2">
                                {searchTerm
                                    ? 'Try adjusting your search terms'
                                    : 'Run the simulator or issue identities to generate audit trails'}
                            </p>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AuditArchives;
