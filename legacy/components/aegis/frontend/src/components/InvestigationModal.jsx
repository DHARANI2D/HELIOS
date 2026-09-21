import React, { useState } from 'react';
import { X, AlertTriangle, CheckCircle2, XCircle, Clock, Shield, FileText, RotateCcw } from 'lucide-react';

const InvestigationModal = ({ agent, onClose, onRestore, onConfirmBreach }) => {
    const [loading, setLoading] = useState(false);
    const [showRestoreConfirm, setShowRestoreConfirm] = useState(false);

    if (!agent || !agent.investigation) return null;

    const inv = agent.investigation;

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/30';
            case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
            case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
            default: return 'text-blue-500 bg-blue-500/10 border-blue-500/30';
        }
    };

    const getStatusBadge = (status) => {
        const badges = {
            'UNDER_INVESTIGATION': { color: 'bg-blue-500/10 border-blue-500/20 text-blue-400', icon: Clock },
            'CONFIRMED': { color: 'bg-red-500/10 border-red-500/20 text-red-500', icon: XCircle },
            'FALSE_POSITIVE': { color: 'bg-green-500/10 border-green-500/20 text-green-500', icon: CheckCircle2 },
            'RESTORED': { color: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500', icon: CheckCircle2 }
        };
        const badge = badges[status] || badges['UNDER_INVESTIGATION'];
        const Icon = badge.icon;
        return (
            <span className={`px-3 py-1 rounded-lg border text-xs font-bold uppercase flex items-center gap-2 ${badge.color}`}>
                <Icon className="w-3 h-3" />
                {status.replace(/_/g, ' ')}
            </span>
        );
    };

    const handleRestore = async () => {
        setLoading(true);
        await onRestore(agent.id);
        setLoading(false);
        setShowRestoreConfirm(false);
    };

    const handleConfirmBreach = async () => {
        setLoading(true);
        await onConfirmBreach(agent.id);
        setLoading(false);
    };

    return (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
            <div className="bg-[#11141b] border border-slate-800 rounded-3xl max-w-4xl w-full my-8 shadow-2xl">
                {/* Header */}
                <div className="p-8 border-b border-slate-800">
                    <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-full bg-red-500/20 border border-red-500/30 flex items-center justify-center">
                                <Shield className="w-6 h-6 text-red-500" />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold">Breach Investigation</h2>
                                <p className="text-slate-400 text-sm mt-1">Agent ID: <span className="font-mono text-white">{agent.id}</span></p>
                            </div>
                        </div>
                        <button onClick={onClose} className="p-2 hover:bg-slate-800 rounded-lg transition-colors">
                            <X className="w-5 h-5" />
                        </button>
                    </div>

                    <div className="flex items-center gap-3">
                        <span className={`px-4 py-2 rounded-xl border font-bold text-sm ${getSeverityColor(inv.severity)}`}>
                            {inv.severity} SEVERITY
                        </span>
                        {getStatusBadge(inv.status)}
                    </div>
                </div>

                {/* Content */}
                <div className="p-8 space-y-6 max-h-[60vh] overflow-y-auto">
                    {/* Breach Type */}
                    <div>
                        <h3 className="text-lg font-bold mb-3 flex items-center gap-2">
                            <AlertTriangle className="w-5 h-5 text-orange-500" />
                            Breach Classification
                        </h3>
                        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                            <p className="text-white font-bold">{inv.breach_type.replace(/_/g, ' ')}</p>
                            <p className="text-slate-400 text-sm mt-2">{inv.detection_mechanism}</p>
                        </div>
                    </div>

                    {/* Detection Mechanism Explanation */}
                    <div>
                        <h3 className="text-lg font-bold mb-3">How Was This Detected?</h3>
                        <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 space-y-3">
                            <p className="text-sm text-slate-300 leading-relaxed">
                                AEGIS uses <span className="font-bold text-blue-400">pattern-based detection</span> without accessing actual sensitive data:
                            </p>
                            <ul className="space-y-2 text-sm text-slate-400">
                                {inv.evidence?.detection_methods?.map((method, i) => (
                                    <li key={i} className="flex items-start gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                                        <span>{method}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>

                    {/* Evidence Timeline */}
                    {inv.evidence?.timeline && (
                        <div>
                            <h3 className="text-lg font-bold mb-3">Event Timeline</h3>
                            <div className="space-y-2">
                                {inv.evidence.timeline.map((event, i) => (
                                    <div key={i} className="flex gap-3 p-3 bg-slate-900/50 border border-slate-800 rounded-lg">
                                        <Clock className="w-4 h-4 text-slate-500 mt-0.5 flex-shrink-0" />
                                        <div className="flex-1">
                                            <p className="text-sm font-bold text-white">{event.event}</p>
                                            <p className="text-xs text-slate-500 mt-1">
                                                {new Date(event.timestamp * 1000).toLocaleString()}
                                            </p>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Previous State */}
                    <div>
                        <h3 className="text-lg font-bold mb-3">Agent State Before Revocation</h3>
                        <div className="grid grid-cols-3 gap-4">
                            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                                <p className="text-xs text-slate-500 font-bold uppercase mb-1">Trust Score</p>
                                <p className="text-2xl font-bold text-emerald-500">{inv.evidence?.previous_trust?.toFixed(1)}%</p>
                            </div>
                            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                                <p className="text-xs text-slate-500 font-bold uppercase mb-1">Status</p>
                                <p className="text-sm font-bold text-white">{inv.evidence?.previous_status}</p>
                            </div>
                            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                                <p className="text-xs text-slate-500 font-bold uppercase mb-1">Access Level</p>
                                <p className="text-2xl font-bold text-blue-400">L{inv.evidence?.previous_level}</p>
                            </div>
                        </div>
                    </div>

                    {/* Recommendation */}
                    {inv.recommendation && (
                        <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-4">
                            <p className="text-sm font-bold text-yellow-500 mb-2">RECOMMENDED ACTION</p>
                            <p className="text-sm text-slate-300">{inv.recommendation}</p>
                        </div>
                    )}
                </div>

                {/* Actions */}
                <div className="p-8 border-t border-slate-800 flex gap-4">
                    {inv.status === 'UNDER_INVESTIGATION' && (
                        <>
                            <button
                                onClick={() => setShowRestoreConfirm(true)}
                                disabled={loading}
                                className="flex-1 px-6 py-3 bg-emerald-600 hover:bg-emerald-700 rounded-xl font-bold text-sm transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                            >
                                <RotateCcw className="w-4 h-4" />
                                Restore Agent
                            </button>
                            <button
                                onClick={handleConfirmBreach}
                                disabled={loading}
                                className="flex-1 px-6 py-3 bg-red-600 hover:bg-red-700 rounded-xl font-bold text-sm transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                            >
                                <XCircle className="w-4 h-4" />
                                Confirm Breach
                            </button>
                        </>
                    )}
                    <button
                        onClick={onClose}
                        className="px-6 py-3 bg-slate-800 border border-slate-700 rounded-xl font-bold text-sm hover:bg-slate-700 transition-all"
                    >
                        Close
                    </button>
                </div>

                {/* Restore Confirmation */}
                {showRestoreConfirm && (
                    <div className="absolute inset-0 bg-black/60 backdrop-blur-sm rounded-3xl flex items-center justify-center p-4">
                        <div className="bg-[#11141b] border border-emerald-500/30 rounded-2xl p-6 max-w-md">
                            <h3 className="text-xl font-bold mb-4">Confirm Agent Restoration</h3>
                            <p className="text-slate-400 text-sm mb-6">
                                This will restore <span className="font-mono text-white">{agent.id}</span> to full access with 100% trust.
                                Only proceed if you've verified this was a false positive.
                            </p>
                            <div className="flex gap-3">
                                <button
                                    onClick={() => setShowRestoreConfirm(false)}
                                    className="flex-1 px-4 py-2 bg-slate-800 rounded-lg font-bold text-sm"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleRestore}
                                    disabled={loading}
                                    className="flex-1 px-4 py-2 bg-emerald-600 rounded-lg font-bold text-sm disabled:opacity-50"
                                >
                                    {loading ? 'Restoring...' : 'Confirm Restore'}
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default InvestigationModal;
