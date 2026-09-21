import React, { useState } from 'react';
import { Key, Loader2, ShieldAlert, CheckCircle2 } from 'lucide-react';

const IdentityRegistry = ({ agents, newId, setNewId, handleIssueId }) => {
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const validateInput = (id) => {
        if (!id || id.trim() === '') return 'Agent ID cannot be empty';
        if (id.length < 3) return 'Agent ID must be at least 3 characters';
        if (!/^[a-zA-Z0-9-_]+$/.test(id)) return 'Agent ID can only contain letters, numbers, hyphens, and underscores';
        if (agents.some(agent => agent.id === id)) return 'Agent ID already exists';
        return null;
    };

    const handleSubmit = async () => {
        const validationError = validateInput(newId);
        if (validationError) {
            setError(validationError);
            return;
        }

        setIsLoading(true);
        setError('');

        try {
            await handleIssueId();
            setNewId('');
        } catch (err) {
            setError('Failed to issue identity. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    const handleKeyPress = (e) => {
        if (e.key === 'Enter') handleSubmit();
    };

    const handleInputChange = (e) => {
        setNewId(e.target.value);
        if (error) setError('');
    };

    const getStatusBadge = (agent) => {
        if (agent.status === 'REVOKED' || agent.trust === 0) {
            return (
                <span className="px-3 py-1 bg-red-500/10 border border-red-500/20 text-red-500 rounded-lg text-[10px] font-black uppercase flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" />
                    REVOKED
                </span>
            );
        }
        if (agent.status === 'ACTIVE') {
            return (
                <span className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 rounded-lg text-[10px] font-black uppercase flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    ACTIVE
                </span>
            );
        }
        return (
            <span className="px-3 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg text-[10px] font-black uppercase">
                {agent.status}
            </span>
        );
    };

    return (
        <div className="space-y-10">
            <div>
                <h2 className="text-3xl font-bold">Identity Registry</h2>
                <p className="text-slate-500 mt-2">Issue cryptographic identities for AI agents</p>
            </div>

            <div className="bg-[#11141b] border border-slate-800 p-10 rounded-[3rem] space-y-6">
                <h3 className="text-xl font-bold flex items-center gap-3 text-emerald-500">
                    <Key className="w-6 h-6" /> Issue New Identity
                </h3>
                <div className="flex gap-4">
                    <input
                        type="text"
                        value={newId}
                        onChange={handleInputChange}
                        onKeyPress={handleKeyPress}
                        disabled={isLoading}
                        placeholder="agent-name (min 3 chars, alphanumeric + hyphens/underscores)"
                        className={`flex-1 px-6 py-4 bg-slate-900 border rounded-xl text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 transition-all ${error
                                ? 'border-red-500/50 focus:ring-red-500/50'
                                : 'border-slate-800 focus:ring-emerald-500/50'
                            } ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                    />
                    <button
                        onClick={handleSubmit}
                        disabled={isLoading || !newId}
                        className={`px-8 py-4 emerald-gradient rounded-xl font-bold flex items-center gap-3 transition-all ${isLoading || !newId
                                ? 'opacity-50 cursor-not-allowed'
                                : 'hover:shadow-lg hover:shadow-emerald-900/40'
                            }`}
                    >
                        {isLoading ? (
                            <>
                                <Loader2 className="w-5 h-5 animate-spin" />
                                ISSUING...
                            </>
                        ) : (
                            'ISSUE NEW ID'
                        )}
                    </button>
                </div>
                {error && (
                    <p className="text-red-500 text-xs flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4" />
                        {error}
                    </p>
                )}
            </div>

            <div className="space-y-4">
                <h3 className="text-xl font-bold">Registered Identities</h3>
                {agents.length === 0 ? (
                    <div className="bg-[#11141b] border border-slate-800 p-10 rounded-[2rem] text-center">
                        <p className="text-slate-400 font-bold">No identities issued yet</p>
                        <p className="text-slate-600 text-sm mt-2">Issue your first AI agent identity above to get started</p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 gap-4">
                        {agents.map(agent => (
                            <div
                                key={agent.id}
                                className={`bg-[#11141b] border p-6 rounded-2xl flex items-center justify-between ${agent.status === 'REVOKED' || agent.trust === 0
                                        ? 'border-red-500/30 bg-red-500/5'
                                        : 'border-slate-800'
                                    }`}
                            >
                                <div className="flex items-center gap-4">
                                    <div className={`p-3 rounded-xl ${agent.status === 'REVOKED' || agent.trust === 0
                                            ? 'bg-red-500/10 text-red-500'
                                            : 'bg-slate-900 text-blue-400'
                                        }`}>
                                        <Key className="w-5 h-5" />
                                    </div>
                                    <div>
                                        <p className="font-bold text-lg">{agent.id}</p>
                                        <p className="text-xs text-slate-500">
                                            Trust: <span className={`font-bold ${agent.trust === 0 ? 'text-red-500' :
                                                    agent.trust < 50 ? 'text-orange-500' :
                                                        agent.trust < 80 ? 'text-yellow-500' :
                                                            'text-emerald-500'
                                                }`}>{agent.trust.toFixed(1)}%</span>
                                        </p>
                                    </div>
                                </div>
                                {getStatusBadge(agent)}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default IdentityRegistry;
