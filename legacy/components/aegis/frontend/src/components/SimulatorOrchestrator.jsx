import React, { useState, useEffect } from 'react';
import { RotateCcw, Zap, Play, ShieldAlert, AlertTriangle, CheckCircle2, XCircle, Loader2, Target, Activity, Clock } from 'lucide-react';
import axios from 'axios';

const SimulatorOrchestrator = ({ agents, handleReset, handleGlobalPurge, showPurgeConfirm, setShowPurgeConfirm }) => {
    const [scenarios, setScenarios] = useState([]);
    const [selectedScenario, setSelectedScenario] = useState(null);
    const [isRunning, setIsRunning] = useState(false);
    const [results, setResults] = useState(null);
    const [loading, setLoading] = useState(true);
    const [liveEvents, setLiveEvents] = useState([]);
    const [currentStep, setCurrentStep] = useState(0);

    const API_BASE = "http://localhost:8000";

    useEffect(() => {
        fetchScenarios();
    }, []);

    const fetchScenarios = async () => {
        try {
            const response = await axios.get(`${API_BASE}/scenarios`);
            setScenarios(response.data.scenarios);
            setLoading(false);
        } catch (err) {
            console.error("Failed to fetch scenarios:", err);
            setLoading(false);
        }
    };

    const runScenarioWithSteps = async (scenarioName) => {
        setIsRunning(true);
        setResults(null);
        setLiveEvents([]);
        setCurrentStep(0);

        try {
            // Fetch the full scenario data first
            const response = await axios.post(`${API_BASE}/scenarios/run/${scenarioName}`);
            const scenarioData = response.data;

            // Simulate step-by-step execution with delays
            for (let i = 0; i < scenarioData.events.length; i++) {
                setCurrentStep(i + 1);

                // Add "attempting" event
                setLiveEvents(prev => [...prev, {
                    type: 'attempting',
                    event: scenarioData.events[i],
                    timestamp: new Date().toLocaleTimeString()
                }]);

                // Wait to simulate processing
                await new Promise(resolve => setTimeout(resolve, 1500));

                // Add "result" event
                setLiveEvents(prev => [...prev, {
                    type: 'result',
                    event: scenarioData.events[i],
                    timestamp: new Date().toLocaleTimeString()
                }]);

                // Wait before next step
                await new Promise(resolve => setTimeout(resolve, 1000));
            }

            setResults(scenarioData);
        } catch (err) {
            console.error("Failed to run scenario:", err);
            setResults({ error: "Failed to execute scenario" });
        } finally {
            setIsRunning(false);
            setCurrentStep(0);
        }
    };

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/20';
            case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
            case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
            default: return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
        }
    };

    return (
        <div className="space-y-10">
            {/* Global Purge Confirmation Modal */}
            {showPurgeConfirm && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-[#11141b] border-2 border-red-500/50 rounded-3xl p-8 max-w-md w-full shadow-2xl shadow-red-900/50">
                        <div className="flex items-center gap-4 mb-6">
                            <div className="w-12 h-12 rounded-full bg-red-500/20 border border-red-500/30 flex items-center justify-center">
                                <ShieldAlert className="w-6 h-6 text-red-500 animate-pulse" />
                            </div>
                            <div>
                                <h3 className="text-xl font-bold text-red-500">CRITICAL WARNING</h3>
                                <p className="text-xs text-slate-400">This action cannot be undone</p>
                            </div>
                        </div>

                        <div className="space-y-4 mb-8">
                            <p className="text-slate-300 leading-relaxed">
                                You are about to execute a <span className="font-bold text-red-500">Global Purge</span> which will:
                            </p>
                            <ul className="space-y-2 text-sm text-slate-400 pl-6">
                                <li className="flex items-start gap-2">
                                    <XCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                                    <span>Revoke all AI agent identities</span>
                                </li>
                                <li className="flex items-start gap-2">
                                    <XCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                                    <span>Transition all nodes to L0 Isolation</span>
                                </li>
                                <li className="flex items-start gap-2">
                                    <XCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                                    <span>Disable all agent operations immediately</span>
                                </li>
                            </ul>
                            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl">
                                <p className="text-xs text-red-400 font-bold">
                                    ⚠️ This is an emergency security measure. Only proceed if you have confirmed a critical security breach.
                                </p>
                            </div>
                        </div>

                        <div className="flex gap-4">
                            <button
                                onClick={() => setShowPurgeConfirm(false)}
                                className="flex-1 px-6 py-3 bg-slate-800 border border-slate-700 rounded-xl font-bold text-sm hover:bg-slate-700 transition-all"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleGlobalPurge}
                                className="flex-1 px-6 py-3 bg-red-600 hover:bg-red-700 rounded-xl font-bold text-sm transition-all shadow-lg shadow-red-900/40"
                            >
                                Execute Purge
                            </button>
                        </div>
                    </div>
                </div>
            )}

            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-3xl font-bold">Simulator Orchestrator</h2>
                    <p className="text-slate-500 mt-1">Interactive real-world AI security scenarios</p>
                </div>
                <div className="flex gap-4">
                    <button onClick={handleReset} className="flex items-center gap-2 px-6 py-3 bg-slate-900 border border-slate-800 rounded-xl font-bold text-sm hover:bg-slate-800 transition-all">
                        <RotateCcw className="w-4 h-4" /> RESET ALL DATA
                    </button>
                    <div className="px-6 py-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 rounded-xl font-black text-xs uppercase tracking-widest flex items-center gap-3">
                        <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div> Engine Operational
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-3 gap-8">
                {/* Scenario Selection */}
                <div className="col-span-1 space-y-4">
                    <h3 className="text-lg font-bold flex items-center gap-2">
                        <Target className="w-5 h-5 text-emerald-500" />
                        Attack Scenarios
                    </h3>

                    {loading ? (
                        <div className="flex items-center justify-center py-10">
                            <Loader2 className="w-8 h-8 text-emerald-500 animate-spin" />
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {scenarios.map((scenario) => (
                                <div
                                    key={scenario.id}
                                    onClick={() => !isRunning && setSelectedScenario(scenario)}
                                    className={`p-4 rounded-xl border cursor-pointer transition-all ${selectedScenario?.id === scenario.id
                                        ? 'bg-emerald-500/10 border-emerald-500/30'
                                        : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
                                        } ${isRunning ? 'opacity-50 cursor-not-allowed' : ''}`}
                                >
                                    <div className="flex items-start justify-between mb-2">
                                        <h4 className="font-bold text-sm">{scenario.name}</h4>
                                        <span className={`text-[9px] font-black px-2 py-1 rounded border ${getSeverityColor(scenario.severity)}`}>
                                            {scenario.severity}
                                        </span>
                                    </div>
                                    <p className="text-xs text-slate-400 leading-relaxed">{scenario.description}</p>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Scenario Details & Execution */}
                <div className="col-span-2 space-y-6">
                    {selectedScenario ? (
                        <>
                            <div className="bg-[#11141b] border border-slate-800 rounded-[2rem] p-8 space-y-6">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <h3 className="text-2xl font-bold">{selectedScenario.name}</h3>
                                        <p className="text-slate-400 mt-1">{selectedScenario.description}</p>
                                    </div>
                                    <button
                                        onClick={() => runScenarioWithSteps(selectedScenario.name.toLowerCase().replace(/\s+/g, '_'))}
                                        disabled={isRunning}
                                        className={`px-8 py-4 emerald-gradient rounded-xl font-bold flex items-center gap-3 shadow-lg shadow-emerald-900/40 ${isRunning ? 'opacity-50 cursor-not-allowed' : 'hover:shadow-emerald-900/60'
                                            }`}
                                    >
                                        {isRunning ? (
                                            <>
                                                <Loader2 className="w-5 h-5 animate-spin" />
                                                EXECUTING...
                                            </>
                                        ) : (
                                            <>
                                                <Play className="w-5 h-5" />
                                                RUN SCENARIO
                                            </>
                                        )}
                                    </button>
                                </div>

                                {/* Live Event Stream */}
                                {(isRunning || liveEvents.length > 0) && (
                                    <div className="space-y-4 pt-6 border-t border-slate-800">
                                        <h4 className="text-lg font-bold flex items-center gap-2">
                                            <Activity className="w-5 h-5 text-emerald-500 animate-pulse" />
                                            Live Event Stream
                                        </h4>
                                        <div className="space-y-2 max-h-96 overflow-y-auto">
                                            {liveEvents.map((event, i) => (
                                                <div key={i} className={`flex gap-3 p-3 rounded-lg border ${event.type === 'attempting'
                                                    ? 'bg-blue-500/5 border-blue-500/20'
                                                    : event.event.decision === 'DENY'
                                                        ? 'bg-red-500/5 border-red-500/20'
                                                        : 'bg-emerald-500/5 border-emerald-500/20'
                                                    }`}>
                                                    <Clock className="w-4 h-4 text-slate-500 mt-0.5 flex-shrink-0" />
                                                    <div className="flex-1 min-w-0">
                                                        <div className="flex items-center gap-2 mb-1">
                                                            <span className="text-[10px] text-slate-500 font-mono">{event.timestamp}</span>
                                                            {event.type === 'attempting' ? (
                                                                <span className="text-xs font-bold text-blue-400">→ Attempting: {event.event.intent}</span>
                                                            ) : (
                                                                <span className={`text-xs font-bold ${event.event.decision === 'DENY' ? 'text-red-400' : 'text-emerald-400'}`}>
                                                                    ✓ {event.event.decision}: {event.event.intent}
                                                                </span>
                                                            )}
                                                        </div>
                                                        {event.type === 'result' && (
                                                            <p className="text-[11px] text-slate-400 italic">{event.event.reason}</p>
                                                        )}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Results Display */}
                                {results && !isRunning && (
                                    <div className="space-y-6 pt-6 border-t border-slate-800">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-lg font-bold flex items-center gap-2">
                                                <Activity className="w-5 h-5 text-emerald-500" />
                                                Final Results
                                            </h4>
                                            <div className={`px-4 py-2 rounded-xl border flex items-center gap-2 ${results.success
                                                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500'
                                                : 'bg-red-500/10 border-red-500/20 text-red-500'
                                                }`}>
                                                {results.success ? (
                                                    <>
                                                        <CheckCircle2 className="w-4 h-4" />
                                                        <span className="font-bold text-xs">ALL CHECKS PASSED</span>
                                                    </>
                                                ) : (
                                                    <>
                                                        <XCircle className="w-4 h-4" />
                                                        <span className="font-bold text-xs">ANOMALIES DETECTED</span>
                                                    </>
                                                )}
                                            </div>
                                        </div>

                                        {/* Forensic Summary */}
                                        <div className="p-6 bg-slate-900/50 border border-slate-800 rounded-xl space-y-3">
                                            <h5 className="text-sm font-bold text-slate-300 uppercase tracking-wider">Forensic Analysis</h5>
                                            <div className="grid grid-cols-3 gap-4">
                                                <div>
                                                    <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Agent ID</p>
                                                    <p className="text-sm font-mono text-slate-300">{results.agent_id}</p>
                                                </div>
                                                <div>
                                                    <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Interventions</p>
                                                    <p className="text-sm font-bold text-red-500">{results.total_interventions}</p>
                                                </div>
                                                <div>
                                                    <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Outcome</p>
                                                    <p className="text-sm font-bold text-emerald-500">{results.outcome}</p>
                                                </div>
                                            </div>
                                            <div className="pt-3 border-t border-slate-800/50">
                                                <p className="text-[10px] text-slate-500 font-bold uppercase mb-2">Notes</p>
                                                <p className="text-xs text-slate-400 leading-relaxed italic">{results.forensic_notes}</p>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* Emergency Controls */}
                            <div className="grid grid-cols-2 gap-6">
                                <div className="bg-emerald-500/5 border border-emerald-500/20 p-6 rounded-[2rem] space-y-3">
                                    <h4 className="font-bold text-emerald-500 tracking-widest uppercase text-xs">Environment Status</h4>
                                    <div className="flex items-center justify-between">
                                        <span className="text-2xl font-black">{agents.length} Nodes</span>
                                        <Play className="text-emerald-500 w-8 h-8 opacity-20" />
                                    </div>
                                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                                        <div className="h-full bg-emerald-500 w-[75%]"></div>
                                    </div>
                                </div>

                                <div
                                    className="bg-red-500/5 border border-red-500/20 p-6 rounded-[2rem] space-y-3 cursor-pointer hover:bg-red-500/10 transition-all"
                                    onClick={() => setShowPurgeConfirm(true)}
                                >
                                    <h4 className="font-bold text-red-500 tracking-widest uppercase text-xs">Emergency Lockdown</h4>
                                    <div className="flex items-center justify-between">
                                        <span className="text-2xl font-black">Global Purge</span>
                                        <ShieldAlert className="text-red-500 w-8 h-8 opacity-30" />
                                    </div>
                                    <p className="text-xs text-red-500/60 font-medium italic">Instantly transition all nodes to L0 Isolation.</p>
                                </div>
                            </div>
                        </>
                    ) : (
                        <div className="bg-[#11141b] border border-slate-800 rounded-[2rem] p-20 text-center">
                            <div className="w-16 h-16 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto mb-4">
                                <Zap className="w-8 h-8 text-slate-600" />
                            </div>
                            <p className="text-slate-400 font-bold text-lg">Select a scenario to begin</p>
                            <p className="text-slate-600 text-sm mt-2">Choose an attack scenario from the left to see details and run simulations</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default SimulatorOrchestrator;
