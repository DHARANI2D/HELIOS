import React from 'react';
import { Zap, Cpu, Lock } from 'lucide-react';

const ConnectivityHub = ({ API_BASE }) => {
    return (
        <div className="space-y-10 max-w-4xl mx-auto pb-20">
            <div className="space-y-4">
                <h2 className="text-4xl font-black">Agent Integration Hub</h2>
                <p className="text-slate-400 text-lg">Deploy the AEGIS Sidecar to enforce Zero‑Trust at the edge of your AI workloads.</p>
            </div>

            <div className="grid gap-6">
                <div className="bg-[#11141b] border border-slate-800 rounded-3xl p-8 space-y-6">
                    <div className="flex items-center gap-4 text-emerald-500 font-bold">
                        <Zap className="w-6 h-6" /> Step 1: Workload Registration
                    </div>
                    <p className="text-sm text-slate-400">Assign a unique identity string to your agent. This creates a cryptographic record in the registry.</p>
                    <pre className="bg-black/50 p-4 rounded-xl text-xs font-mono text-emerald-400 border border-emerald-900/30">
                        <code>curl -X POST {API_BASE}/identity/issue/MY-AI-AGENT</code>
                    </pre>
                </div>

                <div className="bg-[#11141b] border border-slate-800 rounded-3xl p-8 space-y-6">
                    <div className="flex items-center gap-4 text-blue-500 font-bold">
                        <Cpu className="w-6 h-6" /> Step 2: Deploy Sidecar Proxy
                    </div>
                    <p className="text-sm text-slate-400">Launch the AEGIS proxy container. It intercepts all outbound traffic from your agent, signs it, and validates it against central policy.</p>
                    <pre className="bg-black/50 p-4 rounded-xl text-xs font-mono text-blue-400 border border-blue-900/30 overflow-x-auto">
                        <code>{`docker run -d \\
  --name aegis-proxy \\
  -e AGENT_ID="MY-AI-AGENT" \\
  -e CONTROL_PLANE_URL="${API_BASE}" \\
  -p 3000:3000 \\
  aegis/governance-proxy:latest`}</code>
                    </pre>
                </div>

                <div className="bg-[#11141b] border border-slate-800 rounded-3xl p-8 space-y-6">
                    <div className="flex items-center gap-4 text-purple-500 font-bold">
                        <Lock className="w-6 h-6" /> Step 3: Configure Outbound SDK
                    </div>
                    <p className="text-sm text-slate-400">Update your AI agent to route its external requests (OpenAI API, Database, etc.) through the local proxy.</p>
                    <pre className="bg-black/50 p-4 rounded-xl text-xs font-mono text-purple-400 border border-purple-900/30">
                        <code>{`# Python Example
os.environ["HTTP_PROXY"] = "http://localhost:3000"
openai.api_base = "http://localhost:3000/v1"`}</code>
                    </pre>
                </div>
            </div>
        </div>
    );
};

export default ConnectivityHub;
