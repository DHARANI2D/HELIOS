import type { AiAutonomy, PlaybookActionType } from "@prisma/client";

// What AI agents exist, which providers can run them, and what they cost.
// Client-safe: the AI Agents page and the pricing configurator both read it.

export type AgentKey = "triage" | "phishing" | "threat_intel" | "investigator" | "report" | "containment" | "investigation" | "advisor";

export interface AgentType {
  key: AgentKey;
  name: string;
  description: string;
  // Can an analyst send it onto a case from the case page?
  dispatchable: boolean;
  defaultAutonomy: AiAutonomy;
  defaultActions: PlaybookActionType[];
  defaultMinConfidence: number;
}

export const AGENT_TYPES: Record<AgentKey, AgentType> = {
  triage: {
    key: "triage",
    name: "Triage first responder",
    description: "Runs on every new case: initial analysis, verdict and confidence, the evidence behind it, and recommended containment. Hands the case to the right analyst tier.",
    dispatchable: true,
    defaultAutonomy: "SUGGEST",
    defaultActions: [],
    defaultMinConfidence: 0.8,
  },
  containment: {
    key: "containment",
    name: "Containment controller",
    description: "Decides what happens to the containment the other agents recommend: suggest only, queue for approval, or act on pre-approved actions above a confidence bar. Policy, not a model — it never improvises an action.",
    dispatchable: false,
    defaultAutonomy: "CONTAIN_WITH_APPROVAL",
    defaultActions: ["BLOCK_IP", "BLOCK_SENDER", "QUARANTINE_FILE", "COLLECT_LOGS"],
    defaultMinConfidence: 0.85,
  },
  phishing: {
    key: "phishing",
    name: "Phishing analyst",
    description: "Email specialist: reads the forensic verdict, headers, links and attachments and explains the lure, the sender's infrastructure and who else may have received it.",
    dispatchable: true,
    defaultAutonomy: "SUGGEST",
    defaultActions: [],
    defaultMinConfidence: 0.8,
  },
  threat_intel: {
    key: "threat_intel",
    name: "Threat-intel enricher",
    description: "Puts the case's IOCs in context: reputation, infrastructure overlap with earlier cases, likely campaign, and which indicators are worth blocking.",
    dispatchable: true,
    defaultAutonomy: "SUGGEST",
    defaultActions: [],
    defaultMinConfidence: 0.8,
  },
  investigator: {
    key: "investigator",
    name: "Investigation agent",
    description: "Works a case on its own with read-only tools: searches the client's telemetry around it, checks the hosts, accounts and indicators it finds, reads related cases, then reports what happened with every finding and timeline step tied to what it looked at. It can't change anything; containment it recommends goes through the same policy as triage.",
    dispatchable: true,
    defaultAutonomy: "SUGGEST",
    defaultActions: [],
    defaultMinConfidence: 0.8,
  },
  report: {
    key: "report",
    name: "Client report writer",
    description: "Drafts a plain-language incident summary for the client. Saved as an internal draft; an analyst publishes it.",
    dispatchable: true,
    defaultAutonomy: "SUGGEST",
    defaultActions: [],
    defaultMinConfidence: 0,
  },
  investigation: {
    key: "investigation",
    name: "Investigation swarm",
    description: "The triage → root cause → adversarial QA → report pipeline behind Investigations.",
    dispatchable: false,
    defaultAutonomy: "SUGGEST",
    defaultActions: [],
    defaultMinConfidence: 0,
  },
  advisor: {
    key: "advisor",
    name: "Stack advisor",
    description: "Suggests the protection stack for a client's endpoint mix, users and budget in Build & Price and the public estimator. It chooses among catalog tools the rules have already priced and checked, and explains the trade-offs and price differences.",
    dispatchable: false,
    defaultAutonomy: "SUGGEST",
    defaultActions: [],
    defaultMinConfidence: 0,
  },
};

export const AGENT_KEYS = Object.keys(AGENT_TYPES) as AgentKey[];
export const DISPATCHABLE_AGENTS = AGENT_KEYS.filter((k) => AGENT_TYPES[k].dispatchable);

export const AUTONOMY_LABEL: Record<AiAutonomy, string> = {
  OFF: "Off",
  SUGGEST: "Suggest only",
  CONTAIN_WITH_APPROVAL: "Contain with approval",
  AUTO_CONTAIN: "Auto-contain (pre-approved actions)",
};

export const AUTONOMY_ORDER: AiAutonomy[] = ["OFF", "SUGGEST", "CONTAIN_WITH_APPROVAL", "AUTO_CONTAIN"];

export function minAutonomy(a: AiAutonomy, b: AiAutonomy): AiAutonomy {
  return AUTONOMY_ORDER.indexOf(a) <= AUTONOMY_ORDER.indexOf(b) ? a : b;
}

export type ProviderKind = "anthropic" | "bedrock" | "azure_openai" | "openai_compatible";
export const PROVIDER_KINDS: ProviderKind[] = ["anthropic", "bedrock", "azure_openai", "openai_compatible"];

export const KIND_LABEL: Record<ProviderKind, string> = {
  anthropic: "Anthropic API",
  bedrock: "Claude in Amazon Bedrock",
  azure_openai: "Azure OpenAI",
  openai_compatible: "OpenAI-compatible endpoint",
};

export interface ProviderPreset {
  id: string;
  kind: ProviderKind;
  label: string;
  isLocal: boolean;
  baseUrl?: string;
  // Bedrock: the AWS region it calls.
  region?: string;
  defaultModel: string;
  models: string[];
  note: string;
}

// Claude in Amazon Bedrock takes the anthropic.-prefixed model IDs. HELIOS's
// Claude SDK sends API version 2026-10-21, which Bedrock accepts for Claude
// 4.7 and later only, so older Bedrock models aren't offered.
export const BEDROCK_MODEL = /^anthropic\.claude-[a-z0-9.-]+$/;
function oldClaude(model: string) {
  if (/^anthropic\.claude-(\d|instant|v\d)/.test(model)) return true; // claude-3-5-sonnet, claude-instant, claude-v2
  const m = /^anthropic\.claude-(?:opus|sonnet|haiku)-(\d+)(?:-(\d+))?/.exec(model);
  if (!m) return false;
  const major = Number(m[1]);
  const minor = m[2] && m[2].length < 8 ? Number(m[2]) : 0; // an 8-digit date isn't a minor version
  return major < 4 || (major === 4 && minor < 7);
}
export function bedrockModelProblem(model: string): string | null {
  if (!BEDROCK_MODEL.test(model)) return `A Bedrock model ID starts with "anthropic." (for example anthropic.claude-sonnet-5-5)`;
  if (oldClaude(model)) return "HELIOS calls Bedrock with an API version that works with Claude 4.7 and later only";
  return null;
}

// Local presets all speak the OpenAI-compatible /v1/chat/completions API
// with JSON-schema structured output.
export const PROVIDER_PRESETS: ProviderPreset[] = [
  {
    id: "claude",
    kind: "anthropic",
    label: "Claude (Anthropic API, online)",
    isLocal: false,
    defaultModel: "claude-opus-5-5",
    models: ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"],
    note: "Hosted by Anthropic. Needs an API key; telemetry excerpts leave your network.",
  },
  {
    id: "bedrock",
    kind: "bedrock",
    label: "Claude in Amazon Bedrock",
    isLocal: false,
    region: "ap-south-1",
    defaultModel: "anthropic.claude-sonnet-5-5",
    models: ["anthropic.claude-opus-5-5", "anthropic.claude-sonnet-5-5", "anthropic.claude-haiku-5-5"],
    note: "Claude in your own AWS account, in the region you pick (ap-south-1 is Mumbai). A Bedrock API key, or an access key pair; for a platform provider, leave both blank to use the server's AWS role. Claude 4.7 and later only.",
  },
  {
    id: "azure",
    kind: "azure_openai",
    label: "Azure OpenAI",
    isLocal: false,
    baseUrl: "https://YOUR-RESOURCE.openai.azure.com",
    defaultModel: "gpt-4o",
    models: ["gpt-4o", "gpt-4.1", "gpt-4o-mini"],
    note: "Your Azure OpenAI resource. The model is your deployment's name; the key is the resource's API key. Pick a deployment that supports structured outputs (gpt-4o 2024-08-06 or later).",
  },
  {
    id: "ollama",
    kind: "openai_compatible",
    label: "Ollama (local, offline)",
    isLocal: true,
    baseUrl: "http://localhost:11434/v1",
    defaultModel: "qwen2.5:14b",
    models: ["qwen2.5:14b", "llama3.1:8b", "llama3.3:70b", "mistral-small:24b"],
    note: "Runs on your own hardware. Pull the model first (ollama pull …).",
  },
  {
    id: "lmstudio",
    kind: "openai_compatible",
    label: "LM Studio (local, offline)",
    isLocal: true,
    baseUrl: "http://localhost:1234/v1",
    defaultModel: "qwen2.5-14b-instruct",
    models: ["qwen2.5-14b-instruct", "meta-llama-3.1-8b-instruct"],
    note: "Start the local server from LM Studio's Developer tab.",
  },
  {
    id: "vllm",
    kind: "openai_compatible",
    label: "vLLM / llama.cpp server (self-hosted)",
    isLocal: true,
    baseUrl: "http://localhost:8000/v1",
    defaultModel: "Qwen/Qwen2.5-14B-Instruct",
    models: ["Qwen/Qwen2.5-14B-Instruct", "meta-llama/Llama-3.1-8B-Instruct"],
    note: "GPU server you run; any OpenAI-compatible endpoint works.",
  },
  {
    id: "edge",
    kind: "openai_compatible",
    label: "HELIOS AI box (on the client's site)",
    isLocal: true,
    baseUrl: "https://ai-box.client.example/v1",
    defaultModel: "qwen2.5:14b",
    models: ["qwen2.5:14b", "qwen2.5:32b", "llama3.3:70b"],
    note: "The on-premises box from deploy/edge-ai: Ollama behind a TLS proxy that wants the box's API key. Telemetry is analysed on the client's own hardware.",
  },
];
