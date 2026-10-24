import type { IndicatorType } from "@prisma/client";

// Reference facts seeded into a new install. Everything else HELIOS prices
// or measures — your service plans, rates, SLAs, exchange rates — is your
// own policy and starts empty until an admin sets it.

// Anthropic first-party list prices, USD per million tokens. Local models
// cost nothing per token; add them with 0/0 if you want them listed.
export const MODEL_PRICES: Array<{ model: string; provider: string; inputPer: number; outputPer: number; source: string }> = [
  { model: "claude-fable-5-1", provider: "Anthropic", inputPer: 10, outputPer: 50, source: "claude.com/pricing" },
  { model: "claude-opus-5-5", provider: "Anthropic", inputPer: 4, outputPer: 20, source: "claude.com/pricing" },
  { model: "claude-sonnet-5-5", provider: "Anthropic", inputPer: 2, outputPer: 10, source: "claude.com/pricing" },
  { model: "claude-haiku-5-5", provider: "Anthropic", inputPer: 0.1, outputPer: 0.5, source: "claude.com/pricing (prompts up to 100K tokens)" },
];

// The currency every price in HELIOS is stored in. Others are added by an
// admin with the rate they actually bill at.
export const BASE_CURRENCY = { code: "USD", symbol: "$", rate: 1 };

// Public, free threat feeds the Threat Intel page can import. Disabled until
// an admin turns one on — importing pulls from the internet.
export const THREAT_FEEDS: Array<{ name: string; url: string; indicatorType: IndicatorType; maliciousScore: number; description: string }> = [
  {
    name: "Tor Project bulk exit list",
    url: "https://check.torproject.org/torbulkexitlist",
    indicatorType: "IP",
    maliciousScore: 0.5,
    description: "Current Tor exit relays. Not malicious in itself — flags anonymized access to client systems.",
  },
  {
    name: "abuse.ch Feodo Tracker botnet C2 IPs",
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    indicatorType: "IP",
    maliciousScore: 0.95,
    description: "Active botnet command-and-control servers (Dridex, Emotet, TrickBot, QakBot and successors).",
  },
  {
    name: "abuse.ch URLhaus online malware URLs",
    url: "https://urlhaus.abuse.ch/downloads/text_online/",
    indicatorType: "URL",
    maliciousScore: 0.9,
    description: "URLs currently serving malware.",
  },
];
