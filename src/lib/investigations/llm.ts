// Ported from asip's models/llm_clients.py LLMClientManager. Tries
// Anthropic, then OpenAI, then a local Ollama instance, then falls back to
// a deterministic mock response keyed by prompt content — the same
// offline-first design asip used, which matters here since this sandbox
// has no route to any of the three providers.

interface InvokeOptions {
  json?: boolean;
}

async function callAnthropic(systemPrompt: string, userPrompt: string): Promise<string> {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY!,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-5",
      max_tokens: 4096,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
    }),
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`Anthropic responded ${res.status}`);
  const data = await res.json();
  return data.content[0].text;
}

async function callOpenAI(systemPrompt: string, userPrompt: string, json?: boolean): Promise<string> {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      ...(json ? { response_format: { type: "json_object" } } : {}),
    }),
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`OpenAI responded ${res.status}`);
  const data = await res.json();
  return data.choices[0].message.content;
}

async function callOllama(systemPrompt: string, userPrompt: string, json?: boolean): Promise<string> {
  const baseUrl = process.env.OLLAMA_BASE_URL ?? "http://localhost:11434";
  const res = await fetch(`${baseUrl}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: process.env.LOCAL_MODEL ?? "qwen2.5:14b",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      stream: false,
      ...(json ? { format: "json" } : {}),
    }),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`Ollama responded ${res.status}`);
  const data = await res.json();
  return data.message?.content ?? "";
}

function mockResponse(systemPrompt: string, json?: boolean): string {
  const sp = systemPrompt.toLowerCase();

  // Order matters: check the most specific marker first. The QA prompt's
  // own text ("verify that the Root Cause Analysis is factually correct")
  // contains "root cause", so a naive rca-before-qa check order
  // misclassifies every QA mock response as an RCA one — a real bug this
  // port found in the original Python (same elif ordering, same overlap),
  // which meant asip's offline/no-API-key demo path always failed QA
  // validation. "adversarial" only appears in the QA prompt, so check it
  // before the broader "root cause" match.
  if (sp.includes("adversarial") || sp.includes("is_valid")) {
    const dict = {
      is_valid: true,
      validated_evidence: [
        "powershell.exe spawn confirmed by ingested endpoint event",
        "C2 connection to 185.220.101.5 confirmed by ingested network event",
      ],
      issues: [] as string[],
    };
    return json ? JSON.stringify(dict) : "QA: approved, all claims verified against ingested events.";
  }

  if (sp.includes("triage") || sp.includes("classify")) {
    const dict = {
      alert_type: "Suspicious Process Execution",
      severity: "high",
      mitre_tactic: "Execution (TA0002)",
      initial_hypothesis:
        "Office document macro spawned a PowerShell cradle to download a secondary payload.",
      evidence_required: ["Process creation logs for winword/outlook", "Network logs to destination IP"],
    };
    return json ? JSON.stringify(dict) : `Triage: ${dict.alert_type} (${dict.severity})`;
  }

  if (sp.includes("correlation") || sp.includes("root cause") || sp.includes("rca")) {
    const dict = {
      root_cause:
        "User opened a phishing attachment which triggered a macro spawning cmd.exe -> powershell.exe with a base64-encoded connection string.",
      timeline: [
        "08:01:23 - Outlook opened invoice.docx attachment",
        "08:01:31 - winword.exe spawned powershell.exe",
        "08:01:34 - powershell.exe connected to remote IP 185.220.101.5:4444",
      ],
      confidence_score: 0.9,
    };
    return json ? JSON.stringify(dict) : dict.root_cause;
  }

  return `# Incident Report

## Executive Summary
A high-severity execution threat was triaged and root-caused from the ingested telemetry.

## Root Cause Analysis
See the RCA panel for the correlated timeline and MITRE mapping.

## Containment
1. Isolate the affected host.
2. Revoke sessions for the affected account.
3. Block the C2 destination at the egress proxy.`;
}

export async function invokeAgent(
  systemPrompt: string,
  userPrompt: string,
  options: InvokeOptions = {},
): Promise<string> {
  const hasCloudKey = process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY;

  if (!hasCloudKey) {
    try {
      return await callOllama(systemPrompt, userPrompt, options.json);
    } catch {
      return mockResponse(systemPrompt, options.json);
    }
  }

  if (process.env.ANTHROPIC_API_KEY) {
    try {
      return await callAnthropic(systemPrompt, userPrompt);
    } catch {
      // fall through
    }
  }

  if (process.env.OPENAI_API_KEY) {
    try {
      return await callOpenAI(systemPrompt, userPrompt, options.json);
    } catch {
      // fall through
    }
  }

  return mockResponse(systemPrompt, options.json);
}

export function parseJsonResponse<T>(raw: string, fallback: T): T {
  try {
    const cleaned = raw.trim().replace(/```json/g, "").replace(/```/g, "");
    return JSON.parse(cleaned) as T;
  } catch {
    return fallback;
  }
}
