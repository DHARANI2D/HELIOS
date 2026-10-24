import type { NextRequest } from "next/server";
import { z } from "zod";

import { agentForToken } from "@/lib/governance/agents";
import { evaluateAgentAction } from "@/lib/governance/runtime";

// Governance gate for AI agents:
//   POST /api/governance/evaluate
//   Authorization: Bearer <agent token shown when the identity was issued>
//   { "action": { "name": "<INTENT>", "target": "...", "reasoning": ["..."], "confidence": 0.9, ...context },
//     "environment": "production" | "staging" | "development" }
// Answers { decision: ALLOW | DENY | ESCALATE, layer, reason, trust, caseId }.
// The agent proceeds only on ALLOW; ESCALATE means wait for a human.

const MAX_BYTES = 256 * 1024;
const RATE_LIMIT_PER_MINUTE = 600;
const hits = new Map<string, { windowStart: number; count: number }>();

function rateLimited(id: string) {
  const now = Date.now();
  const entry = hits.get(id);
  if (!entry || now - entry.windowStart > 60_000) {
    hits.set(id, { windowStart: now, count: 1 });
    return false;
  }
  entry.count++;
  return entry.count > RATE_LIMIT_PER_MINUTE;
}

const bodySchema = z.object({
  action: z
    .object({
      name: z.string().trim().min(1).max(80),
      target: z.string().max(2000).optional(),
      reasoning: z.array(z.string().max(4000)).max(50).optional(),
      confidence: z.number().min(0).max(1).optional(),
    })
    .passthrough(),
  environment: z.enum(["production", "staging", "development"]).default("production"),
});

export async function POST(request: NextRequest) {
  const agent = await agentForToken(request.headers.get("authorization"));
  if (!agent) return Response.json({ error: "Invalid or revoked agent token" }, { status: 401 });
  if (rateLimited(agent.id)) return Response.json({ error: `Rate limit: ${RATE_LIMIT_PER_MINUTE} requests per minute` }, { status: 429 });

  const text = await request.text();
  if (text.length > MAX_BYTES) return Response.json({ error: "Body larger than 256 KB" }, { status: 413 });
  let parsed;
  try {
    parsed = bodySchema.safeParse(JSON.parse(text));
  } catch {
    return Response.json({ error: "Body must be JSON" }, { status: 400 });
  }
  if (!parsed.success) return Response.json({ error: "Invalid request", issues: parsed.error.issues.slice(0, 5) }, { status: 400 });

  const verdict = await evaluateAgentAction(agent, parsed.data.action, parsed.data.environment);
  return Response.json(verdict, { status: verdict.layer === "IDENTITY" ? 403 : 200 });
}
