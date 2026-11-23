import type { AiSystem } from "@prisma/client";
import { z } from "zod";

import { openSealed } from "@/lib/keys";
import { publicFetch } from "@/lib/net/public-fetch";
import { Masker } from "@/lib/aisec/mask";
import { guard, policyOf, type GuardOutcome } from "@/lib/aisec/service";
import { VERDICT_RANK, type Verdict } from "@/lib/aisec/policy";

// The AI gateway: an application sends its model calls to HELIOS
// (POST /api/v1/ai/gateway/chat/completions, the OpenAI chat-completions
// shape) instead of to the model provider. HELIOS
//   1. checks the newest prompt and tool results against the system's policy;
//   2. masks personal data (privacy mode) so the provider never receives it;
//   3. calls the provider with the key it holds (sealed with the client's
//      key; the application never has it);
//   4. restores the masked values, then checks the answer and each tool
//      call the model asks for, before the application sees them.
// Every check is a guard decision with a signed receipt. Streaming isn't
// supported: the whole answer has to be checked before anyone sees it.

const content = z.union([z.string(), z.array(z.object({ type: z.string(), text: z.string().optional() }).passthrough()), z.null()]);
const message = z
  .object({
    role: z.enum(["system", "developer", "user", "assistant", "tool"]),
    content: content.optional(),
    name: z.string().max(120).optional(),
    tool_call_id: z.string().max(200).optional(),
    tool_calls: z.array(z.object({ id: z.string(), type: z.literal("function"), function: z.object({ name: z.string(), arguments: z.string() }) })).optional(),
  })
  .passthrough();
export const chatSchema = z
  .object({
    model: z.string().max(120).optional(),
    messages: z.array(message).min(1).max(500),
    temperature: z.number().min(0).max(2).optional(),
    top_p: z.number().min(0).max(1).optional(),
    max_tokens: z.number().int().min(1).max(32_000).optional(),
    max_completion_tokens: z.number().int().min(1).max(32_000).optional(),
    tools: z.array(z.unknown()).max(128).optional(),
    tool_choice: z.unknown().optional(),
    response_format: z.unknown().optional(),
    stream: z.boolean().optional(),
    user: z.string().max(200).optional(),
  })
  .passthrough();
export type ChatRequest = z.infer<typeof chatSchema>;
type Message = ChatRequest["messages"][number];

export class GatewayError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const textOf = (c: Message["content"]): string => (typeof c === "string" ? c : Array.isArray(c) ? c.map((p) => (typeof p.text === "string" ? p.text : "")).join("\n") : "");

function mapText(m: Message, fn: (s: string) => string): Message {
  const c = m.content;
  const next = typeof c === "string" ? fn(c) : Array.isArray(c) ? c.map((p) => (typeof p.text === "string" ? { ...p, text: fn(p.text) } : p)) : c;
  return { ...m, content: next, ...(m.tool_calls ? { tool_calls: m.tool_calls.map((t) => ({ ...t, function: { ...t.function, arguments: fn(t.function.arguments) } })) } : {}) };
}

export interface GatewayOptions {
  fetchImpl?: typeof fetch;
  user?: { id?: string; ip?: string };
  now?: () => Date;
}

export interface GatewayResult {
  status: number;
  body: unknown;
  decision: Verdict;
  receipts: string[];
}

const worstOf = (outs: GuardOutcome[]) => outs.reduce<Verdict>((d, o) => (VERDICT_RANK[o.enforced] > VERDICT_RANK[d] ? o.enforced : d), "allow");

function filtered(model: string, text: string, outs: GuardOutcome[], masked: number) {
  return {
    id: `chatcmpl-helios-${Date.now().toString(36)}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "content_filter" }],
    helios: summary(outs, masked),
  };
}

function summary(outs: GuardOutcome[], masked: number) {
  return {
    decision: worstOf(outs),
    masked,
    checks: outs.map((o) => ({ stage: o.receipt.body.stage, decision: o.decision, enforced: o.enforced, rules: o.findings.map((f) => f.rule), receipt: o.receipt.body.id, explanation: o.explanation })),
    ...(outs.some((o) => o.needsConfirmation) ? { needsConfirmation: true } : {}),
  };
}

export async function gatewayChat(system: AiSystem, raw: unknown, opts: GatewayOptions = {}): Promise<GatewayResult> {
  const now = opts.now ?? (() => new Date());
  const parsed = chatSchema.safeParse(raw);
  if (!parsed.success) throw new GatewayError(400, `Invalid request: ${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
  const req = parsed.data;
  if (req.stream) throw new GatewayError(400, "Streaming isn't supported: HELIOS checks the whole answer before it's returned. Send stream: false.");
  if (!system.upstreamUrl || !system.upstreamCipher) throw new GatewayError(409, "This AI system has no model provider set up in HELIOS (AI Security → the system → Gateway)");
  const model = req.model || system.upstreamModel;
  if (!model) throw new GatewayError(400, "Say which model (model), or set a default model on the system");
  const user = { id: opts.user?.id ?? req.user, ip: opts.user?.ip };
  const outs: GuardOutcome[] = [];
  // In privacy mode personal data and credentials are masked below, with
  // placeholders the model can refer to and the answer gets back; the
  // guard's irreversible masking is only for anything else it masked.
  const takeGuardMask = (o: GuardOutcome) => o.enforced === "redact" && o.content !== undefined && !(system.privacyMode && o.findings.filter((f) => f.verdict === "redact").every((f) => f.rule.startsWith("pii.") || f.rule === "secret"));
  const messages = [...req.messages];

  // 1. The newest turn: the last person's message, and any tool results after it.
  const lastUser = messages.map((m) => m.role).lastIndexOf("user");
  if (lastUser >= 0) {
    const o = await guard(system, { stage: "prompt", content: textOf(messages[lastUser].content), user }, now());
    outs.push(o);
    if (takeGuardMask(o)) messages[lastUser] = { ...messages[lastUser], content: o.content };
  }
  for (let i = Math.max(0, lastUser + 1); i < messages.length; i++) {
    if (messages[i].role !== "tool") continue;
    const o = await guard(system, { stage: "tool_output", content: textOf(messages[i].content), user }, now());
    outs.push(o);
    if (takeGuardMask(o)) messages[i] = { ...messages[i], content: o.content };
  }
  const masker = new Masker(policyOf(system).pii.kinds.length ? policyOf(system).pii.kinds : ["email", "phone"]);
  if (outs.some((o) => o.enforced === "block")) {
    const b = outs.find((o) => o.enforced === "block")!;
    return { status: 200, body: filtered(model, `HELIOS stopped this request: ${b.explanation}`, outs, 0), decision: "block", receipts: outs.map((o) => o.receipt.body.id) };
  }

  // 2. Privacy mode.
  const outgoing = system.privacyMode ? messages.map((m) => mapText(m, (s) => masker.mask(s))) : messages;

  // 3. The provider.
  const key = await openSealed(system.upstreamCipher);
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${system.upstreamUrl}/chat/completions`;
  const init: RequestInit = {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${key}`, "api-key": key },
    body: JSON.stringify({ ...req, model, messages: outgoing, stream: false, user: undefined }),
    signal: AbortSignal.timeout(120_000),
  };
  let res: Response;
  try {
    res = process.env.HELIOS_AI_GATEWAY_ALLOW_PRIVATE === "1" || opts.fetchImpl ? await fetchImpl(url, init) : await publicFetch(url, init, fetchImpl);
  } catch (err) {
    throw new GatewayError(502, `The model provider couldn't be reached: ${err instanceof Error ? err.message : String(err)}`);
  }
  const text = await res.text();
  if (!res.ok) throw new GatewayError(502, `The model provider answered ${res.status}: ${text.replaceAll(key, "[key]").slice(0, 300)}`);
  let answer: { choices?: Array<{ index?: number; message?: { role?: string; content?: string | null; tool_calls?: Array<{ id: string; type: string; function: { name: string; arguments: string } }> }; finish_reason?: string }>; [k: string]: unknown };
  try {
    answer = JSON.parse(text);
  } catch {
    throw new GatewayError(502, "The model provider's answer wasn't JSON");
  }

  // 4. Back through the guard.
  for (const choice of answer.choices ?? []) {
    const msg = choice.message;
    if (!msg) continue;
    if (typeof msg.content === "string") {
      const restored = system.privacyMode ? masker.restore(msg.content) : msg.content;
      const o = await guard(system, { stage: "output", content: restored, user }, now());
      outs.push(o);
      if (o.enforced === "block") {
        msg.content = `HELIOS withheld this answer: ${o.explanation}`;
        choice.finish_reason = "content_filter";
      } else msg.content = o.enforced === "redact" && o.content !== undefined ? o.content : restored;
    }
    if (msg.tool_calls?.length) {
      const kept: typeof msg.tool_calls = [];
      for (const call of msg.tool_calls) {
        const argsText = system.privacyMode ? masker.restore(call.function.arguments) : call.function.arguments;
        let args: Record<string, unknown> = {};
        try {
          const a = JSON.parse(argsText || "{}");
          args = a && typeof a === "object" && !Array.isArray(a) ? a : { value: a };
        } catch {
          args = { raw: argsText };
        }
        const o = await guard(system, { stage: "tool_call", tool: { name: call.function.name, args }, user }, now());
        outs.push(o);
        if (o.enforced === "block") continue;
        kept.push({ ...call, function: { ...call.function, arguments: argsText } });
      }
      if (kept.length !== msg.tool_calls.length) {
        const blocked = outs.filter((o) => o.receipt.body.stage === "tool_call" && o.enforced === "block");
        msg.tool_calls = kept.length ? kept : undefined;
        const note = `HELIOS blocked ${blocked.length} tool call(s): ${blocked.map((b) => b.explanation).join(" ")}`;
        msg.content = msg.content ? `${msg.content}\n\n${note}` : note;
        if (!kept.length) choice.finish_reason = blocked.some((b) => b.needsConfirmation) ? "stop" : "content_filter";
      }
    }
  }
  return { status: 200, body: { ...answer, helios: summary(outs, masker.masked) }, decision: worstOf(outs), receipts: outs.map((o) => o.receipt.body.id) };
}
