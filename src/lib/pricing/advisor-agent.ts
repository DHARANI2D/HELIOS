import { z } from "zod";

import { db } from "@/lib/db";
import { resolveAgent } from "@/lib/ai/resolve";
import { usageColumns } from "@/lib/ai/provider";
import { getCategory, toolLabel } from "@/lib/integrations/catalog";
import { formatMoney, normalizeConfig, toolMonthlyPrice, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";
import { ADVISOR_GOALS, adviseStack, type Advice, type AdvisorGoal } from "@/lib/pricing/advisor";
import { describeMix, mixMobile } from "@/lib/pricing/endpoint-mix";
import { choiceLabel, controlShort, stackTool } from "@/lib/pricing/upgrades";
import { surfaceCoverage } from "@/lib/assets/coverage";
import { COMPANY_TYPES, ENVIRONMENTS, INDUSTRIES, MATURITY } from "@/lib/assets/estate";

// The AI stack advisor. The rules (advisor.ts) score and price every catalog
// tool for the client first; the model then picks one per layer from those
// candidates, weighing what the catalog can't express (vendor maturity,
// licence bundles, how the tools fit together), and explains the choice.
// A pick that isn't one of the layer's candidates is discarded in favour of
// the rules' pick, and every price shown is recalculated from the picks by
// the calculator, never taken from the model's text.

export const AdvisorOutputSchema = z.object({
  summary: z.string().describe("2-4 plain-language sentences on the suggested stack: what changes, why, and the main trade-off. Quote prices only exactly as given."),
  picks: z
    .array(
      z.object({
        layer: z.string().describe("The layer key, e.g. edr"),
        choice: z.string().describe('One candidate key listed for that layer, "keep" for the current choice, or "none"'),
        reason: z.string().describe("One sentence"),
      }),
    )
    .describe("One entry per layer"),
});

export type AdvisorAudience = "staff" | "public";

export interface AiAdvice {
  goal: AdvisorGoal;
  engine: string;
  model: string | null;
  isLocal: boolean;
  // rules: no model is configured (or it is off), the rules answered.
  status: "succeeded" | "fallback" | "rules";
  summary: string;
  // Layer → tool key, "byo" or "none", relative to the config sent.
  changes: Record<string, string>;
  reasons: Record<string, string>;
  // Layers where the model's pick wasn't a valid candidate.
  discarded: string[];
  error?: string;
}

function rulesSummary(advice: Advice, money: (n: number) => string) {
  const moved = advice.picks.filter((p) => p.change === "add" || p.change === "switch" || p.change === "drop");
  if (!moved.length) return `The current stack already fits the "${ADVISOR_GOALS[advice.goal].label}" goal; nothing to change.`;
  const verbs = moved.map((p) => (p.change === "drop" ? `drop ${p.label}` : `${p.change === "switch" ? "switch to" : "add"} ${p.tool ? toolLabel(p.tool) : p.label}`));
  const d = advice.delta.monthly;
  return `For "${ADVISOR_GOALS[advice.goal].label}": ${verbs.join("; ")}. The estimate changes by ${d >= 0 ? "+" : "−"}${money(Math.abs(d))} per month${advice.delta.gapsClosed.length ? ` and closes ${advice.delta.gapsClosed.map(controlShort).join(", ")}` : ""}.`;
}

function renderFacts(cfg: QuoteConfig, ctx: PricingContext, advice: Advice, money: (n: number) => string) {
  const surface = surfaceCoverage(advice.config, ctx);
  const mix = cfg.profile.mix;
  const plan = ctx.plans.find((p) => p.key === cfg.plan);
  const lines = [
    "<client>",
    `Computers and servers: ${(cfg.profile.workstations + cfg.profile.servers).toLocaleString("en-US")}${mix ? ` (${describeMix({ ...mix, ios: 0, android: 0 })})` : " (operating systems not given)"}`,
    mix && mixMobile(mix) ? `Phones and tablets: ${mixMobile(mix)} (${describeMix({ ...mix, windows: 0, macos: 0, linux: 0, windowsServer: 0, linuxServer: 0, other: 0 })})` : null,
    `Users / mailboxes: ${cfg.profile.users.toLocaleString("en-US")}`,
    `Logs: ${cfg.profile.logGbPerDay} GB/day`,
    `Service plan: ${plan ? `${plan.name} (${plan.coverage})` : "not chosen"}`,
    `Goal: ${ADVISOR_GOALS[advice.goal].label}: ${ADVISOR_GOALS[advice.goal].description}`,
    `Organization: ${[cfg.context.companyType && COMPANY_TYPES[cfg.context.companyType], INDUSTRIES[cfg.context.industry], cfg.context.environment && ENVIRONMENTS[cfg.context.environment], cfg.context.maturity && MATURITY[cfg.context.maturity]].filter(Boolean).join("; ")}`,
    "Attack surface (asset group, priority, what they have, open gaps after the rules' picks):",
    ...surface.classes.map((c) => `- ${c.info.label} [${c.priority}${c.reasons.length ? `: ${c.reasons.join("; ")}` : ""}]: ${c.describe}; gaps: ${c.gaps.map(controlShort).join(", ") || "none"}`),
    `Prices are per month in ${cfg.commercial.currency}.`,
    "</client>",
    "<layers>",
  ].filter(Boolean) as string[];
  for (const p of advice.picks) {
    const category = getCategory(p.category)!;
    const { tool: current, source } = stackTool(cfg, ctx, p.category);
    const currentText =
      p.current === "none" ? "nothing" : p.current === "byo" ? (current ? `the client's own ${toolLabel(current)} (licensed separately)` : "the client's own tool (not named)") : choiceLabel(ctx, p.current);
    lines.push(`## ${p.category}: ${category.label}. ${category.description}`);
    const currentPrice = current ? toolMonthlyPrice(current, cfg).monthly : null;
    lines.push(`Current: ${currentText}${currentPrice != null ? ` (${money(currentPrice)}/month${source === "existing" ? " at catalog price" : ""})` : ""}`);
    lines.push(`Rules suggest: ${p.choice === p.current ? "keep" : p.choice} (${p.reasons.join("; ")})`);
    lines.push("Candidates:");
    for (const c of p.candidates) {
      const fit = c.fit ? (c.fit.agentless ? "no endpoint agent" : c.fit.unsupported.length ? `does NOT run on ${c.fit.unsupported.map((u) => `${u.count} ${u.label}`).join(", ")}` : "runs on all devices in scope") : "not endpoint-based";
      lines.push(
        `- ${c.key}: ${c.label} | provides ${c.adds.length ? c.adds.map(controlShort).join(", ") : "nothing new for this goal"} | ${fit} | alerts to SOC: ${c.alerts ? "yes" : "no"}, response actions: ${c.actions} | ${c.monthly == null ? "price on request" : money(c.monthly)}/month | ${c.deployment}${c.offlineCapable ? ", works offline" : ""}`,
      );
    }
  }
  lines.push("</layers>");
  return lines.join("\n");
}

const SYSTEM = (audience: AdvisorAudience) =>
  [
    "You advise on the security tool stack for a small or mid-sized organization that is buying a managed detection and response service from an MSSP. The SOC watches every tool that sends alerts and carries out response actions through the tools that support them.",
    audience === "public"
      ? "You are talking to a prospective client on the MSSP's website. Address them as \"you\"; be clear and neutral, never pushy."
      : "You are helping the MSSP's account manager prepare a proposal. Refer to the organization as \"the client\".",
    `Rules:
- Choose for every layer exactly one of: a candidate key listed under that layer, "keep" (the current choice), or "none".
- Base the choice on the facts given and your general knowledge of these products. Never choose a tool that doesn't run on devices the client has when a candidate that does exists.
- Don't pay twice for the same control: skip a layer whose controls the other picks already provide.
- Cover the client's whole attack surface in priority order (P1 groups first); the managed service already provides central log collection (SIEM) and automated response (SOAR).
- Respect the goal. Prefer keeping the current tool when an alternative is only marginally better: switching costs a migration.
- Mention prices only exactly as given, and never invent products, prices or features.`,
  ].join("\n\n");

export async function runAdvisorAgent(
  input: QuoteConfig,
  ctx: PricingContext,
  goal: AdvisorGoal,
  // rulesOnly: answer without a model (the website's AI budget is spent).
  opts: { audience: AdvisorAudience; trigger: "manual" | "website"; requestedById?: string | null; rulesOnly?: string },
): Promise<AiAdvice> {
  const cfg = normalizeConfig(input);
  const money = (n: number) => formatMoney(n, cfg.commercial.currency, cfg.commercial.fxRate, { decimals: Math.abs(n) >= 100 ? 0 : 2 });
  const advice = adviseStack(cfg, ctx, goal, opts.audience);
  const rulesReasons = Object.fromEntries(advice.picks.map((p) => [p.category, p.reasons.join(" · ")]));
  const rules: AiAdvice = { goal, engine: "built-in", model: null, isLocal: true, status: "rules", summary: rulesSummary(advice, money), changes: advice.changes, reasons: rulesReasons, discarded: [] };

  if (opts.rulesOnly) return { ...rules, summary: `${opts.rulesOnly} ${rules.summary}` };
  const { profile, provider } = await resolveAgent("advisor");
  if (!provider) return rules;

  const started = Date.now();
  try {
    const res = await provider.structured({
      schema: AdvisorOutputSchema,
      schemaName: "stack_advice",
      system: `${SYSTEM(opts.audience)}${profile.instructions?.trim() ? `\n\nAdditional instructions from the MSSP:\n${profile.instructions.trim()}` : ""}`,
      user: renderFacts(cfg, ctx, advice, money),
      effort: profile.effort,
    });
    const changes: Record<string, string> = {};
    const reasons: Record<string, string> = { ...rulesReasons };
    const discarded: string[] = [];
    for (const p of advice.picks) {
      const pick = res.data.picks.find((x) => x.layer.trim().toLowerCase() === p.category);
      const raw = pick?.choice.trim();
      let choice: string;
      if (!raw) choice = p.choice;
      else if (raw === "keep") choice = p.current;
      else if (raw === "none") choice = "none";
      else if (p.candidates.some((c) => c.key === raw)) choice = raw;
      else {
        discarded.push(p.category);
        choice = p.choice;
      }
      if (choice !== p.current) changes[p.category] = choice;
      if (pick?.reason && !discarded.includes(p.category)) reasons[p.category] = pick.reason.slice(0, 400);
    }
    const out: AiAdvice = { goal, engine: provider.name, model: res.model, isLocal: provider.isLocal, status: "succeeded", summary: res.data.summary.slice(0, 1500), changes, reasons, discarded };
    await logRun(out, opts, Date.now() - started, res.usage);
    return out;
  } catch (err) {
    const out: AiAdvice = { ...rules, status: "fallback", error: `${provider.name}: ${err instanceof Error ? err.message : String(err)}`.slice(0, 500) };
    await logRun({ ...out, engine: provider.name, model: provider.model, isLocal: provider.isLocal }, opts, Date.now() - started, {});
    return out;
  }
}

async function logRun(a: AiAdvice, opts: { trigger: string; requestedById?: string | null }, durationMs: number, usage: { inputTokens?: number; outputTokens?: number }) {
  await db.aiRun
    .create({
      data: {
        agentKey: "advisor",
        trigger: opts.trigger,
        engine: a.engine,
        model: a.model,
        isLocal: a.isLocal,
        status: a.status,
        output: { goal: a.goal, changes: a.changes, summary: a.summary, discarded: a.discarded },
        error: a.error ?? null,
        durationMs,
        ...usageColumns(usage),
        requestedById: opts.requestedById ?? null,
      },
    })
    .catch((err) => console.error("[advisor] couldn't log the run", err));
}
