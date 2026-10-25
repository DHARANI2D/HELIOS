import type { ResponseAction } from "@prisma/client";

import { db } from "@/lib/db";
import { aiSettings } from "@/lib/settings";
import { endpointClass } from "@/lib/assets/inventory";
import { loadProfile } from "@/lib/ai/resolve";
import { decideResponse, type PolicyInput } from "@/lib/response/policy";
import { RULED_ACTIONS, type RuledAction, type Rulebook, type Severity } from "@/lib/rulebook/schema";
import { matchesAsset, matchesIdentity, rulebookHits, type AssetFacts, type Outcome } from "@/lib/rulebook/evaluate";
import { allowlistMatch } from "@/lib/rulebook/service";

// A draft rulebook tried out before anyone signs it:
//   history — the client's last 30 days of AI containment proposals,
//     decided again under the draft (what would have run, been held or only
//     suggested, against what happened then);
//   probes — what the draft does with a confident proposal of each action at
//     each severity, right now;
//   coverage — which of the client's real assets and accounts its
//     protections catch.

export interface DryRunChange {
  id: string;
  caseId: string;
  caseTitle: string;
  action: string;
  target: string | null;
  severity: Severity;
  at: string;
  then: Outcome;
  now: Outcome;
  reason: string;
}

export interface DryRunResult {
  days: number;
  total: number;
  then: Record<Outcome, number>;
  now: Record<Outcome, number>;
  changes: DryRunChange[];
  probes: Array<{ action: RuledAction; outcomes: Array<{ severity: Severity; outcome: Outcome; reason: string }> }>;
  assets: { total: number; neverIsolate: string[]; crownJewels: string[] };
  accounts: { seen: number; protected: string[]; vip: string[] };
}

// What the policy decided at the time. Decisions made since the trace was
// recorded say so; older ones are read from how they ended.
function outcomeThen(a: Pick<ResponseAction, "status" | "trace" | "decidedById">): Outcome {
  const trace = Array.isArray(a.trace) ? (a.trace as Array<{ outcome?: string }>) : [];
  if (trace[0]?.outcome) return trace[0].outcome as Outcome;
  if (a.status === "BLOCKED" || a.status === "SUGGESTED") return a.status;
  if (a.status === "PENDING_APPROVAL" || a.status === "REJECTED") return "PENDING_APPROVAL";
  return a.decidedById ? "PENDING_APPROVAL" : "EXECUTED";
}

const empty = (): Record<Outcome, number> => ({ BLOCKED: 0, SUGGESTED: 0, PENDING_APPROVAL: 0, EXECUTED: 0 });

export async function dryRunRulebook(tenantId: string, draft: Rulebook, now = new Date(), days = 30): Promise<DryRunResult> {
  const since = new Date(now.getTime() - days * 86_400_000);
  const [tenant, settings, controller, actions, endpoints, users] = await Promise.all([
    db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { aiAutonomyCap: true, plan: { select: { defaultAutonomyCap: true } } } }),
    aiSettings(),
    loadProfile("containment"),
    db.responseAction.findMany({ where: { tenantId, source: "ai", createdAt: { gte: since } }, include: { case: { select: { title: true, severity: true } } }, orderBy: { createdAt: "asc" }, take: 2000 }),
    db.endpoint.findMany({ where: { tenantId }, select: { hostname: true, ipAddress: true, assetClass: true, assetType: true, criticality: true, os: true }, take: 5000 }),
    db.securityEvent.findMany({ where: { tenantId, userName: { not: null }, timestamp: { gte: since } }, distinct: ["userName"], select: { userName: true }, take: 1000 }),
  ]);

  const facts = (e: (typeof endpoints)[number]): AssetFacts => ({ hostname: e.hostname, ip: e.ipAddress, assetGroup: endpointClass(e), assetType: e.assetType, criticality: e.criticality });
  const byHost = new Map(endpoints.map((e) => [e.hostname.toLowerCase(), facts(e)]));
  const byIp = new Map(endpoints.filter((e) => e.ipAddress).map((e) => [e.ipAddress!, facts(e)]));
  const assetOf = (action: string, target: string | null): AssetFacts | null => {
    if (!target) return null;
    if (action === "BLOCK_IP") return byIp.get(target) ?? { ip: target };
    if (action === "ISOLATE_HOST" || action === "COLLECT_LOGS") return byHost.get(target.toLowerCase()) ?? { hostname: target };
    return null;
  };

  const base: Omit<PolicyInput, "actionType" | "grounded" | "confidence" | "rulebook" | "endpointCriticality" | "autoActionsLastHour"> = {
    killSwitch: false,
    autonomy: controller.enabled ? controller.autonomy : "SUGGEST",
    allowedActions: controller.allowedActions,
    minConfidence: controller.minConfidence,
    planCap: tenant.plan?.defaultAutonomyCap,
    tenantCap: tenant.aiAutonomyCap,
    maxAutoActionsPerHour: settings.maxAutoActionsPerHour,
  };

  const then = empty();
  const after = empty();
  const changes: DryRunChange[] = [];
  const executedAt: number[] = [];
  for (const a of actions) {
    const at = a.createdAt.getTime();
    const lastHour = executedAt.filter((t) => t > at - 3_600_000).length;
    const asset = assetOf(a.actionType, a.target);
    const allowlisted = await allowlistMatch(tenantId, a.actionType, a.target, a.createdAt);
    const hits = rulebookHits(draft, { actionType: a.actionType, target: a.target, severity: a.case.severity, now: a.createdAt, asset, allowlisted, aiActionsLastHour: lastHour, hostsIsolated: 0 });
    const grounded = !(a.status === "BLOCKED" && /evidence/i.test(a.policyReason ?? ""));
    const decision = decideResponse({ ...base, actionType: a.actionType, grounded, confidence: a.confidence ?? 0, endpointCriticality: asset?.criticality, autoActionsLastHour: lastHour, rulebook: { version: 0, hash: "draft", hits } });
    const was = outcomeThen(a);
    then[was]++;
    after[decision.status]++;
    if (decision.status === "EXECUTED") executedAt.push(at);
    if (was !== decision.status) {
      changes.push({ id: a.id, caseId: a.caseId, caseTitle: a.case.title, action: a.actionType, target: a.target, severity: a.case.severity, at: a.createdAt.toISOString(), then: was, now: decision.status, reason: decision.reason.replace(" (rulebook v0)", "") });
    }
  }

  const severities: Severity[] = ["MEDIUM", "HIGH", "CRITICAL"];
  const probes = RULED_ACTIONS.map((action) => ({
    action,
    outcomes: severities.map((severity) => {
      const hits = rulebookHits(draft, { actionType: action, target: null, severity, now, asset: null, allowlisted: null, aiActionsLastHour: 0, hostsIsolated: 0 });
      const d = decideResponse({ ...base, actionType: action, grounded: true, confidence: 0.95, autoActionsLastHour: 0, rulebook: { version: 0, hash: "draft", hits } });
      return { severity, outcome: d.status, reason: d.reason.replace(" (rulebook v0)", "") };
    }),
  }));

  const names = (list: typeof endpoints) => list.map((e) => e.hostname);
  const accounts = users.map((u) => u.userName!).filter(Boolean);
  return {
    days,
    total: actions.length,
    then,
    now: after,
    changes: changes.slice(-100),
    probes,
    assets: {
      total: endpoints.length,
      neverIsolate: names(endpoints.filter((e) => draft.assets.neverIsolate.some((m) => matchesAsset(m, facts(e), e.hostname)))),
      crownJewels: names(endpoints.filter((e) => draft.assets.crownJewels.some((m) => matchesAsset(m, facts(e), e.hostname)))),
    },
    accounts: {
      seen: accounts.length,
      protected: accounts.filter((u) => [...draft.identities.breakGlass, ...draft.identities.service].some((p) => matchesIdentity(p, u))),
      vip: accounts.filter((u) => draft.identities.vip.some((p) => matchesIdentity(p, u))),
    },
  };
}
