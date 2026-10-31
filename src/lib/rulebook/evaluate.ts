import { RULED_ACTION_LABEL, SEVERITIES, isRuledAction, type Matcher, type PolicyWindow, type Rulebook, type Severity } from "@/lib/rulebook/schema";

// What a client's rulebook says about one proposed action. Pure: the caller
// looks up the asset, the allowlist and the counters, and this returns every
// rule that restricts the action. The response policy takes the most
// restrictive outcome. Hard rules bind people too (a never-isolate asset
// stays connected whoever asks); the rest only restrict automation.

export const OUTCOMES = ["BLOCKED", "SUGGESTED", "PENDING_APPROVAL", "EXECUTED"] as const;
export type Outcome = (typeof OUTCOMES)[number];
export const OUTCOME_RANK: Record<Outcome, number> = { BLOCKED: 0, SUGGESTED: 1, PENDING_APPROVAL: 2, EXECUTED: 3 };

export interface AssetFacts {
  hostname?: string | null;
  ip?: string | null;
  assetGroup?: string | null;
  assetType?: string | null;
  criticality?: string | null;
}

export interface AllowlistFact {
  kind: string;
  value: string;
  reason: string;
  owner: string;
  expiresAt: Date | null;
}

export interface RuleContext {
  actionType: string;
  target: string | null;
  severity: Severity;
  now: Date;
  asset?: AssetFacts | null;
  allowlisted?: AllowlistFact | null;
  aiActionsLastHour: number;
  hostsIsolated: number;
}

export interface RuleHit {
  rule: string;
  outcome: Outcome;
  reason: string;
  // Binds analysts as well as AI agents.
  hard: boolean;
  // Approvals needed before it runs (the two-person rule).
  approvals?: number;
}

function wildcard(pattern: string) {
  const re = pattern.trim().replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${re}$`, "i");
}

export function matchesPattern(pattern: string, value: string | null | undefined) {
  return !!value && wildcard(pattern).test(value.trim());
}

// A user target can be "DOMAIN\\user", "user@domain" or "user": a pattern
// matches any of those spellings.
function identityForms(user: string) {
  const v = user.trim();
  const bare = v.includes("\\") ? v.split("\\").pop()! : v;
  const local = bare.includes("@") ? bare.split("@")[0] : bare;
  return [...new Set([v, bare, local])];
}

export function matchesIdentity(pattern: string, user: string | null | undefined) {
  return !!user && identityForms(user).some((form) => matchesPattern(pattern, form));
}

export function matchesAsset(m: Matcher, asset: AssetFacts | null | undefined, target: string | null) {
  switch (m.kind) {
    case "hostname":
      return matchesPattern(m.value, asset?.hostname ?? target);
    case "ip":
      return matchesPattern(m.value, asset?.ip ?? target);
    case "assetGroup":
      return !!asset?.assetGroup && asset.assetGroup.toLowerCase() === m.value.toLowerCase();
    case "assetType":
      return !!asset?.assetType && asset.assetType.toLowerCase() === m.value.toLowerCase();
    case "criticality":
      return !!asset?.criticality && asset.criticality.toLowerCase() === m.value.toLowerCase();
  }
}

const HOST_ACTIONS = new Set(["ISOLATE_HOST", "COLLECT_LOGS"]);
const IP_ACTIONS = new Set(["BLOCK_IP"]);

// Weekday (0 = Sunday) and minutes past midnight in the client's time zone.
export function localClock(now: Date, timeZone: string) {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(now);
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
  const weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(get("weekday"));
  return { weekday, minutes: Number(get("hour")) * 60 + Number(get("minute")) };
}

const toMinutes = (hhmm: string) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5));

export function inBusinessHours(rb: Rulebook, now: Date) {
  const { weekday, minutes } = localClock(now, rb.schedule.timeZone);
  if (!rb.schedule.businessDays.includes(weekday)) return false;
  const start = toMinutes(rb.schedule.businessStart);
  const end = toMinutes(rb.schedule.businessEnd);
  return start <= end ? minutes >= start && minutes < end : minutes >= start || minutes < end;
}

export function activeWindow(windows: PolicyWindow[], now: Date) {
  const t = now.getTime();
  return windows.find((w) => Date.parse(w.start) <= t && t < Date.parse(w.end)) ?? null;
}

const severityAtLeast = (s: Severity, min: Severity) => SEVERITIES.indexOf(s) >= SEVERITIES.indexOf(min);
const label = (a: string) => (isRuledAction(a) ? RULED_ACTION_LABEL[a].toLowerCase() : a.toLowerCase().replaceAll("_", " "));

export function rulebookHits(rb: Rulebook, ctx: RuleContext): RuleHit[] {
  if (!isRuledAction(ctx.actionType)) return [];
  const a = ctx.actionType;
  const hits: RuleHit[] = [];

  const rule = rb.actions[a];
  if (rule.mode === "never") hits.push({ rule: `actions.${a}`, outcome: "BLOCKED", hard: true, reason: `The client's rulebook says HELIOS never does "${label(a)}"` });
  else if (rule.mode === "suggest") hits.push({ rule: `actions.${a}`, outcome: "SUGGESTED", hard: false, reason: `The client's rulebook allows "${label(a)}" as a suggestion only` });
  else if (rule.mode === "approve") hits.push({ rule: `actions.${a}`, outcome: "PENDING_APPROVAL", hard: false, reason: `The client's rulebook requires approval for "${label(a)}"` });
  else if (!severityAtLeast(ctx.severity, rule.autoFrom)) {
    hits.push({ rule: `actions.${a}.autoFrom`, outcome: "PENDING_APPROVAL", hard: false, reason: `The client allows automatic "${label(a)}" from ${rule.autoFrom.toLowerCase()} severity; this case is ${ctx.severity.toLowerCase()}` });
  }

  if (HOST_ACTIONS.has(a) || IP_ACTIONS.has(a)) {
    if (a === "ISOLATE_HOST") {
      const i = rb.assets.neverIsolate.findIndex((m) => matchesAsset(m, ctx.asset, ctx.target));
      if (i >= 0) {
        const m = rb.assets.neverIsolate[i];
        hits.push({ rule: `assets.neverIsolate[${i}]`, outcome: "BLOCKED", hard: true, reason: `${ctx.target} is on the client's never-isolate list (${m.note || `${m.kind} ${m.value}`})` });
      }
    }
    const j = rb.assets.crownJewels.findIndex((m) => matchesAsset(m, ctx.asset, ctx.target));
    if (j >= 0) {
      const m = rb.assets.crownJewels[j];
      hits.push({ rule: `assets.crownJewels[${j}]`, outcome: "PENDING_APPROVAL", hard: false, reason: `${ctx.target} is a tier-1 asset for this client (${m.note || `${m.kind} ${m.value}`}); a human decides` });
    }
  }

  // A password reset locks the account out just as surely as disabling it.
  if ((a === "DISABLE_USER" || a === "RESET_PASSWORD") && ctx.target) {
    const verb = a === "DISABLE_USER" ? "be disabled" : "have its password reset";
    const protectedBy = (["breakGlass", "service"] as const).flatMap((k) => rb.identities[k].map((p, i) => ({ k, p, i }))).find(({ p }) => matchesIdentity(p, ctx.target));
    if (protectedBy) {
      const what = protectedBy.k === "breakGlass" ? "break-glass account" : "service account";
      hits.push({ rule: `identities.${protectedBy.k}[${protectedBy.i}]`, outcome: "BLOCKED", hard: true, reason: `${ctx.target} is a ${what} the client says must never ${verb}` });
    }
    const vip = rb.identities.vip.findIndex((p) => matchesIdentity(p, ctx.target));
    if (vip >= 0) hits.push({ rule: `identities.vip[${vip}]`, outcome: "PENDING_APPROVAL", hard: false, reason: `${ctx.target} is a VIP account: approval only, never ${verb} automatically` });
  }

  if (ctx.allowlisted) {
    const l = ctx.allowlisted;
    hits.push({
      rule: "allowlist",
      outcome: "SUGGESTED",
      hard: false,
      reason: `${l.value} is on the client's allowlist (${l.reason}; owner ${l.owner}${l.expiresAt ? `, until ${l.expiresAt.toISOString().slice(0, 10)}` : ""})`,
    });
  }

  const freeze = activeWindow(rb.schedule.freezes, ctx.now);
  if (freeze) hits.push({ rule: "schedule.freezes", outcome: freeze.effect === "suggest" ? "SUGGESTED" : "PENDING_APPROVAL", hard: false, reason: `Change freeze in effect: ${freeze.label}` });
  const maintenance = activeWindow(rb.schedule.maintenance, ctx.now);
  if (maintenance) hits.push({ rule: "schedule.maintenance", outcome: maintenance.effect === "suggest" ? "SUGGESTED" : "PENDING_APPROVAL", hard: false, reason: `Maintenance window in progress: ${maintenance.label}` });
  if (rb.schedule.outOfHours !== "same" && !inBusinessHours(rb, ctx.now)) {
    hits.push({ rule: "schedule.outOfHours", outcome: rb.schedule.outOfHours === "suggest" ? "SUGGESTED" : "PENDING_APPROVAL", hard: false, reason: "Outside the client's business hours" });
  }

  if (ctx.aiActionsLastHour >= rb.blastRadius.maxActionsPerHour) {
    hits.push({ rule: "blastRadius.maxActionsPerHour", outcome: "PENDING_APPROVAL", hard: false, reason: `The client allows at most ${rb.blastRadius.maxActionsPerHour} automatic actions an hour` });
  }
  if (a === "ISOLATE_HOST" && ctx.hostsIsolated >= rb.blastRadius.maxHostsIsolated) {
    hits.push({ rule: "blastRadius.maxHostsIsolated", outcome: "PENDING_APPROVAL", hard: false, reason: `${ctx.hostsIsolated} hosts are already isolated; the client allows ${rb.blastRadius.maxHostsIsolated} at once without a human` });
  }
  if (rb.blastRadius.twoPerson.includes(a)) {
    hits.push({ rule: "blastRadius.twoPerson", outcome: "PENDING_APPROVAL", hard: true, approvals: 2, reason: `"${label(a)}" needs two people to approve for this client` });
  }
  return hits;
}

// The hard rules alone: what binds a person asking for an action.
export function humanGate(hits: RuleHit[]): { allowed: boolean; reason: string | null; approvals: number } {
  const blocked = hits.find((h) => h.hard && h.outcome === "BLOCKED");
  const approvals = Math.max(1, ...hits.filter((h) => h.hard).map((h) => h.approvals ?? 1));
  return { allowed: !blocked, reason: blocked?.reason ?? (approvals > 1 ? hits.find((h) => (h.approvals ?? 1) > 1)!.reason : null), approvals };
}
