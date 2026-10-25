import { z } from "zod";

// A client's rulebook: the rules it sets at onboarding for what HELIOS may
// do on its estate, read by the response policy on every decision. It can
// only restrict what the plan and the client's AI consent allow, never widen
// it. Versioned and signed (lib/rulebook/service.ts); this file is the shape,
// shared by the policy engine and the editor so the two never disagree.
// Client-safe and pure.

export const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Severity = (typeof SEVERITIES)[number];

// The containment actions a rulebook governs. Rollbacks (release, unblock,
// re-enable, restore) undo containment and are never restricted.
export const RULED_ACTIONS = ["ISOLATE_HOST", "BLOCK_IP", "KILL_PROCESS", "QUARANTINE_FILE", "DISABLE_USER", "BLOCK_SENDER", "COLLECT_LOGS", "REVOKE_AGENT"] as const;
export type RuledAction = (typeof RULED_ACTIONS)[number];

export const ACTION_MODES = {
  auto: "Automatic",
  approve: "Needs approval",
  suggest: "Suggest only",
  never: "Never",
} as const;
export type ActionMode = keyof typeof ACTION_MODES;

export const MATCHER_KINDS = {
  hostname: "Hostname",
  ip: "IP address",
  assetGroup: "Asset group",
  assetType: "Asset type",
  criticality: "Criticality",
} as const;

export const OUT_OF_HOURS = {
  same: "Same as business hours",
  approve: "Automatic actions need approval",
  suggest: "Suggest only",
} as const;

export const WINDOW_EFFECTS = {
  approve: "Automatic actions need approval",
  suggest: "Suggest only",
} as const;

export const APPROVER_CHANNELS = { app: "HELIOS app", email: "Email", phone: "Phone", slack: "Slack", teams: "Microsoft Teams" } as const;
export const ON_TIMEOUT = { hold: "Keep holding (nothing runs)", suggest: "Downgrade to a suggestion" } as const;

export const AI_RESIDENCY = {
  any: "Any approved cloud model",
  region: "Region-locked cloud model",
  onprem: "On-premises models only",
} as const;

const key = <T extends Record<string, string>>(o: T) => Object.keys(o) as [keyof T & string, ...(keyof T & string)[]];
const text = (max: number) => z.string().trim().max(max);
const hhmm = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, "Use HH:MM");

export function validTimeZone(tz: string) {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

// Hostnames and accounts match case-insensitively; * is a wildcard.
export const matcherSchema = z.object({
  kind: z.enum(key(MATCHER_KINDS)),
  value: text(200).min(1),
  note: text(200).default(""),
});
export type Matcher = z.infer<typeof matcherSchema>;

const pattern = text(200).min(1);

export const windowSchema = z
  .object({
    label: text(120).min(1),
    start: z.iso.datetime({ offset: true }),
    end: z.iso.datetime({ offset: true }),
    effect: z.enum(key(WINDOW_EFFECTS)).default("approve"),
  })
  .refine((w) => Date.parse(w.end) > Date.parse(w.start), { message: "A window must end after it starts", path: ["end"] });
export type PolicyWindow = z.infer<typeof windowSchema>;

export const actionRuleSchema = z.object({
  mode: z.enum(key(ACTION_MODES)),
  // With mode "auto": below this case severity the action needs approval.
  autoFrom: z.enum(SEVERITIES).default("HIGH"),
});
export type ActionRule = z.infer<typeof actionRuleSchema>;

export const approverSchema = z.object({
  name: text(120).min(1),
  contact: text(200).min(1),
  channel: z.enum(key(APPROVER_CHANNELS)),
  timeoutMinutes: z.number().int().min(1).max(24 * 60).default(15),
});
export type Approver = z.infer<typeof approverSchema>;

const DEFAULT_ACTIONS: Record<RuledAction, ActionRule> = {
  ISOLATE_HOST: { mode: "approve", autoFrom: "HIGH" },
  BLOCK_IP: { mode: "approve", autoFrom: "HIGH" },
  KILL_PROCESS: { mode: "approve", autoFrom: "HIGH" },
  QUARANTINE_FILE: { mode: "approve", autoFrom: "HIGH" },
  DISABLE_USER: { mode: "approve", autoFrom: "CRITICAL" },
  BLOCK_SENDER: { mode: "approve", autoFrom: "HIGH" },
  COLLECT_LOGS: { mode: "approve", autoFrom: "MEDIUM" },
  REVOKE_AGENT: { mode: "approve", autoFrom: "HIGH" },
};

export const rulebookSchema = z.object({
  assets: z
    .object({
      // Tier 1: any containment on these needs a human, whatever else allows.
      crownJewels: z.array(matcherSchema).max(200).default([]),
      // HELIOS never isolates these, not even when an analyst asks.
      neverIsolate: z.array(matcherSchema).max(200).default([]),
    })
    .default({ crownJewels: [], neverIsolate: [] }),
  identities: z
    .object({
      // Approval only; never disabled automatically.
      vip: z.array(pattern).max(200).default([]),
      // Never disabled through HELIOS.
      breakGlass: z.array(pattern).max(100).default([]),
      service: z.array(pattern).max(500).default([]),
    })
    .default({ vip: [], breakGlass: [], service: [] }),
  actions: z
    .object(Object.fromEntries(RULED_ACTIONS.map((a) => [a, actionRuleSchema.default(DEFAULT_ACTIONS[a])])) as Record<RuledAction, z.ZodDefault<typeof actionRuleSchema>>)
    .default(DEFAULT_ACTIONS),
  blastRadius: z
    .object({
      maxActionsPerHour: z.number().int().min(0).max(500).default(5),
      maxHostsIsolated: z.number().int().min(0).max(10_000).default(3),
      // These need two different people to approve, whoever asks.
      twoPerson: z.array(z.enum(RULED_ACTIONS)).default(["DISABLE_USER"]),
    })
    .default({ maxActionsPerHour: 5, maxHostsIsolated: 3, twoPerson: ["DISABLE_USER"] }),
  schedule: z
    .object({
      timeZone: text(64).refine(validTimeZone, "Unknown time zone").default("UTC"),
      businessDays: z.array(z.number().int().min(0).max(6)).max(7).default([1, 2, 3, 4, 5]),
      businessStart: hhmm.default("09:00"),
      businessEnd: hhmm.default("18:00"),
      outOfHours: z.enum(key(OUT_OF_HOURS)).default("same"),
      maintenance: z.array(windowSchema).max(100).default([]),
      freezes: z.array(windowSchema).max(100).default([]),
    })
    .default({ timeZone: "UTC", businessDays: [1, 2, 3, 4, 5], businessStart: "09:00", businessEnd: "18:00", outOfHours: "same", maintenance: [], freezes: [] }),
  approvers: z
    .object({
      chain: z.array(approverSchema).max(10).default([]),
      onTimeout: z.enum(key(ON_TIMEOUT)).default("hold"),
    })
    .default({ chain: [], onTimeout: "hold" }),
  dataHandling: z
    .object({
      residency: z.enum(key(AI_RESIDENCY)).default("any"),
      // With "region": provider regions allowed (e.g. "india", "eu").
      regions: z.array(text(40).min(1)).max(20).default([]),
      // AI providers this client allows; empty = any provider HELIOS offers.
      allowedProviders: z.array(text(40).min(1)).max(50).default([]),
      redactPii: z.boolean().default(true),
      allowUserChoice: z.boolean().default(false),
    })
    .default({ residency: "any", regions: [], allowedProviders: [], redactPii: true, allowUserChoice: false }),
  obligations: z
    .object({
      regulatedEntity: z.boolean().default(false),
      certInContact: z.object({ name: text(120), email: text(200), phone: text(40) }).default({ name: "", email: "", phone: "" }),
      reportRecipients: z.array(z.email()).max(20).default([]),
    })
    .default({ regulatedEntity: false, certInContact: { name: "", email: "", phone: "" }, reportRecipients: [] }),
  reviewEveryDays: z.number().int().min(7).max(365).default(90),
});
export type Rulebook = z.infer<typeof rulebookSchema>;

export const EMPTY_RULEBOOK: Rulebook = rulebookSchema.parse({});

// Stable JSON (sorted keys) so the same rulebook always hashes the same.
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value as Record<string, unknown>)
      .sort()
      .filter((k) => (value as Record<string, unknown>)[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export const RULED_ACTION_LABEL: Record<RuledAction, string> = {
  ISOLATE_HOST: "Isolate host",
  BLOCK_IP: "Block IP",
  KILL_PROCESS: "Kill process",
  QUARANTINE_FILE: "Quarantine file",
  DISABLE_USER: "Disable account",
  BLOCK_SENDER: "Block sender",
  COLLECT_LOGS: "Collect logs",
  REVOKE_AGENT: "Revoke AI agent",
};

export function isRuledAction(a: string): a is RuledAction {
  return (RULED_ACTIONS as readonly string[]).includes(a);
}
