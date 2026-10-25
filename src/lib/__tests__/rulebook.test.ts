import { describe, expect, it } from "vitest";
import fc from "fast-check";

import { EMPTY_RULEBOOK, RULED_ACTIONS, SEVERITIES, rulebookSchema, type Rulebook } from "@/lib/rulebook/schema";
import { OUTCOME_RANK, OUTCOMES, humanGate, inBusinessHours, matchesIdentity, rulebookHits, type RuleContext, type RuleHit } from "@/lib/rulebook/evaluate";
import { TEMPLATES, buildTemplate, templateFor, type TemplateKey } from "@/lib/rulebook/templates";
import { diffRulebooks } from "@/lib/rulebook/diff";
import { decideResponse, type PolicyInput } from "@/lib/response/policy";

const rb = (patch: Record<string, unknown>): Rulebook => rulebookSchema.parse(patch);
const ctx = (over: Partial<RuleContext> = {}): RuleContext => ({
  actionType: "ISOLATE_HOST",
  target: "WS-01",
  severity: "HIGH",
  now: new Date("2026-10-26T06:00:00Z"), // Monday 11:30 in India
  asset: { hostname: "WS-01", assetGroup: "user", assetType: "laptop", criticality: "standard" },
  allowlisted: null,
  aiActionsLastHour: 0,
  hostsIsolated: 0,
  ...over,
});
const auto = { actions: Object.fromEntries(RULED_ACTIONS.map((a) => [a, { mode: "auto", autoFrom: "LOW" }])), blastRadius: { twoPerson: [] }, schedule: { timeZone: "Asia/Kolkata" } };

describe("rulebook schema and templates", () => {
  it("fills every default and every template is valid", () => {
    expect(EMPTY_RULEBOOK.actions.ISOLATE_HOST.mode).toBe("approve");
    expect(EMPTY_RULEBOOK.blastRadius.twoPerson).toContain("DISABLE_USER");
    for (const key of Object.keys(TEMPLATES) as TemplateKey[]) expect(() => rulebookSchema.parse(buildTemplate(key))).not.toThrow();
    expect(buildTemplate("healthcare").assets.neverIsolate.some((m) => m.value === "medical")).toBe(true);
    expect(templateFor("energy")).toBe("manufacturing");
    expect(templateFor(null)).toBe("general");
  });

  it("rejects bad time zones, clock times and windows that end before they start", () => {
    expect(() => rb({ schedule: { timeZone: "Mars/Olympus" } })).toThrow();
    expect(() => rb({ schedule: { businessStart: "25:00" } })).toThrow();
    expect(() => rb({ schedule: { freezes: [{ label: "x", start: "2026-11-02T00:00:00Z", end: "2026-11-01T00:00:00Z" }] } })).toThrow();
  });
});

describe("rulebook rules", () => {
  it("applies the action matrix by mode and severity", () => {
    expect(rulebookHits(rb({ actions: { ISOLATE_HOST: { mode: "never" } } }), ctx())).toEqual([expect.objectContaining({ outcome: "BLOCKED", hard: true, rule: "actions.ISOLATE_HOST" })]);
    expect(rulebookHits(rb({ ...auto, actions: { ...auto.actions, BLOCK_IP: { mode: "auto", autoFrom: "CRITICAL" } } }), ctx({ actionType: "BLOCK_IP", target: "203.0.113.9", asset: { ip: "203.0.113.9" } }))[0]).toMatchObject({
      outcome: "PENDING_APPROVAL",
      rule: "actions.BLOCK_IP.autoFrom",
    });
    expect(rulebookHits(rb(auto), ctx())).toEqual([]);
    // Rollbacks are never restricted.
    expect(rulebookHits(rb({ actions: { ISOLATE_HOST: { mode: "never" } } }), ctx({ actionType: "RELEASE_HOST" }))).toEqual([]);
  });

  it("never isolates protected assets and holds tier-1 assets for a human", () => {
    const book = rb({ ...auto, assets: { neverIsolate: [{ kind: "hostname", value: "dc-*" }, { kind: "assetType", value: "medical" }], crownJewels: [{ kind: "assetGroup", value: "server" }] } });
    expect(rulebookHits(book, ctx({ target: "DC-01", asset: { hostname: "DC-01" } }))[0]).toMatchObject({ outcome: "BLOCKED", hard: true, rule: "assets.neverIsolate[0]" });
    expect(rulebookHits(book, ctx({ target: "MRI-3", asset: { hostname: "MRI-3", assetType: "medical" } }))[0]).toMatchObject({ outcome: "BLOCKED", rule: "assets.neverIsolate[1]" });
    expect(rulebookHits(book, ctx({ target: "SQL-1", asset: { hostname: "SQL-1", assetGroup: "server" } }))[0]).toMatchObject({ outcome: "PENDING_APPROVAL", hard: false, rule: "assets.crownJewels[0]" });
    // A never-isolate rule doesn't stop logs being collected.
    expect(rulebookHits(book, ctx({ actionType: "COLLECT_LOGS", target: "DC-01", asset: { hostname: "DC-01" } }))).toEqual([]);
  });

  it("protects break-glass, service and VIP accounts in any spelling", () => {
    const book = rb({ ...auto, identities: { breakGlass: ["break-glass*"], service: ["svc-*"], vip: ["ceo"] } });
    const disable = (target: string) => rulebookHits(book, ctx({ actionType: "DISABLE_USER", target, asset: null }));
    expect(disable("CORP\\break-glass1")[0]).toMatchObject({ outcome: "BLOCKED", hard: true });
    expect(disable("svc-backup@corp.example")[0]).toMatchObject({ outcome: "BLOCKED", rule: "identities.service[0]" });
    expect(disable("CEO@corp.example")[0]).toMatchObject({ outcome: "PENDING_APPROVAL", rule: "identities.vip[0]" });
    expect(disable("alice")).toEqual([]);
    expect(matchesIdentity("j*", "CORP\\jdoe")).toBe(true);
    expect(matchesIdentity("svc.*", "svcXbackup")).toBe(false);
  });

  it("turns allowlisted targets into suggestions", () => {
    const hits = rulebookHits(rb(auto), ctx({ actionType: "BLOCK_IP", target: "10.0.5.20", allowlisted: { kind: "ip", value: "10.0.5.20", reason: "Vulnerability scanner", owner: "IT", expiresAt: new Date("2027-03-31") } }));
    expect(hits[0]).toMatchObject({ outcome: "SUGGESTED", rule: "allowlist" });
    expect(hits[0].reason).toContain("Vulnerability scanner");
  });

  it("follows business hours, maintenance windows and change freezes in the client's time zone", () => {
    const book = rb({ ...auto, schedule: { timeZone: "Asia/Kolkata", outOfHours: "approve", freezes: [{ label: "Diwali sale", start: "2026-11-01T00:00:00+05:30", end: "2026-11-10T00:00:00+05:30", effect: "suggest" }] } });
    expect(inBusinessHours(book, new Date("2026-10-26T06:00:00Z"))).toBe(true); // Mon 11:30 IST
    expect(inBusinessHours(book, new Date("2026-10-26T13:00:00Z"))).toBe(false); // Mon 18:30 IST
    expect(inBusinessHours(book, new Date("2026-10-25T06:00:00Z"))).toBe(false); // Sunday
    expect(rulebookHits(book, ctx({ now: new Date("2026-10-26T13:00:00Z") }))[0]).toMatchObject({ outcome: "PENDING_APPROVAL", rule: "schedule.outOfHours" });
    expect(rulebookHits(book, ctx({ now: new Date("2026-11-03T06:00:00Z") }))[0]).toMatchObject({ outcome: "SUGGESTED", rule: "schedule.freezes" });
    const overnight = rb({ schedule: { businessStart: "22:00", businessEnd: "06:00", timeZone: "UTC", businessDays: [0, 1, 2, 3, 4, 5, 6] } });
    expect(inBusinessHours(overnight, new Date("2026-10-26T23:00:00Z"))).toBe(true);
    expect(inBusinessHours(overnight, new Date("2026-10-26T12:00:00Z"))).toBe(false);
  });

  it("limits the blast radius and asks for two people", () => {
    const book = rb({ ...auto, blastRadius: { maxActionsPerHour: 2, maxHostsIsolated: 3, twoPerson: ["ISOLATE_HOST"] } });
    const hits = rulebookHits(book, ctx({ aiActionsLastHour: 2, hostsIsolated: 3 }));
    expect(hits.map((h) => h.rule)).toEqual(["blastRadius.maxActionsPerHour", "blastRadius.maxHostsIsolated", "blastRadius.twoPerson"]);
    expect(humanGate(hits)).toMatchObject({ allowed: true, approvals: 2 });
    expect(humanGate(rulebookHits(rb({ actions: { ISOLATE_HOST: { mode: "never" } } }), ctx()))).toMatchObject({ allowed: false });
    // Soft rules don't bind people.
    expect(humanGate(rulebookHits(rb({ ...auto, blastRadius: { maxHostsIsolated: 0, twoPerson: [] } }), ctx()))).toMatchObject({ allowed: true, approvals: 1, reason: null });
  });
});

const BASE: PolicyInput = {
  actionType: "ISOLATE_HOST",
  grounded: true,
  confidence: 0.95,
  killSwitch: false,
  autonomy: "AUTO_CONTAIN",
  allowedActions: ["ISOLATE_HOST", "BLOCK_IP"],
  minConfidence: 0.8,
  planCap: "AUTO_CONTAIN",
  tenantCap: "AUTO_CONTAIN",
  endpointCriticality: "standard",
  autoActionsLastHour: 0,
  maxAutoActionsPerHour: 5,
};

describe("response policy with a rulebook", () => {
  it("names the deciding rule and the rulebook version", () => {
    const hits = rulebookHits(rb({ ...auto, assets: { neverIsolate: [{ kind: "hostname", value: "DC-01", note: "Domain controller" }] } }), ctx({ target: "DC-01", asset: { hostname: "DC-01" } }));
    const d = decideResponse({ ...BASE, killSwitch: true, rulebook: { version: 7, hash: "abc", hits } });
    expect(d.status).toBe("BLOCKED");
    expect(d.reason).toContain("never-isolate");
    expect(d.reason).toContain("rulebook v7");
    expect(d.trace[0]).toMatchObject({ layer: "rulebook", rule: "assets.neverIsolate[0]" });
    expect(d.trace.some((t) => t.layer === "kill_switch")).toBe(true);
    expect(d).toMatchObject({ policyVersion: 7, policyHash: "abc" });
  });

  it("caps by the plan before consent, and passes a clean action", () => {
    expect(decideResponse({ ...BASE, planCap: "SUGGEST" })).toMatchObject({ status: "SUGGESTED", reason: "The client's plan allows suggestions only", effectiveAutonomy: "SUGGEST" });
    expect(decideResponse({ ...BASE, planCap: "CONTAIN_WITH_APPROVAL", tenantCap: "CONTAIN_WITH_APPROVAL" }).trace[0].layer).toBe("plan");
    expect(decideResponse({ ...BASE, rulebook: { version: 1, hash: "h", hits: [] } })).toMatchObject({ status: "EXECUTED", trace: [], approvals: 1 });
    const twoPerson: RuleHit = { rule: "blastRadius.twoPerson", outcome: "PENDING_APPROVAL", hard: true, approvals: 2, reason: "two people" };
    expect(decideResponse({ ...BASE, rulebook: { version: 1, hash: "h", hits: [twoPerson] } })).toMatchObject({ status: "PENDING_APPROVAL", approvals: 2 });
  });

  // The roadmap's monotonicity guarantee: whatever a rulebook says, the
  // result is never more permissive than the same decision without it, nor
  // than the plan cap or the client's consent.
  const autonomy = fc.constantFrom("OFF", "SUGGEST", "CONTAIN_WITH_APPROVAL", "AUTO_CONTAIN") as fc.Arbitrary<PolicyInput["autonomy"]>;
  const hit = fc.record({ rule: fc.string(), outcome: fc.constantFrom(...OUTCOMES), reason: fc.string(), hard: fc.boolean(), approvals: fc.option(fc.constantFrom(1, 2), { nil: undefined }) });
  const input = fc.record({
    actionType: fc.constantFrom("ISOLATE_HOST", "BLOCK_IP", "DISABLE_USER", "KILL_PROCESS", "QUARANTINE_FILE") as fc.Arbitrary<PolicyInput["actionType"]>,
    grounded: fc.boolean(),
    confidence: fc.double({ min: 0, max: 1, noNaN: true }),
    killSwitch: fc.boolean(),
    autonomy,
    allowedActions: fc.subarray(["ISOLATE_HOST", "BLOCK_IP", "DISABLE_USER", "KILL_PROCESS", "QUARANTINE_FILE"] as PolicyInput["allowedActions"]),
    minConfidence: fc.double({ min: 0, max: 1, noNaN: true }),
    planCap: autonomy,
    tenantCap: autonomy,
    endpointCriticality: fc.constantFrom("standard", "high", "critical"),
    autoActionsLastHour: fc.nat(10),
    maxAutoActionsPerHour: fc.nat(10),
  });
  const capRank = (a: PolicyInput["autonomy"]) => (a === "AUTO_CONTAIN" ? 3 : a === "CONTAIN_WITH_APPROVAL" ? 2 : 1);

  it("no rulebook can make a decision more permissive", () => {
    fc.assert(
      fc.property(input, fc.array(hit, { maxLength: 6 }), (i, hits) => {
        const without = decideResponse(i);
        const withBook = decideResponse({ ...i, rulebook: { version: 1, hash: "h", hits } });
        expect(OUTCOME_RANK[withBook.status]).toBeLessThanOrEqual(OUTCOME_RANK[without.status]);
        expect(OUTCOME_RANK[withBook.status]).toBeLessThanOrEqual(capRank(i.planCap!));
        expect(OUTCOME_RANK[withBook.status]).toBeLessThanOrEqual(capRank(i.tenantCap));
        if (i.killSwitch) expect(OUTCOME_RANK[withBook.status]).toBeLessThanOrEqual(OUTCOME_RANK.SUGGESTED);
        if (!i.grounded) expect(withBook.status).toBe("BLOCKED");
        // The stated reason is the deciding rule's.
        if (withBook.trace.length) expect(withBook.trace[0].outcome).toBe(withBook.status);
      }),
      { numRuns: 500 },
    );
  });

  it("a real rulebook never widens the plan cap either", () => {
    const actionRule = fc.record({ mode: fc.constantFrom("auto", "approve", "suggest", "never"), autoFrom: fc.constantFrom(...SEVERITIES) });
    const book = fc.record({ actions: fc.record(Object.fromEntries(RULED_ACTIONS.map((a) => [a, actionRule])) as Record<string, typeof actionRule>), blastRadius: fc.record({ maxActionsPerHour: fc.nat(5), maxHostsIsolated: fc.nat(5), twoPerson: fc.subarray([...RULED_ACTIONS]) }) });
    fc.assert(
      fc.property(input, book, fc.constantFrom(...SEVERITIES), (i, b, severity) => {
        const hits = rulebookHits(rulebookSchema.parse(b), ctx({ actionType: i.actionType, severity }));
        const d = decideResponse({ ...i, rulebook: { version: 1, hash: "h", hits } });
        expect(OUTCOME_RANK[d.status]).toBeLessThanOrEqual(OUTCOME_RANK[decideResponse(i).status]);
      }),
      { numRuns: 300 },
    );
  });
});

describe("rulebook diff", () => {
  it("lists changed settings and added or removed items, ignoring order", () => {
    const a = rb({ assets: { neverIsolate: [{ kind: "hostname", value: "DC-01" }, { kind: "hostname", value: "DC-02" }] } });
    const b = rb({ assets: { neverIsolate: [{ kind: "hostname", value: "DC-02" }, { kind: "hostname", value: "DC-01" }, { kind: "assetType", value: "medical", note: "Medical" }] }, actions: { ISOLATE_HOST: { mode: "auto" } } });
    const lines = diffRulebooks(a, b);
    expect(lines).toContainEqual({ path: "actions.ISOLATE_HOST.mode", kind: "changed", before: "approve", after: "auto" });
    expect(lines).toContainEqual({ path: "assets.neverIsolate", kind: "added", after: "assetType medical (Medical)" });
    expect(lines.filter((l) => l.path === "assets.neverIsolate")).toHaveLength(1);
    expect(diffRulebooks(a, a)).toEqual([]);
  });
});
