import { describe, expect, it } from "vitest";

import { approvalBlock, fullyApproved, profileWidening, rejectBlock, settingsWidening, sidesFor, type Approver, type ChangeState } from "@/lib/changes/rules";
import { AI_INITIAL_CONTAINMENT, decideResponse, type PolicyInput } from "@/lib/response/policy";

const change = (over: Partial<ChangeState> = {}): ChangeState => ({
  kind: "ALLOWLIST_ADD",
  tenantId: "t1",
  status: "PENDING",
  requestedById: "staff-a",
  clientApprovedAt: null,
  clientApprovedById: null,
  clientOnBehalf: false,
  heliosApprovedAt: null,
  heliosApprovedById: null,
  ...over,
});
const staff = (id: string, role: Approver["role"] = "SOC_MANAGER"): Approver => ({ id, role, isClient: false, tenantId: null });
const clientAdmin = (id = "ca", tenantId = "t1"): Approver => ({ id, role: "CLIENT_ADMIN", isClient: true, tenantId });

describe("who approves a rule change", () => {
  it("needs the client and HELIOS for a client's rules, a second HELIOS approver for the platform's", () => {
    expect(sidesFor("RULEBOOK_VERSION")).toEqual(["client", "helios"]);
    expect(sidesFor("ALLOWLIST_REMOVE")).toEqual(["client", "helios"]);
    expect(sidesFor("AUTONOMY_RAISE")).toEqual(["client", "helios"]);
    expect(sidesFor("AI_SETTINGS")).toEqual(["helios"]);
    expect(sidesFor("AGENT_PROFILE")).toEqual(["helios"]);
    expect(fullyApproved({ kind: "AI_CONSENT", clientApprovedAt: new Date(), heliosApprovedAt: null })).toBe(false);
    expect(fullyApproved({ kind: "AI_CONSENT", clientApprovedAt: new Date(), heliosApprovedAt: new Date() })).toBe(true);
    expect(fullyApproved({ kind: "AI_SETTINGS", clientApprovedAt: null, heliosApprovedAt: new Date() })).toBe(true);
  });

  it("lets nobody give HELIOS's approval to their own request", () => {
    expect(approvalBlock(change(), "helios", staff("staff-a"))).toMatch(/other than the requester/);
    expect(approvalBlock(change(), "helios", staff("staff-b"))).toBeNull();
    expect(approvalBlock(change({ kind: "AI_SETTINGS", tenantId: null }), "helios", staff("staff-a", "ADMIN"))).toMatch(/other than the requester/);
  });

  it("keeps the client's side to the client's admins, or staff recording its instruction", () => {
    expect(approvalBlock(change(), "client", clientAdmin())).toBeNull();
    expect(approvalBlock(change(), "client", clientAdmin("ca2", "t2"))).toMatch(/Not your organisation/);
    expect(approvalBlock(change(), "client", { id: "cv", role: "CLIENT_VIEWER", isClient: true, tenantId: "t1" })).toMatch(/client's admins/);
    expect(approvalBlock(change(), "client", staff("staff-b"))).toBeNull();
    expect(approvalBlock(change(), "client", staff("an", "ANALYST"))).toMatch(/can't record/);
    expect(approvalBlock(change(), "helios", clientAdmin())).toMatch(/Only HELIOS approvers/);
  });

  it("needs two different people when staff stand in for the client", () => {
    // B recorded the client's approval: B can't also approve for HELIOS.
    expect(approvalBlock(change({ clientApprovedAt: new Date(), clientApprovedById: "staff-b", clientOnBehalf: true }), "helios", staff("staff-b"))).toMatch(/recorded the client's approval/);
    // B approved for HELIOS: B can't then record the client's approval.
    expect(approvalBlock(change({ heliosApprovedAt: new Date(), heliosApprovedById: "staff-b" }), "client", staff("staff-b"))).toMatch(/gave HELIOS's approval/);
    expect(approvalBlock(change({ heliosApprovedAt: new Date(), heliosApprovedById: "staff-b" }), "client", staff("staff-c"))).toBeNull();
  });

  it("decides each side once, only while waiting, and only for active people", () => {
    expect(approvalBlock(change({ clientApprovedAt: new Date() }), "client", clientAdmin())).toMatch(/already approved/);
    expect(approvalBlock(change({ status: "APPLIED" }), "helios", staff("staff-b"))).toMatch(/isn't waiting/);
    expect(approvalBlock(change(), "helios", { ...staff("staff-b"), active: false })).toMatch(/inactive/);
    expect(approvalBlock(change({ kind: "AI_SETTINGS", tenantId: null }), "client", clientAdmin())).toMatch(/doesn't need/);
    expect(approvalBlock(change({ kind: "AI_SETTINGS", tenantId: null }), "helios", staff("an", "ANALYST"))).toMatch(/can't approve/);
    expect(rejectBlock(change(), staff("an", "ANALYST"))).toMatch(/can't decide/);
    expect(rejectBlock(change(), clientAdmin())).toBeNull();
    expect(rejectBlock(change({ status: "REJECTED" }), clientAdmin())).toMatch(/isn't waiting/);
  });
});

describe("what gives the AI more room", () => {
  const base = { enabled: true, autonomy: "CONTAIN_WITH_APPROVAL" as const, minConfidence: 0.8, allowedActions: ["BLOCK_IP" as const] };
  it("spots a wider containment agent", () => {
    expect(profileWidening(base, base)).toEqual([]);
    expect(profileWidening(base, { ...base, autonomy: "SUGGEST", minConfidence: 0.9, allowedActions: [] })).toEqual([]);
    expect(profileWidening(base, { ...base, autonomy: "AUTO_CONTAIN" })).toEqual(["autonomy CONTAIN_WITH_APPROVAL → AUTO_CONTAIN"]);
    expect(profileWidening(base, { ...base, minConfidence: 0.6 })).toEqual(["confidence bar 80% → 60%"]);
    expect(profileWidening(base, { ...base, allowedActions: ["BLOCK_IP", "ISOLATE_HOST"] })).toEqual(["pre-approves ISOLATE_HOST"]);
    expect(profileWidening({ ...base, enabled: false }, base)).toEqual(["turns the agent on"]);
  });

  it("spots wider platform limits, and lets narrower ones through", () => {
    const s = { killSwitch: true, firstResponse: false, minSeverity: "HIGH", maxAutoActionsPerHour: 5 };
    expect(settingsWidening(s, { ...s, killSwitch: false })).toEqual(["turns the kill switch off"]);
    expect(settingsWidening(s, { ...s, firstResponse: true, minSeverity: "MEDIUM", maxAutoActionsPerHour: 10 })).toHaveLength(3);
    expect(settingsWidening({ ...s, killSwitch: false }, { ...s, killSwitch: true, maxAutoActionsPerHour: 1, minSeverity: "CRITICAL" })).toEqual([]);
  });
});

describe("the AI's initial containment", () => {
  const input = (actionType: PolicyInput["actionType"]): PolicyInput => ({
    actionType,
    grounded: true,
    confidence: 0.95,
    killSwitch: false,
    autonomy: "AUTO_CONTAIN",
    allowedActions: ["ISOLATE_HOST", "BLOCK_IP", "QUARANTINE_FILE", "BLOCK_SENDER", "COLLECT_LOGS", "RESET_PASSWORD", "PURGE_EMAIL", "REVOKE_AGENT", "COLLECT_FORENSICS"],
    minConfidence: 0.8,
    tenantCap: "AUTO_CONTAIN",
    autoActionsLastHour: 0,
    maxAutoActionsPerHour: 10,
  });

  it("runs the first, reversible steps on its own when every rule allows", () => {
    for (const a of AI_INITIAL_CONTAINMENT) expect(decideResponse(input(a)).status).toBe("EXECUTED");
  });

  it("leaves everything past them to a person, whatever the rules allow", () => {
    for (const a of ["RESET_PASSWORD", "PURGE_EMAIL", "REVOKE_AGENT", "COLLECT_FORENSICS"] as const) {
      const d = decideResponse(input(a));
      expect(d.status).toBe("PENDING_APPROVAL");
      expect(d.trace[0].rule).toBe("agent.initialContainment");
    }
    expect(decideResponse(input("DISABLE_USER")).trace[0].rule).toBe("agent.alwaysHuman");
  });

  it("stops on a tampered rulebook", () => {
    const d = decideResponse({ ...input("BLOCK_IP"), rulebook: { version: 3, hash: "h", hits: [{ rule: "rulebook.integrity", outcome: "PENDING_APPROVAL", reason: "doesn't match", hard: false }] } });
    expect(d.status).toBe("PENDING_APPROVAL");
    expect(d.trace[0].rule).toBe("rulebook.integrity");
  });
});
