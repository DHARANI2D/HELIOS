import { describe, expect, it } from "vitest";

import { CERT_IN_CATEGORIES, atLeast, classifyIncident, type IncidentFacts } from "@/lib/compliance/cert-in";
import { DPDP_RULE7_FROM, dpdpInForce } from "@/lib/compliance/dpdp";
import { certInEmail, clockOf, missingFields, noticeDue, parseContent, reminderStage } from "@/lib/compliance/notices";
import { rulebookSchema } from "@/lib/rulebook/schema";

const base: IncidentFacts = { sourceType: "SIEM_ALERT", domain: "ENDPOINT", severity: "HIGH", verdict: null, techniques: [], detectionSources: [], titles: [], assets: [] };
const codes = (f: Partial<IncidentFacts>) => classifyIncident({ ...base, ...f }).map((m) => m.code);
const H = 3_600_000;

describe("CERT-In incident types", () => {
  it("lists Annexure I's twenty types in order", () => {
    expect(CERT_IN_CATEGORIES.map((c) => c.code)).toEqual(["i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "xi", "xii", "xiii", "xiv", "xv", "xvi", "xvii", "xviii", "xix", "xx"]);
    expect(CERT_IN_CATEGORIES[10].label).toBe("Data Breach");
  });

  it("proposes types from techniques, detections and the assets touched, with reasons", () => {
    // Ransomware on a critical database server.
    const ransomware = classifyIncident({ ...base, techniques: ["T1486"], detectionSources: ["IMPACT"], assets: [{ hostname: "DB-01", assetClass: "server", assetType: "database_server", criticality: "critical" }] });
    expect(ransomware.map((m) => m.code)).toEqual(["ii", "v", "vi"]);
    expect(ransomware.find((m) => m.code === "v")!.reasons[0]).toMatch(/T1486.*ransomware/);
    expect(ransomware.find((m) => m.code === "vi")!.reasons[0]).toMatch(/database server DB-01/);

    expect(codes({ sourceType: "EMAIL_ANALYSIS", domain: "EMAIL", verdict: "malicious", techniques: ["T1566.001"], detectionSources: ["EMAIL_HEADER_AUTH"] })).toEqual(["vii"]);
    expect(codes({ techniques: ["T1041"], detectionSources: ["DATA_EXFILTRATION"] })).toEqual(["xi"]);
    expect(codes({ detectionSources: ["AGENT_DLP"], sourceType: "AGENT_GOVERNANCE", domain: "AI_AGENTS" })).toEqual(["xii", "xx"]);
    expect(codes({ domain: "CLOUD", techniques: ["T1078.004"] })).toEqual(["iii", "xviii"]);
    expect(codes({ techniques: ["T0855"], assets: [{ hostname: "PLC-7", assetClass: "iot_ot", assetType: "plc", criticality: "standard" }] })).toEqual(["ix"]);
    expect(codes({ titles: ["DDoS against the payment gateway"] })).toEqual(["viii"]);
    expect(codes({ assets: [{ hostname: "CAM-3", assetClass: "iot_ot", assetType: "camera", criticality: "standard" }] })).toEqual(["xiii"]);
    expect(codes({ techniques: ["T1190"], assets: [{ hostname: "shop", assetClass: "apps", assetType: "web_app", criticality: "standard" }] })).toEqual(["x"]);
  });

  it("needs signs of compromise before calling a critical system compromised", () => {
    // Scanning a critical server is (i), not (ii); a phishing lure alone isn't compromise.
    expect(codes({ techniques: ["T1595"], assets: [{ hostname: "DC-01", assetClass: "server", assetType: "domain_controller", criticality: "critical" }] })).toEqual(["i"]);
    expect(codes({ techniques: ["T1566"], assets: [{ hostname: "DC-01", assetClass: "server", assetType: "domain_controller", criticality: "critical" }] })).toEqual(["vii"]);
    expect(codes({ techniques: ["T1059"], assets: [{ hostname: "DC-01", assetClass: "server", assetType: "domain_controller", criticality: "critical" }] })).toEqual(["ii", "vi"]);
  });

  it("proposes nothing for a benign case or one with nothing that maps", () => {
    expect(codes({ verdict: "clean", techniques: ["T1486"] })).toEqual([]);
    expect(codes({ techniques: ["T1082"] })).toEqual([]);
    expect(atLeast("HIGH", "MEDIUM")).toBe(true);
    expect(atLeast("MEDIUM", "HIGH")).toBe(false);
  });
});

describe("regulatory clocks", () => {
  const start = new Date("2026-10-26T04:00:00Z");

  it("sets each deadline from when the clock started", () => {
    expect(noticeDue("CERT_IN", start, 24).toISOString()).toBe("2026-10-26T10:00:00.000Z");
    expect(noticeDue("DPDP_REPORT", start, 24).toISOString()).toBe("2026-10-29T04:00:00.000Z");
    expect(noticeDue("DPDP_INTIMATION", start, 12).toISOString()).toBe("2026-10-26T16:00:00.000Z");
  });

  it("knows when a notice is running, due soon, overdue, on time or late", () => {
    const dueAt = noticeDue("CERT_IN", start, 24);
    const at = (h: number) => new Date(start.getTime() + h * H);
    const open = { clockStartAt: start, dueAt, submittedAt: null, status: "DRAFT" };
    expect(clockOf(open, at(1)).state).toBe("running");
    expect(clockOf(open, at(5.5)).state).toBe("due_soon");
    expect(clockOf(open, at(6.5))).toMatchObject({ state: "overdue", marginMs: -0.5 * H });
    expect(clockOf({ ...open, submittedAt: at(4), status: "SUBMITTED" }, at(9))).toMatchObject({ state: "met", marginMs: 2 * H, elapsedMs: 4 * H });
    expect(clockOf({ ...open, submittedAt: at(7), status: "SUBMITTED" }, at(9)).state).toBe("late");
    expect(clockOf({ ...open, status: "NOT_REQUIRED" }, at(9)).state).toBe("closed");
    expect([0.5, 3, 5.2, 6.1].map((h) => reminderStage({ clockStartAt: start, dueAt }, at(h)))).toEqual([1, 2, 3, 4]);
  });

  it("knows Rule 7 of the DPDP Rules applies from 13 May 2027", () => {
    expect(DPDP_RULE7_FROM.toISOString()).toBe("2027-05-12T18:30:00.000Z");
    expect(dpdpInForce(new Date("2026-10-26T00:00:00Z"))).toBe(false);
    expect(dpdpInForce(new Date("2027-05-13T00:00:00+05:30"))).toBe(true);
  });
});

describe("notice content", () => {
  it("says what's still needed before a notice can go out", () => {
    const certIn = parseContent("CERT_IN", { description: "Ransomware on DB-01" });
    expect(missingFields("CERT_IN", certIn)).toEqual(["the client's point of contact"]);
    expect(missingFields("CERT_IN", { ...certIn, reporter: { ...certIn.reporter, name: "A. Rao", phone: "+91 98" } })).toEqual([]);
    const principals = parseContent("DPDP_PRINCIPALS", {});
    expect(missingFields("DPDP_PRINCIPALS", principals)).toEqual(["description of the breach", "likely consequences", "steps people can take", "a contact for affected people"]);
    expect(() => parseContent("DPDP_INTIMATION", { principalsAffected: -1 })).toThrow();
  });

  it("writes the CERT-In email body from the report", () => {
    const r = parseContent("CERT_IN", {
      reporter: { name: "A. Rao", organisation: "Acme India", designation: "CISO", email: "ciso@acme.example", phone: "+91 98" },
      noticedAt: "2026-10-26T04:00:00.000Z",
      description: "Ransomware encrypted DB-01.",
      affectedSystems: [{ hostname: "DB-01", ip: "10.0.0.5", os: "Windows Server 2022", type: "Database server", critical: true }],
      actionsTaken: ["Isolate host DB-01 (done)"],
    });
    const text = certInEmail(r, ["v", "vi"], { tenantName: "Acme India", caseRef: "case_1", sequence: 1 });
    expect(text).toContain("Incident type (Annexure I): (v) Malicious code attacks");
    expect(text).toContain("(vi) Attack on servers");
    expect(text).toContain("- DB-01 · 10.0.0.5 · Windows Server 2022 · Database server (critical)");
    expect(text).not.toContain("Sector:");
    expect(certInEmail(r, ["v"], { tenantName: "Acme India", caseRef: "case_1", sequence: 2 })).toMatch(/^Cyber security incident report \(update 1\)/);
  });

  it("reads rulebooks saved before the reporting settings existed", () => {
    const old = rulebookSchema.parse({ obligations: { regulatedEntity: true, certInContact: { name: "A", email: "", phone: "" }, reportRecipients: [] } });
    expect(old.obligations).toMatchObject({ regulatedEntity: true, certInMinSeverity: "HIGH", dpdpFiduciary: false, dpdpWithoutDelayHours: 24 });
  });
});
