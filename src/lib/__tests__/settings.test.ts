import { afterEach, describe, expect, it } from "vitest";

import { normalize } from "@/lib/siem/adapters";
import { runDetections } from "@/lib/siem/engine";
import { detectionCapabilities } from "@/lib/mitre/coverage";
import { aggregateVerdict } from "@/lib/forensics/scoring";
import { domainWhitelist } from "@/lib/forensics/body";
import { companySchema, thresholdsSchema } from "@/lib/settings";
import { platformSecret } from "@/lib/platform-secrets";
import { EMPTY_INTEL } from "@/lib/threat-intel/local-intel";

const dump = { id: "e1", ...normalize("endpoint", { user: "u", process: "mimikatz.exe sekurlsa::logonpasswords", hostname: "ws-1" }) };

describe("detection tuning", () => {
  it("skips detectors that are switched off", () => {
    expect(runDetections([dump]).some((d) => d.detector === "CredentialHarvestingDetector")).toBe(true);
    expect(runDetections([dump], { intel: EMPTY_INTEL, disabled: ["CredentialHarvestingDetector"] }).some((d) => d.detector === "CredentialHarvestingDetector")).toBe(false);
  });

  it("drops switched-off detectors from ATT&CK coverage", () => {
    const rules = (disabled: string[]) => new Set(detectionCapabilities(disabled).map((c) => c.rule));
    expect(rules([]).has("ImpactDetector")).toBe(true);
    expect(rules(["ImpactDetector"]).has("ImpactDetector")).toBe(false);
  });
});

describe("forensics settings", () => {
  it("applies the saved verdict thresholds", () => {
    const parts = [{ component: "Content analysis" as const, points: 40, reasons: ["lure"] }];
    expect(aggregateVerdict(parts).verdict).toBe("suspicious");
    expect(aggregateVerdict(parts, { malicious: 40, suspicious: 20 }).verdict).toBe("malicious");
    expect(aggregateVerdict(parts, { malicious: 90, suspicious: 50 }).verdict).toBe("benign");
  });

  it("rejects thresholds that overlap", () => {
    expect(thresholdsSchema.safeParse({ malicious: 30, suspicious: 40 }).success).toBe(false);
    expect(thresholdsSchema.safeParse({ malicious: 71, suspicious: 31 }).success).toBe(true);
  });

  it("adds saved trusted domains to the built-in ones", () => {
    expect(domainWhitelist(["partner.example"])).toEqual(expect.arrayContaining(["google.com", "partner.example"]));
  });
});

describe("company profile", () => {
  it("allows an empty profile but not a malformed email", () => {
    const empty = { name: "", legalName: "", address: "", email: "", phone: "", website: "", taxId: "", quoteTerms: "", reportFooter: "" };
    expect(companySchema.safeParse(empty).success).toBe(true);
    expect(companySchema.safeParse({ ...empty, email: "not-an-email" }).success).toBe(false);
  });
});

describe("platform secrets", () => {
  afterEach(() => {
    delete process.env.ABUSEIPDB_API_KEY;
  });

  it("falls back to the environment variable when nothing is stored", async () => {
    process.env.ABUSEIPDB_API_KEY = "env-key-1234";
    expect(await platformSecret("abuseipdb")).toBe("env-key-1234");
  });
});
