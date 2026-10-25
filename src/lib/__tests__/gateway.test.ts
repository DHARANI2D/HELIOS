import { describe, expect, it } from "vitest";
import { z } from "zod";

import { Redactor } from "@/lib/ai/redact";
import { pickCandidate, whyNot, withRedaction, type Candidate } from "@/lib/ai/gateway";
import type { LlmProvider } from "@/lib/ai/provider";

const cloud = (over: Partial<Candidate> = {}): Candidate => ({ source: "platform", id: "p-cloud", name: "Claude", model: "claude-sonnet-5-5", isLocal: false, region: "us", tenantId: null, ...over });
const local = cloud({ id: "p-local", name: "vLLM", isLocal: true, region: null });
const rules = (over: Partial<{ residency: "any" | "region" | "onprem"; regions: string[]; allowedProviders: string[] }> = {}) => ({ residency: "any" as const, regions: [], allowedProviders: [], ...over });

describe("model choice per client", () => {
  it("applies residency, allowed lists and ownership", () => {
    expect(whyNot(cloud(), "t1", null)).toBeNull();
    expect(whyNot(cloud(), "t1", rules({ residency: "onprem" }))).toMatch(/on-premises/);
    expect(whyNot(local, "t1", rules({ residency: "onprem" }))).toBeNull();
    expect(whyNot(cloud(), "t1", rules({ residency: "region", regions: ["india"] }))).toMatch(/runs in us/);
    expect(whyNot(cloud({ region: "India" }), "t1", rules({ residency: "region", regions: ["india"] }))).toBeNull();
    expect(whyNot(cloud(), "t1", rules({ allowedProviders: ["other"] }))).toMatch(/allowed list/);
    // The client's own provider is allowed by being theirs; never anyone else's.
    expect(whyNot(cloud({ tenantId: "t1" }), "t1", rules({ allowedProviders: ["other"] }))).toBeNull();
    expect(whyNot(cloud({ tenantId: "t2" }), "t1", null)).toMatch(/another client/);
  });

  it("takes the first allowed candidate and says what it skipped", () => {
    const { chosen, skipped } = pickCandidate([cloud({ source: "user", name: "Mine" }), local], "t1", rules({ residency: "onprem" }));
    expect(chosen?.name).toBe("vLLM");
    expect(skipped).toEqual([{ name: "Mine", source: "user", why: expect.stringMatching(/on-premises/) }]);
    expect(pickCandidate([cloud()], "t1", rules({ residency: "onprem" })).chosen).toBeNull();
  });
});

describe("masking personal data", () => {
  it("tokenises known and found entities and restores them", () => {
    const r = new Redactor({ hosts: ["WS-FIN-07"], users: ["CORP\\jdoe"], ips: ["10.1.2.3"] });
    const text = "CORP\\jdoe logged on to WS-FIN-07 from 10.1.2.3, then mailed jane.roe@corp.example and connected to 203.0.113.9. ws-fin-07 again.";
    const masked = r.redact(text);
    expect(masked).not.toMatch(/jdoe|WS-FIN-07|10\.1\.2\.3|jane\.roe|203\.0\.113\.9/i);
    expect(masked).toContain("USER_1 logged on to HOST_1 from IP_1");
    expect(masked).toMatch(/HOST_1 again/);
    expect(r.restoreText(masked)).toBe(text.replace("ws-fin-07 again", "WS-FIN-07 again"));
    // Doesn't touch parts of longer names.
    expect(r.redact("WS-FIN-070 and WS-FIN-07.corp.local")).toBe("WS-FIN-070 and WS-FIN-07.corp.local");
  });

  it("wraps a provider so the model only sees tokens and callers only see values", async () => {
    let seen = "";
    const fake: LlmProvider = {
      name: "fake",
      kind: "anthropic",
      model: "m",
      isLocal: false,
      async structured(req) {
        seen = req.user;
        return { data: req.schema.parse({ target: "HOST_1", note: "isolate HOST_1 for USER_1" }), model: "m", usage: {} };
      },
      async text(req) {
        seen = req.user;
        return { data: "HOST_1 is clean", model: "m", usage: {} };
      },
      async check() {
        return { ok: true, message: "ok" };
      },
    };
    const { provider } = withRedaction(fake, { hosts: ["DC-01"], users: ["alice"] });
    const res = await provider.structured({ schema: z.object({ target: z.string(), note: z.string() }), schemaName: "x", system: "", user: "alice on DC-01", effort: "low" });
    expect(seen).toBe("USER_1 on HOST_1");
    expect(res.data).toEqual({ target: "DC-01", note: "isolate DC-01 for alice" });
    expect((await provider.text({ system: "", user: "DC-01", effort: "low" })).data).toBe("DC-01 is clean");
  });
});
