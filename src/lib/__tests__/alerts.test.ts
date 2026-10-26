import { describe, expect, it } from "vitest";

import { E164, groupsFromPrefs, parsePrefs, prefsFromGroups, smsText } from "@/lib/alerts/kinds";
import { approverSchema } from "@/lib/rulebook/schema";

describe("alert preferences", () => {
  it("stores group choices per notification kind and reads them back", () => {
    const prefs = prefsFromGroups({ approvals: ["email", "sms"], regulatory: ["whatsapp"], mine: [] });
    expect(prefs).toEqual({ approval: ["email", "sms"], compliance: ["whatsapp"] });
    expect(groupsFromPrefs(prefs)).toMatchObject({ approvals: ["email", "sms"], regulatory: ["whatsapp"], incidents: [], mine: [], sources: [] });
    expect(prefsFromGroups({ incidents: ["email"] })).toEqual({ shared: ["email"], escalated: ["email"], sla: ["email"] });
  });

  it("ignores stored preferences it can't read", () => {
    expect(parsePrefs({ approval: ["pager"] })).toEqual({});
    expect(parsePrefs(null)).toEqual({});
    expect(parsePrefs("junk")).toEqual({});
  });

  it("keeps a text message short, with the link intact", () => {
    const link = "https://soc.example/approvals";
    const text = smsText("Approval needed: Isolate host DB-01", "x".repeat(1000), link);
    expect(text.length).toBeLessThanOrEqual(320);
    expect(text.startsWith("HELIOS: Approval needed: Isolate host DB-01 — ")).toBe(true);
    expect(text.endsWith(` ${link}`)).toBe(true);
    expect(smsText("Test alert", null, null)).toBe("HELIOS: Test alert");
  });

  it("checks phone numbers for texts are in international format", () => {
    expect(E164.test("+919812345678")).toBe(true);
    expect(E164.test("9812345678")).toBe(false);
    const sms = approverSchema.parse({ name: "CISO", contact: "+91 98123-45678", channel: "sms" });
    expect(sms.contact).toBe("+919812345678");
    expect(approverSchema.safeParse({ name: "CISO", contact: "98123 45678", channel: "whatsapp" }).success).toBe(false);
    expect(approverSchema.parse({ name: "CISO", contact: "ciso@client.example", channel: "email" }).contact).toBe("ciso@client.example");
  });
});
