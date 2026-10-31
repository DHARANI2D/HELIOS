import { describe, expect, it } from "vitest";

import { financialYear, gstFor, gstinCheckChar, gstinProblem, invoiceNumber, stateOfGstin } from "@/lib/billing/gst";
import { evaluate, formatMoney, invoiceLines, periods, termEnd } from "@/lib/billing/terms";

const d = (s: string) => new Date(`${s}T00:00:00Z`);

describe("GST", () => {
  it("validates GSTINs, including the check character", () => {
    // Published examples.
    expect(gstinProblem("27AAPFU0939F1ZV")).toBeNull();
    expect(gstinProblem("29AAGCB7383J1Z4")).toBeNull();
    expect(gstinProblem("27AAPFU0939F1ZW")).toMatch(/check character/);
    expect(gstinProblem("99AAPFU0939F1ZV")).toMatch(/state code/);
    expect(gstinProblem("27AAPFU0939F1")).toMatch(/15 characters/);
    const base = "33ABCDE1234F1Z";
    expect(gstinProblem(base + gstinCheckChar(base))).toBeNull();
    expect(stateOfGstin("27aapfu0939f1zv")).toBe("27");
  });

  it("splits tax by place of supply", () => {
    const rate = { ratePct: 18, recipientInIndia: true };
    expect(gstFor({ ...rate, supplierState: "27", recipientState: "27" }, 100_000)).toEqual({ mode: "intra", lines: [{ label: "CGST 9%", ratePct: 9, amount: 9000 }, { label: "SGST 9%", ratePct: 9, amount: 9000 }] });
    expect(gstFor({ ...rate, supplierState: "04", recipientState: "04" }, 100_000).lines[1].label).toBe("UTGST 9%");
    expect(gstFor({ ...rate, supplierState: "27", recipientState: "29" }, 100_001)).toEqual({ mode: "inter", lines: [{ label: "IGST 18%", ratePct: 18, amount: 18000 }] });
    expect(gstFor({ ...rate, supplierState: "27", recipientState: null, recipientInIndia: false }, 100_000)).toEqual({ mode: "export", lines: [] });
    expect(gstFor({ ...rate, supplierState: null, recipientState: "27" }, 100_000).mode).toBe("none");
    expect(() => gstFor({ ...rate, supplierState: "27", recipientState: null }, 1)).toThrow(/state/);
  });

  it("numbers invoices by Indian financial year, within 16 characters", () => {
    expect(financialYear(d("2026-03-31"))).toBe("25-26");
    expect(financialYear(d("2026-04-01"))).toBe("26-27");
    // 31 March 20:00 UTC is already 1 April in India.
    expect(financialYear(new Date("2027-03-31T20:00:00Z"))).toBe("27-28");
    expect(invoiceNumber("HEL", "26-27", 7)).toBe("HEL/26-27/0007");
    expect(() => invoiceNumber("HELIOSX", "26-27", 1)).toThrow(/too long/);
  });
});

describe("contract terms", () => {
  it("cuts a term into billing periods, the last one short", () => {
    const p = periods(d("2026-01-31"), d("2026-04-15"), "monthly");
    expect(p.map((x) => [x.from.toISOString().slice(0, 10), x.to.toISOString().slice(0, 10), x.fraction])).toEqual([
      ["2026-01-31", "2026-02-28", 1],
      ["2026-02-28", "2026-03-31", 1],
      ["2026-03-31", "2026-04-15", 0.5],
    ]);
    expect(periods(d("2026-01-01"), termEnd(d("2026-01-01"), 12), "quarterly")).toHaveLength(4);
  });

  it("bills the commitment, endpoints above it, and onboarding once", () => {
    const c = { planName: "Advanced", cycle: "quarterly" as const, monthlyFee: 500_000, endpointsCommitted: 100, overagePerEndpoint: 6_000, oneTimeFee: 250_000 };
    const [p] = periods(d("2026-01-01"), d("2027-01-01"), "quarterly");
    const lines = invoiceLines(c, p, 120, true);
    expect(lines.map((l) => [l.quantity, l.amount])).toEqual([[3, 1_500_000], [60, 360_000], [1, 250_000]]);
    expect(lines[0].description).toContain("2026-01-01 to 2026-03-31");
    expect(invoiceLines(c, p, 90, false)).toHaveLength(1);
    expect(formatMoney(1_500_000, "INR")).toBe("₹15,000.00");
  });

  it("judges pilot criteria in each metric's better direction", () => {
    const r = evaluate([{ metric: "mtta_minutes", target: 15 }, { metric: "ai_agreement_pct", target: 90 }, { metric: "critical_false_containments", target: 0 }, { metric: "qa_agreement_pct", target: 80 }], { mtta_minutes: 12, ai_agreement_pct: 85, critical_false_containments: 0, qa_agreement_pct: null });
    expect(r.map((x) => x.met)).toEqual([true, false, true, null]);
  });
});
