import { createElement } from "react";
import { renderToBuffer } from "@react-pdf/renderer";
import { describe, expect, it } from "vitest";

import { pdfText, plainMarkdown } from "@/lib/pdf/kit";
import { ServiceReportPdf } from "@/lib/pdf/service-report";
import { caseTrend, parseRange, summarizeCases } from "@/lib/reports";
import type { ServiceReport } from "@/lib/reports";

const company = { name: "Test SOC", legalName: "", address: "", email: "soc@helios.test", phone: "", website: "", taxId: "", quoteTerms: "", reportFooter: "Confidential — test" };

describe("PDF text", () => {
  it("keeps Latin-1 and typographic marks, and maps or replaces the rest", () => {
    expect(pdfText("Café — 5 € · ≥ 3 → done")).toBe("Café — 5 € · >= 3 -> done");
    expect(pdfText("Привет\u0000ok")).toBe("??????ok");
  });

  it("flattens agent Markdown", () => {
    expect(plainMarkdown("## Root cause\n**Phishing** via `invoice.docm`\n- step [one](https://x.test)")).toBe("Root cause\nPhishing via invoice.docm\n• step one (https://x.test)");
  });
});

describe("service report PDF", () => {
  it("renders a valid multi-section document", async () => {
    const now = new Date("2026-10-24T12:00:00Z");
    const range = parseRange({ range: "7d" }, now);
    const opened = [{ createdAt: new Date("2026-10-20T08:00:00Z"), acknowledgedAt: new Date("2026-10-20T08:10:00Z"), containedAt: null, resolvedAt: null, slaDueAt: null, severity: "HIGH" as const, status: "OPEN" as const, sourceType: "SIEM_ALERT" as const, domain: "ENDPOINT" as const, tenantId: "t1", assignedToId: null }];
    const summary = summarizeCases(opened, [], range, now);
    const report: ServiceReport = {
      range,
      previous: range,
      generatedAt: now,
      openNow: 1,
      summary,
      previousSummary: summarizeCases([], [], range, now),
      trend: caseTrend(opened, [], range),
      tenants: [{ id: "t1", name: "Test · Clinic", isTest: true, count: 1 }],
      techniques: [{ id: "T1059", name: "Command and Scripting Interpreter", count: 1 }],
      indicators: [{ type: "IP", value: "198.51.100.7", score: 0.9, cases: 1 }],
      analysts: [],
      ai: { runs: 1, automatic: 1, local: 0, byStatus: { succeeded: 1 }, medianDurationMs: 1200, rated: 0, agreed: 0 },
      actions: { total: 0, byStatus: {}, byType: {}, fromAi: 0 },
    };
    const buffer = await renderToBuffer(createElement(ServiceReportPdf, { report, company, scope: "Test · Clinic", internal: true }) as Parameters<typeof renderToBuffer>[0]);
    expect(buffer.subarray(0, 5).toString()).toBe("%PDF-");
    expect(buffer.length).toBeGreaterThan(2000);
  }, 30_000);
});
