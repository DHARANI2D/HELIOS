import { describe, expect, it } from "vitest";

import { caseTrend, formatDuration, median, parseRange, previousRange, slaOutcome, summarizeCases, type CaseFacts } from "@/lib/reports";

const NOW = new Date("2026-10-24T12:00:00Z");
const t = (iso: string) => new Date(iso);
const base: CaseFacts = { createdAt: t("2026-10-20T08:00:00Z"), acknowledgedAt: null, containedAt: null, resolvedAt: null, slaDueAt: null, severity: "HIGH", status: "OPEN", sourceType: "SIEM_ALERT", domain: "ENDPOINT", tenantId: "t1", assignedToId: null };
const facts = (o: Partial<CaseFacts>): CaseFacts => ({ ...base, ...o });

describe("report periods", () => {
  it("parses presets and calendar months", () => {
    expect(parseRange({ range: "7d" }, NOW)).toMatchObject({ key: "7d", from: t("2026-10-17T12:00:00Z"), to: NOW });
    expect(parseRange({ month: "2026-09" }, NOW)).toMatchObject({ key: "2026-09", label: "September 2026", from: t("2026-09-01T00:00:00Z"), to: t("2026-10-01T00:00:00Z") });
    expect(parseRange({ range: "bogus" }, NOW).key).toBe("30d");
    expect(parseRange({ month: "2027-01" }, NOW).key).toBe("30d"); // the future has no report
  });

  it("compares against the period of the same length before it", () => {
    const r = parseRange({ month: "2026-09" }, NOW);
    expect(previousRange(r)).toMatchObject({ from: t("2026-08-02T00:00:00Z"), to: r.from });
  });
});

describe("case metrics", () => {
  it("counts SLA outcomes, treating an unacknowledged overdue case as breached", () => {
    const due = t("2026-10-20T09:00:00Z");
    const sla = slaOutcome(
      [
        facts({ slaDueAt: due, acknowledgedAt: t("2026-10-20T08:30:00Z") }),
        facts({ slaDueAt: due, acknowledgedAt: t("2026-10-20T10:00:00Z") }),
        facts({ slaDueAt: due }),
        facts({ slaDueAt: t("2026-10-25T00:00:00Z") }),
        facts({}),
      ],
      NOW,
    );
    expect(sla).toEqual({ met: 1, breached: 2, pending: 1, compliance: 1 / 3 });
  });

  it("takes medians of acknowledge and resolve times", () => {
    const r = parseRange({ range: "30d" }, NOW);
    const opened = [10, 20, 60].map((m) => facts({ acknowledgedAt: new Date(base.createdAt.getTime() + m * 60_000) }));
    const closed = [facts({ status: "RESOLVED", resolvedAt: t("2026-10-20T10:00:00Z") }), facts({ status: "FALSE_POSITIVE", resolvedAt: t("2026-10-20T12:00:00Z") })];
    const s = summarizeCases(opened, closed, r, NOW);
    expect(s).toMatchObject({ opened: 3, closed: 2, falsePositives: 1, medianAcknowledgeMs: 20 * 60_000, medianResolveMs: 3 * 3_600_000, bySeverity: { HIGH: 3 }, byTenant: { t1: 3 } });
    expect(median([])).toBeNull();
  });

  it("buckets the trend by day, and by week for long periods", () => {
    const r = parseRange({ range: "7d" }, NOW);
    const trend = caseTrend([facts({ createdAt: t("2026-10-20T08:00:00Z") }), facts({ createdAt: t("2026-10-20T23:00:00Z") })], [facts({ resolvedAt: t("2026-10-21T01:00:00Z") })], r);
    expect(trend).toHaveLength(8);
    expect(trend.find((p) => p.start === "2026-10-20")).toMatchObject({ opened: 2, closed: 0 });
    expect(trend.find((p) => p.start === "2026-10-21")).toMatchObject({ opened: 0, closed: 1 });
    const year = caseTrend([], [], parseRange({ range: "365d" }, NOW));
    expect(year.length).toBeGreaterThanOrEqual(52);
    expect(new Date(year[1].start).getUTCDay()).toBe(1); // Mondays
  });

  it("formats durations for people", () => {
    expect([formatDuration(null), formatDuration(30_000), formatDuration(45 * 60_000), formatDuration(5 * 3_600_000), formatDuration(3 * 86_400_000)]).toEqual(["—", "30s", "45m", "5.0h", "3.0d"]);
  });
});
