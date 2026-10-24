import type { Prisma } from "@prisma/client";

import { db } from "@/lib/db";

// SOC service metrics over a case set: mean time to acknowledge / contain /
// resolve, and SLA compliance (acknowledged by the plan's deadline).

export interface ServiceMetrics {
  cases: number;
  mttaMinutes: number | null;
  mttcMinutes: number | null;
  mttrMinutes: number | null;
  slaMet: number;
  slaBreached: number;
  slaCompliance: number | null; // 0-1
}

const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);

export function computeMetrics(
  rows: Array<{ createdAt: Date; acknowledgedAt: Date | null; containedAt: Date | null; resolvedAt: Date | null; slaDueAt: Date | null }>,
  now: Date,
): ServiceMetrics {
  const minutes = (a: Date, b: Date) => (b.getTime() - a.getTime()) / 60_000;
  let met = 0;
  let breached = 0;
  for (const r of rows) {
    if (!r.slaDueAt) continue;
    if (r.acknowledgedAt) {
      if (r.acknowledgedAt <= r.slaDueAt) met++;
      else breached++;
    } else if (now > r.slaDueAt) {
      breached++;
    }
  }
  return {
    cases: rows.length,
    mttaMinutes: avg(rows.filter((r) => r.acknowledgedAt).map((r) => minutes(r.createdAt, r.acknowledgedAt!))),
    mttcMinutes: avg(rows.filter((r) => r.containedAt).map((r) => minutes(r.createdAt, r.containedAt!))),
    mttrMinutes: avg(rows.filter((r) => r.resolvedAt).map((r) => minutes(r.createdAt, r.resolvedAt!))),
    slaMet: met,
    slaBreached: breached,
    slaCompliance: met + breached ? met / (met + breached) : null,
  };
}

export async function serviceMetrics(where: Prisma.CaseWhereInput, since: Date, now = new Date()): Promise<ServiceMetrics> {
  const rows = await db.case.findMany({
    where: { AND: [where, { createdAt: { gte: since } }] },
    select: { createdAt: true, acknowledgedAt: true, containedAt: true, resolvedAt: true, slaDueAt: true },
    take: 10_000,
  });
  return computeMetrics(rows, now);
}

export function formatDuration(minutes: number | null): string {
  if (minutes == null) return "—";
  if (minutes < 1) return `${Math.round(minutes * 60)}s`;
  if (minutes < 60) return `${Math.round(minutes)}m`;
  const h = minutes / 60;
  if (h < 48) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}
