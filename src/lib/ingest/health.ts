import type { CaseSeverity, Integration, SecurityDomain } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { createCase } from "@/lib/cases/writer";
import { notify, staffFor } from "@/lib/notifications";
import { getCatalogTool } from "@/lib/integrations/tools";
import type { IngestFormat } from "@/lib/integrations/catalog";

// Source health. Every source's events are counted per hour; a source that
// goes quiet for longer than it should is itself a finding, because
// attackers often stop logging first (MITRE T1562.002, T1562.008). It opens
// a case of its own (unless it went quiet over a week ago: then it is only
// marked), and a client can't go live while a source is dead.
//
// How long is too long: the integration's own setting if set (0 = never);
// otherwise two hours for telemetry (sign-ins, audit logs, forwarders,
// firewalls) and a day for a sparse one (a median under two events an hour
// over the last week). Alert-only feeds (EDR alerts) are quiet when all is
// well, so they aren't watched unless someone sets a limit.

const HOUR = 3_600_000;
const STALE_DAYS = 7;
const TELEMETRY: IngestFormat[] = ["forwarder", "entra", "okta", "google_workspace", "cloudtrail", "azure_activity", "gcp_audit", "wazuh", "generic"];
// Categories whose tools send data at all (not chat, tickets or automation).
export const DATA_CATEGORIES = new Set(["edr", "epp", "identity", "network", "email", "cloud", "siem", "ndr", "ot", "webapp", "dlp", "pam", "mtd", "mdm"]);

const hourOf = (d: Date) => new Date(Math.floor(d.getTime() / HOUR) * HOUR);

export async function recordSourceEvents(integrationId: string, count: number, at = new Date()) {
  if (count <= 0) return;
  const hour = hourOf(at);
  await db.$executeRaw`
    INSERT INTO source_health_hours ("integrationId", hour, events) VALUES (${integrationId}, ${hour}, ${count})
    ON CONFLICT ("integrationId", hour) DO UPDATE SET events = source_health_hours.events + EXCLUDED.events`;
}

export function median(values: number[]) {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

// Minutes of silence before the source counts as quiet, or null when it
// isn't watched. `hourly` covers the hours since the source first sent
// (up to a week), empty hours included.
export function quietLimit(setting: number | null, format: IngestFormat | null, hourly: number[]): number | null {
  if (setting !== null && setting !== undefined) return setting > 0 ? setting : null;
  if (!format || !TELEMETRY.includes(format)) return null;
  return hourly.length && median(hourly) < 2 ? 24 * 60 : 120;
}

export type SourceState = "live" | "quiet" | "never" | "unwatched" | "stale";

export interface SourceHealth {
  integrationId: string;
  state: SourceState;
  lastEventAt: Date | null;
  quietSince: Date | null;
  quietCaseId: string | null;
  limitMinutes: number | null;
  lastHour: number;
  perHour7d: number;
  // The last 24 hours, oldest first.
  hours: number[];
}

type HealthInput = Pick<Integration, "id" | "vendor" | "lastEventAt" | "quietAfterMinutes" | "quietSince" | "quietCaseId">;

export async function sourceHealth(integrations: HealthInput[], now = new Date()): Promise<Map<string, SourceHealth>> {
  const ids = integrations.map((i) => i.id);
  const rows = ids.length ? await db.sourceHealthHour.findMany({ where: { integrationId: { in: ids }, hour: { gte: new Date(now.getTime() - 168 * HOUR) } } }) : [];
  const byId = new Map<string, Map<number, number>>();
  for (const r of rows) {
    const m = byId.get(r.integrationId) ?? new Map<number, number>();
    m.set(r.hour.getTime(), r.events);
    byId.set(r.integrationId, m);
  }
  const current = hourOf(now).getTime();
  const out = new Map<string, SourceHealth>();
  for (const i of integrations) {
    const tool = await getCatalogTool(i.vendor);
    const m = byId.get(i.id) ?? new Map<number, number>();
    const week = Array.from({ length: 168 }, (_, k) => m.get(current - (167 - k) * HOUR) ?? 0);
    // The baseline starts when the source did: hours before it existed aren't quiet ones.
    const first = m.size ? Math.min(...m.keys()) : current;
    const span = week.slice(167 - Math.round((current - first) / HOUR));
    const limit = quietLimit(i.quietAfterMinutes, tool?.ingest ?? null, m.size ? span : []);
    const silentMin = i.lastEventAt ? (now.getTime() - i.lastEventAt.getTime()) / 60_000 : null;
    const state: SourceState = !i.lastEventAt ? "never" : i.quietSince ? "quiet" : limit === null ? "unwatched" : silentMin! > limit ? "stale" : "live";
    out.set(i.id, {
      integrationId: i.id,
      state,
      lastEventAt: i.lastEventAt,
      quietSince: i.quietSince,
      quietCaseId: i.quietCaseId,
      limitMinutes: limit,
      lastHour: week[167],
      perHour7d: Math.round((week.reduce((a, b) => a + b, 0) / 168) * 100) / 100,
      hours: week.slice(-24),
    });
  }
  return out;
}

const DOMAIN: Record<string, SecurityDomain> = { identity: "IDENTITY", email: "EMAIL", network: "NETWORK", ndr: "NETWORK", cloud: "CLOUD", webapp: "CLOUD" };
// A silent EDR, identity provider or forwarder is the likeliest sign of tampering.
const SEVERE = new Set(["edr", "epp", "identity", "siem"]);

const ago = (from: Date, to: Date) => {
  const m = Math.round((to.getTime() - from.getTime()) / 60_000);
  return m < 120 ? `${m} minutes` : m < 72 * 60 ? `${Math.round(m / 60)} hours` : `${Math.round(m / 1440)} days`;
};

// The five-minute check: open a case for each source that went quiet, and
// note on it when the source comes back.
export async function checkSourceHealth(now = new Date()) {
  const integrations = await db.integration.findMany({ where: { enabled: true, lastEventAt: { not: null } }, include: { tenant: { select: { name: true } } } });
  const health = await sourceHealth(integrations, now);
  let opened = 0;
  let resumed = 0;
  for (const i of integrations) {
    const h = health.get(i.id)!;
    if (h.limitMinutes === null) continue;
    const silentMin = (now.getTime() - i.lastEventAt!.getTime()) / 60_000;
    const silent = silentMin > h.limitMinutes;
    // Silent for over a week (a retired tool still enabled, or this check is new):
    // marked quiet, but not raised as something happening now.
    if (silent && !i.quietSince && silentMin > STALE_DAYS * 24 * 60) {
      await db.integration.update({ where: { id: i.id }, data: { quietSince: i.lastEventAt, status: "DEGRADED", lastError: `No events for ${ago(i.lastEventAt!, now)}` } });
      continue;
    }
    if (silent && !i.quietSince) {
      const severity: CaseSeverity = SEVERE.has(i.category) ? "HIGH" : "MEDIUM";
      const title = `Log source went quiet: ${i.name}`;
      const usual = h.perHour7d >= 1 ? `about ${Math.round(h.perHour7d)} events an hour over the last week` : "only occasional events";
      const kase = await createCase({
        sourceType: "SIEM_ALERT",
        title,
        summary: `No events from ${i.name} for ${ago(i.lastEventAt!, now)} (last at ${i.lastEventAt!.toISOString()}; usually ${usual}). Attackers often stop logging before they act. Check the source itself, the forwarder or collector and its credentials, and whether anything changed on the hosts that send it.`,
        severity,
        sourceRef: `source:${i.id}`,
        tenantId: i.tenantId,
        domain: DOMAIN[i.category] ?? "ENDPOINT",
        metadata: { integrationId: i.id, riskObject: i.name, riskObjectType: "source", lastEventAt: i.lastEventAt!.toISOString(), limitMinutes: h.limitMinutes },
        techniques: [i.category === "cloud" ? "T1562.008" : "T1562.002"],
        detections: [
          {
            source: "DEFENSE_EVASION",
            ruleId: "source_health:quiet",
            title,
            severity,
            fingerprint: `quiet:${i.id}:${i.lastEventAt!.toISOString()}`,
            evidence: { integration: i.name, lastEventAt: i.lastEventAt, limitMinutes: h.limitMinutes, perHour7d: h.perHour7d, hours: h.hours },
          },
        ],
        timeline: [{ occurredAt: i.lastEventAt!, actor: i.name, action: "source.last_event", detail: `Last event received from ${i.name}` }],
      });
      await db.integration.update({ where: { id: i.id }, data: { quietSince: i.lastEventAt, quietCaseId: kase.id, status: "DEGRADED", lastError: `No events for ${ago(i.lastEventAt!, now)}` } });
      await logAction({ caseId: kase.id, action: "source.quiet", detail: { integrationId: i.id, tenantId: i.tenantId, lastEventAt: i.lastEventAt, limitMinutes: h.limitMinutes } });
      await notify(await staffFor(["SOC_MANAGER", "TRIAGE_ANALYST", "DETECTION_ENGINEER"], DOMAIN[i.category] ?? "ENDPOINT"), {
        kind: "ingest",
        title,
        body: `${i.tenant?.name ?? "SOC"} · nothing for ${ago(i.lastEventAt!, now)}`,
        caseId: kase.id,
        href: `/cases/${kase.id}`,
      });
      opened++;
    } else if (!silent && i.quietSince) {
      if (i.quietCaseId) {
        await db.timelineEntry.create({ data: { caseId: i.quietCaseId, occurredAt: i.lastEventAt!, actor: i.name, action: "source.resumed", detail: `${i.name} is sending again after ${ago(i.quietSince, i.lastEventAt!)} of silence. Check what was missed in that window.` } }).catch(() => undefined);
      }
      await db.integration.update({ where: { id: i.id }, data: { quietSince: null, quietCaseId: null, status: "CONNECTED", lastError: null } });
      await logAction({ caseId: i.quietCaseId ?? undefined, action: "source.resumed", detail: { integrationId: i.id, tenantId: i.tenantId, quietSince: i.quietSince } });
      resumed++;
    }
  }
  return { checked: integrations.length, opened, resumed };
}

// Why a client can't go live yet: every data source must have sent
// something in the last day, and none may be quiet.
export async function goLiveBlockers(tenantId: string, now = new Date()): Promise<string[]> {
  const integrations = await db.integration.findMany({ where: { tenantId, enabled: true } });
  const sources = integrations.filter((i) => DATA_CATEGORIES.has(i.category));
  if (!sources.length) return ["No log source is connected yet"];
  const blockers: string[] = [];
  for (const i of sources) {
    if (!i.lastEventAt) blockers.push(`${i.name} hasn't sent anything yet`);
    else if (i.quietSince) blockers.push(`${i.name} has been quiet since ${i.quietSince.toISOString().slice(0, 16).replace("T", " ")} UTC`);
    else if (now.getTime() - i.lastEventAt.getTime() > 24 * HOUR) blockers.push(`${i.name} hasn't sent anything in the last day`);
  }
  return blockers;
}
