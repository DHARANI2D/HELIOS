import { createHash } from "node:crypto";
import type { Integration, Prisma, UserRole } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { hashToken, newToken, seal } from "@/lib/secrets";
import { maxSeverity } from "@/lib/severity";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { appendToCase, createCase, type NewIndicator } from "@/lib/cases/writer";
import { ingestTelemetry, type IngestItem } from "@/lib/siem/service";
import { applyInventory, touchEndpoints } from "@/lib/endpoints/service";
import { getCategory } from "@/lib/integrations/catalog";
import { getCatalogTool } from "@/lib/integrations/tools";
import { inventoryFrom, mapRecord, recordsFrom, type VendorAlert } from "@/lib/integrations/mappers";
import type { IntegrationConfig, IntegrationSecrets } from "@/lib/integrations/dispatch";
import type { SessionUser } from "@/lib/session";
import type { TelemetrySource } from "@/lib/siem/types";

// Onboarded tools. Each integration belongs to one client tenant, is visible
// to the roles in allowedRoles plus explicitly assigned users, and gets an
// ingest token for POST /api/ingest/<id> (vendor alerts become cases;
// telemetry goes through the detection engine; inventory updates endpoints).

const MAX_RECORDS = 5000;
const WINDOW_MS = 24 * 60 * 60 * 1000;

export function visibleIntegrationsWhere(user: SessionUser): Prisma.IntegrationWhereInput {
  if (user.isClient) return { tenantId: user.tenantId ?? "__none__" };
  if (user.role === "ADMIN" || user.role === "SOC_MANAGER" || user.role === "AUDITOR") return {};
  return { OR: [{ allowedRoles: { has: user.role } }, { assignments: { some: { userId: user.id } } }] };
}

export interface OnboardInput {
  tenantId: string | null;
  vendor: string;
  name?: string;
  allowedRoles?: UserRole[];
  assignedUserIds?: string[];
  config?: IntegrationConfig;
  secrets?: IntegrationSecrets;
}

export async function onboardIntegration(input: OnboardInput, actorId: string) {
  const tool = await getCatalogTool(input.vendor);
  if (!tool) throw new Error("Unknown tool");
  const category = getCategory(tool.category)!;
  const { token, hash, display } = newToken("hel");
  const secrets = Object.fromEntries(Object.entries(input.secrets ?? {}).filter(([, v]) => !!v));
  const integration = await db.integration.create({
    data: {
      tenantId: input.tenantId,
      vendor: tool.key,
      category: tool.category,
      name: input.name?.trim() || `${tool.vendor} ${tool.name}`,
      allowedRoles: input.allowedRoles?.length ? input.allowedRoles : category.defaultRoles,
      config: { telemetrySource: category.telemetry, ...(input.config ?? {}) } as Prisma.InputJsonValue,
      secretCipher: Object.keys(secrets).length ? seal(JSON.stringify(secrets)) : null,
      ingestTokenHash: tool.ingest ? hash : null,
      tokenPrefix: tool.ingest ? display : null,
      createdById: actorId,
      assignments: input.assignedUserIds?.length ? { create: input.assignedUserIds.map((userId) => ({ userId })) } : undefined,
    },
  });
  await logAction({ actorId, action: "integration.onboarded", detail: { integrationId: integration.id, vendor: tool.key, tenantId: input.tenantId } });
  return { integration, token: tool.ingest ? token : null };
}

export async function rotateIngestToken(integrationId: string, actorId: string) {
  const { token, hash, display } = newToken("hel");
  await db.integration.update({ where: { id: integrationId }, data: { ingestTokenHash: hash, tokenPrefix: display } });
  await logAction({ actorId, action: "integration.token_rotated", detail: { integrationId } });
  return token;
}

export async function integrationForToken(header: string | null): Promise<Integration | null> {
  const token = header?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (!token) return null;
  const integration = await db.integration.findUnique({ where: { ingestTokenHash: hashToken(token) } });
  if (!integration || !integration.enabled) return null;
  return integration;
}

// Firewalls and proxies pulling the blocklist feed use a network-category
// tool's ingest token.
export async function authenticateFeedToken(header: string | null) {
  const integration = await integrationForToken(header);
  return integration && integration.category === "network" ? integration : null;
}

function fingerprint(integrationId: string, alert: VendorAlert) {
  const key = alert.externalId ?? `${alert.title}|${alert.host ?? ""}|${alert.user ?? ""}|${alert.timestamp.toISOString()}`;
  return createHash("sha256").update(`${integrationId}:${key}`).digest("hex").slice(0, 40);
}

async function fileVendorAlerts(integration: Integration, alerts: VendorAlert[]) {
  const tool = await getCatalogTool(integration.vendor);
  const fingerprints = alerts.map((a) => fingerprint(integration.id, a));
  const existing = new Set((await db.detection.findMany({ where: { fingerprint: { in: fingerprints } }, select: { fingerprint: true } })).map((d) => d.fingerprint));

  // Correlate per risk object, the same keys the SIEM uses, so a vendor
  // alert and HELIOS's own detection on the same host land in one case.
  const groups = new Map<string, Array<{ alert: VendorAlert; fp: string }>>();
  alerts.forEach((alert, i) => {
    const fp = fingerprints[i];
    if (existing.has(fp)) return;
    existing.add(fp);
    const key = alert.host ? `host:${alert.host}` : alert.user ? `user:${alert.user}` : alert.ips[0] ? `ip:${alert.ips[0]}` : `alert:${fp}`;
    groups.set(key, [...(groups.get(key) ?? []), { alert, fp }]);
  });

  const since = new Date(Date.now() - WINDOW_MS);
  let created = 0;
  let updated = 0;
  const caseIds: string[] = [];
  for (const [key, group] of groups) {
    const severity = maxSeverity(...group.map((g) => g.alert.severity));
    const indicators: NewIndicator[] = group.flatMap(({ alert }) => [
      ...alert.ips.map((ip) => ({ type: "IP" as const, value: ip, role: "observed_ip" })),
      ...alert.hashes.map((h) => ({ type: "FILE_HASH" as const, value: h, role: "file_sha256" })),
    ]);
    const artifacts = {
      detections: group.map(({ alert, fp }) => ({
        source: "VENDOR_ALERT" as const,
        ruleId: `${integration.vendor}:${alert.externalId ?? alert.title}`.slice(0, 200),
        title: alert.title.slice(0, 240),
        severity: alert.severity,
        fingerprint: fp,
        evidence: { tool: integration.name, description: alert.description, host: alert.host, user: alert.user, process: alert.process, commandLine: alert.commandLine, raw: alert.raw },
      })),
      timeline: group.map(({ alert }) => ({
        occurredAt: alert.timestamp,
        actor: integration.name,
        action: "vendor.alert",
        detail: `${alert.title}${alert.host ? ` on ${alert.host}` : ""}${alert.user ? ` (${alert.user})` : ""}`,
      })),
      techniques: group.flatMap(({ alert }) => alert.techniques),
      indicators,
    };
    const open = await db.case.findFirst({
      where: { sourceType: "SIEM_ALERT", sourceRef: key, tenantId: integration.tenantId, status: { notIn: CLOSED_STATUSES }, createdAt: { gte: since } },
      orderBy: { createdAt: "desc" },
      select: { id: true },
    });
    if (open) {
      await appendToCase(open.id, { ...artifacts, severity });
      caseIds.push(open.id);
      updated++;
    } else {
      const first = group[0].alert;
      const kase = await createCase({
        sourceType: "SIEM_ALERT",
        title: group.length === 1 ? first.title : `${group.length} ${tool?.vendor ?? integration.name} alerts on ${key.split(":")[1]}`,
        summary: group.map((g) => g.alert.description ?? g.alert.title).join("\n").slice(0, 2000),
        severity,
        sourceRef: key,
        tenantId: integration.tenantId,
        domain: integration.category === "identity" ? "IDENTITY" : integration.category === "email" ? "EMAIL" : integration.category === "network" ? "NETWORK" : "ENDPOINT",
        metadata: { tool: integration.name, vendor: integration.vendor, integrationId: integration.id, hostName: first.host, userName: first.user, riskObject: key.split(":").slice(1).join(":"), riskObjectType: key.split(":")[0] },
        ...artifacts,
      });
      caseIds.push(kase.id);
      created++;
    }
  }
  return { alerts: alerts.length, newAlerts: [...groups.values()].reduce((n, g) => n + g.length, 0), casesCreated: created, casesUpdated: updated, caseIds };
}

export interface IngestResult {
  received: number;
  alerts: number;
  newAlerts: number;
  telemetryEvents: number;
  inventory: number;
  casesCreated: number;
  casesUpdated: number;
}

export async function ingestForIntegration(integration: Integration, body: unknown): Promise<IngestResult> {
  const tool = await getCatalogTool(integration.vendor);
  if (!tool?.ingest) throw new Error("This tool doesn't push data");
  const config = (integration.config ?? {}) as IntegrationConfig;
  const source = (config.telemetrySource ?? getCategory(tool.category)?.telemetry ?? "endpoint") as TelemetrySource;

  const inventory = inventoryFrom(body);
  const records = inventory.length ? [] : recordsFrom(body);
  if (records.length > MAX_RECORDS) throw new Error(`At most ${MAX_RECORDS} records per request`);

  const alerts: VendorAlert[] = [];
  const telemetry: IngestItem[] = [];
  for (const record of records) {
    const mapped = mapRecord(tool.ingest, record, source);
    if (mapped.kind === "alert") alerts.push(mapped.alert);
    else telemetry.push({ source: mapped.source, data: mapped.data });
  }

  const [filed, siem, inv] = await Promise.all([
    alerts.length ? fileVendorAlerts(integration, alerts) : Promise.resolve(null),
    telemetry.length ? ingestTelemetry(telemetry, { tenantId: integration.tenantId, integrationId: integration.id, label: integration.name }) : Promise.resolve(null),
    inventory.length ? applyInventory(integration.tenantId, inventory, integration.name) : Promise.resolve(0),
  ]);

  // Alerts name hosts too: they count as seen, with this tool's controls.
  if (alerts.length) {
    await touchEndpoints(integration.tenantId, alerts.map((a) => ({ hostName: a.host, sourceIp: a.ips[0], userName: a.user })), { integrationId: integration.id });
  }

  const received = records.length + inventory.length;
  await db.integration.update({
    where: { id: integration.id },
    data: { status: "CONNECTED", lastEventAt: new Date(), eventCount: { increment: received }, lastError: null },
  });

  return {
    received,
    alerts: alerts.length,
    newAlerts: filed?.newAlerts ?? 0,
    telemetryEvents: telemetry.length,
    inventory: inv,
    casesCreated: (filed?.casesCreated ?? 0) + (siem?.casesCreated ?? 0),
    casesUpdated: (filed?.casesUpdated ?? 0) + (siem?.casesUpdated ?? 0),
  };
}
