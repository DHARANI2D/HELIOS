import type { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { getCatalogTool } from "@/lib/integrations/tools";
import { dispatchAction } from "@/lib/integrations/dispatch";
import { CONTROL_KEYS, parseProtections, type ControlStatus, type EndpointProtections, type ProtectionControl } from "@/lib/endpoints/controls";
import type { InventoryRecord } from "@/lib/integrations/mappers";
import { isDeviceControl } from "@/lib/assets/capabilities";

// The endpoint inventory builds itself: every host seen in telemetry gets a
// row, a tool that reports through its integration marks the protection
// controls it provides as active on that host, and tools can push a full
// inventory (OS, owner, control status) to the same ingest endpoint.

const MAX_HOSTS_PER_BATCH = 500;

async function findEndpoint(tenantId: string | null, hostname: string) {
  return db.endpoint.findFirst({ where: { tenantId, hostname: { equals: hostname, mode: "insensitive" } } });
}

function withControls(current: Prisma.JsonValue | null, controls: ProtectionControl[], product: string, status: ControlStatus = "active"): EndpointProtections {
  const next = parseProtections(current);
  const now = new Date().toISOString();
  for (const c of controls) next[c] = { status, product, updatedAt: now };
  return next;
}

export async function touchEndpoints(
  tenantId: string | null,
  rows: Array<{ hostName?: string | null; sourceIp?: string | null; userName?: string | null }>,
  options: { integrationId?: string } = {},
) {
  const hosts = new Map<string, { ip?: string; user?: string }>();
  for (const r of rows) {
    const h = r.hostName?.trim();
    if (!h || h === "unknown" || hosts.size >= MAX_HOSTS_PER_BATCH) continue;
    if (!hosts.has(h)) hosts.set(h, { ip: r.sourceIp ?? undefined, user: r.userName ?? undefined });
  }
  if (hosts.size === 0) return 0;

  const integration = options.integrationId ? await db.integration.findUnique({ where: { id: options.integrationId }, select: { vendor: true, name: true } }) : null;
  const tool = integration ? await getCatalogTool(integration.vendor) : undefined;
  const now = new Date();

  for (const [hostname, info] of hosts) {
    const existing = await findEndpoint(tenantId, hostname);
    const deviceControls = (tool?.controls ?? []).filter(isDeviceControl);
    const protections = deviceControls.length ? withControls(existing?.protections ?? null, deviceControls, integration!.name) : undefined;
    if (existing) {
      await db.endpoint.update({
        where: { id: existing.id },
        data: { lastSeenAt: now, ...(protections ? { protections: protections as Prisma.InputJsonValue } : {}), ...(existing.ipAddress ? {} : info.ip ? { ipAddress: info.ip } : {}) },
      });
    } else {
      await db.endpoint.create({
        data: {
          tenantId,
          hostname,
          ipAddress: info.ip,
          owner: info.user,
          lastSeenAt: now,
          source: tool ? "integration" : "telemetry",
          protections: protections as Prisma.InputJsonValue | undefined,
        },
      });
    }
  }
  return hosts.size;
}

const STATUS_ALIASES: Record<string, ControlStatus> = {
  active: "active",
  on: "active",
  enabled: "active",
  healthy: "active",
  ok: "active",
  true: "active",
  degraded: "degraded",
  outdated: "degraded",
  warning: "degraded",
  missing: "missing",
  off: "missing",
  disabled: "missing",
  false: "missing",
};

export async function applyInventory(tenantId: string | null, records: InventoryRecord[], product: string) {
  let count = 0;
  for (const r of records.slice(0, 5000)) {
    const existing = await findEndpoint(tenantId, r.hostname);
    const protections = parseProtections(existing?.protections ?? null);
    const now = new Date().toISOString();
    for (const [key, value] of Object.entries(r.controls ?? {})) {
      const status = STATUS_ALIASES[String(value).toLowerCase()];
      if (status && (CONTROL_KEYS as string[]).includes(key)) protections[key as ProtectionControl] = { status, product, updatedAt: now };
    }
    const data = {
      os: r.os ?? existing?.os ?? undefined,
      ipAddress: r.ipAddress ?? existing?.ipAddress ?? undefined,
      owner: r.owner ?? existing?.owner ?? undefined,
      criticality: r.criticality && ["standard", "high", "critical"].includes(r.criticality) ? r.criticality : existing?.criticality ?? "standard",
      protections: protections as Prisma.InputJsonValue,
      lastSeenAt: new Date(),
    };
    if (existing) await db.endpoint.update({ where: { id: existing.id }, data });
    else await db.endpoint.create({ data: { ...data, tenantId, hostname: r.hostname, source: "integration" } });
    count++;
  }
  return count;
}

// Direct isolation from the endpoint inventory (no case): same connector
// path as case containment, recorded in the audit chain.
export async function setEndpointIsolated(endpointId: string, isolate: boolean, actor: { id: string; name: string }) {
  const endpoint = await db.endpoint.findUniqueOrThrow({ where: { id: endpointId } });
  const result = await dispatchAction({ tenantId: endpoint.tenantId, actionType: isolate ? "ISOLATE_HOST" : "RELEASE_HOST", target: endpoint.hostname, caseRef: null });
  if (result.dispatched && !result.ok) throw new Error(result.message);
  await db.endpoint.update({
    where: { id: endpointId },
    data: isolate ? { isolated: true, isolatedAt: new Date(), isolatedBy: actor.name } : { isolated: false, isolatedAt: null, isolatedBy: null },
  });
  await logAction({ actorId: actor.id, action: isolate ? "endpoint.isolated" : "endpoint.released", detail: { endpointId, hostname: endpoint.hostname, tenantId: endpoint.tenantId, connector: result.message, manual: !result.dispatched } });
  return result;
}

// CSV import: hostname,os,ip,owner,criticality[,control=status;...]
export function parseInventoryCsv(text: string): InventoryRecord[] {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return [];
  const header = lines[0].toLowerCase().split(",").map((h) => h.trim());
  const hasHeader = header.includes("hostname");
  const cols = hasHeader ? header : ["hostname", "os", "ip", "owner", "criticality", "controls"];
  return (hasHeader ? lines.slice(1) : lines).map((line) => {
    const cells = line.split(",").map((c) => c.trim());
    const get = (name: string) => {
      const i = cols.indexOf(name);
      return i >= 0 ? cells[i] || undefined : undefined;
    };
    const controls: Record<string, string> = {};
    for (const pair of (get("controls") ?? "").split(";")) {
      const [k, v] = pair.split("=").map((x) => x?.trim());
      if (k && v) controls[k] = v;
    }
    return { hostname: get("hostname") ?? "", os: get("os"), ipAddress: get("ip"), owner: get("owner"), criticality: get("criticality")?.toLowerCase(), controls };
  }).filter((r) => r.hostname);
}
