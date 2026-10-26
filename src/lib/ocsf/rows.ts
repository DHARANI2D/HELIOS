import type { Prisma } from "@prisma/client";

import { columnsFromOcsf, ocsfFromColumns, type EventColumns } from "@/lib/ocsf/columns";
import type { OcsfEvent } from "@/lib/ocsf/schema";

// A SecurityEvent row with both forms. `unmapped` isn't stored twice: it is
// the row's metadata, and storedOcsf() puts it back.

type Placement = Pick<Prisma.SecurityEventCreateManyInput, "batchId" | "tenantId" | "integrationId" | "caseId">;

const json = (v: unknown) => JSON.parse(JSON.stringify(v)) as Prisma.InputJsonValue;

function withoutUnmapped(ev: OcsfEvent) {
  const { unmapped: _unmapped, ...rest } = ev;
  return rest;
}

export function rowFromOcsf(ev: OcsfEvent, placement: Placement = {}): Prisma.SecurityEventCreateManyInput {
  const { classUid, sourceEventId, metadata, ...cols } = columnsFromOcsf(ev);
  return {
    ...placement,
    ...cols,
    commandLine: cols.commandLine ?? undefined,
    metadata: json(metadata ?? {}),
    classUid,
    sourceEventId: sourceEventId?.slice(0, 200),
    ocsf: json(withoutUnmapped(ev)),
  };
}

export function rowFromColumns(cols: EventColumns, placement: Placement = {}, sourceEventId?: string | null): Prisma.SecurityEventCreateManyInput {
  const ev = ocsfFromColumns(cols, sourceEventId);
  return {
    ...placement,
    ...cols,
    metadata: json(cols.metadata ?? {}),
    classUid: ev.class_uid,
    sourceEventId: sourceEventId?.slice(0, 200) ?? undefined,
    ocsf: json(withoutUnmapped(ev)),
  };
}

// The full OCSF event for a stored row.
export function storedOcsf(row: { ocsf: Prisma.JsonValue; metadata: Prisma.JsonValue }): OcsfEvent | null {
  if (!row.ocsf || typeof row.ocsf !== "object" || Array.isArray(row.ocsf)) return null;
  const unmapped = row.metadata && typeof row.metadata === "object" && !Array.isArray(row.metadata) ? (row.metadata as Record<string, unknown>) : undefined;
  return { ...(row.ocsf as unknown as OcsfEvent), ...(unmapped && Object.keys(unmapped).length ? { unmapped } : {}) };
}
