import type { ConnectorField } from "@/lib/connectors/types";
import type { Collector, CollectorStream } from "@/lib/collectors/types";
import { azureCollector, defenderCollector, entraCollector } from "@/lib/collectors/vendors/microsoft";
import { crowdstrikeCollector, oktaCollector, sentineloneCollector } from "@/lib/collectors/vendors/saas";
import { cloudtrailCollector, gcpCollector, workspaceCollector } from "@/lib/collectors/vendors/clouds";

// Pull collectors by the catalog tools they read from, in the order the
// roadmap ranks them: Microsoft 365 / Entra and Defender first, then the
// EDRs, the second identity stacks, and the clouds.

export const COLLECTORS: Collector[] = [entraCollector, defenderCollector, crowdstrikeCollector, sentineloneCollector, oktaCollector, workspaceCollector, cloudtrailCollector, azureCollector, gcpCollector];

export function collectorForTool(toolKey: string): Collector | undefined {
  return COLLECTORS.find((c) => c.tools.includes(toolKey));
}

export function collectorByKey(key: string | undefined | null): Collector | undefined {
  return COLLECTORS.find((c) => c.key === key);
}

export function streamByKey(key: string): { collector: Collector; stream: CollectorStream } | undefined {
  for (const collector of COLLECTORS) {
    const stream = collector.streams.find((s) => s.key === key);
    if (stream) return { collector, stream };
  }
  return undefined;
}

// What the setup screens show, safe to hand to the browser.
export interface CollectorInfo {
  key: string;
  label: string;
  fields: ConnectorField[];
  docs: string;
  streams: Array<{ key: string; label: string; permissions: string; everyMinutes: number }>;
}

export function collectorInfo(c: Collector): CollectorInfo {
  return { key: c.key, label: c.label, fields: c.fields, docs: c.docs, streams: c.streams.map((s) => ({ key: s.key, label: s.label, permissions: s.permissions, everyMinutes: Math.max(1, Math.round(s.everyMs / 60_000)) })) };
}
