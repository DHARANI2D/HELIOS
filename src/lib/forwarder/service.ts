import type { Integration, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { signFor } from "@/lib/secrets";
import { renderConfig, verifyConfig, type ForwarderOptions } from "@/lib/forwarder/config";
import type { IntegrationConfig } from "@/lib/integrations/dispatch";

// Issuing forwarder configurations and noticing which one each forwarder
// runs (the X-Helios-Config header on its requests).

const PURPOSE = "forwarder-config";
const sign = (hash: string) => signFor(PURPOSE, hash);

export type ConfigStatus = "current" | "outdated" | "unknown";

export interface ForwarderState {
  // Absent until a configuration is issued (a forwarder can report first).
  options?: ForwarderOptions;
  current?: { hash: string; issuedAt: string; issuedById: string };
  // Earlier issues, newest first: a forwarder on one of these is outdated, not foreign.
  history: Array<{ hash: string; issuedAt: string }>;
  seen?: { hash: string; at: string; status: ConfigStatus };
}

export function forwarderState(i: Pick<Integration, "config">): ForwarderState | null {
  const f = ((i.config ?? {}) as IntegrationConfig & { forwarder?: Partial<ForwarderState> }).forwarder;
  return f ? { ...f, history: f.history ?? [] } : null;
}

export function ingestUrlFor(integrationId: string, origin = process.env.AUTH_URL ?? "http://localhost:3000") {
  return `${origin.replace(/\/+$/, "")}/api/ingest/${integrationId}`;
}

export async function issueForwarderConfig(integrationId: string, options: ForwarderOptions, actor: { id: string }, origin?: string) {
  const integration = await db.integration.findUniqueOrThrow({ where: { id: integrationId }, include: { tenant: { select: { name: true } } } });
  const issuedAt = new Date();
  const issued = renderConfig(options, { ingestUrl: ingestUrlFor(integration.id, origin), label: `${integration.name}${integration.tenant ? ` (${integration.tenant.name})` : ""}`, issuedAt }, sign);
  const config = (integration.config ?? {}) as IntegrationConfig & { forwarder?: ForwarderState };
  const prev = forwarderState(integration);
  const state: ForwarderState = {
    options,
    current: { hash: issued.hash, issuedAt: issuedAt.toISOString(), issuedById: actor.id },
    history: [...(prev?.current ? [{ hash: prev.current.hash, issuedAt: prev.current.issuedAt }] : []), ...(prev?.history ?? [])].filter((h) => h.hash !== issued.hash).slice(0, 10),
    seen: prev?.seen,
  };
  await db.integration.update({ where: { id: integration.id }, data: { config: { ...config, forwarder: state } as unknown as Prisma.InputJsonValue } });
  await logAction({ actorId: actor.id, action: "forwarder.config_issued", detail: { integrationId: integration.id, hash: issued.hash, os: options.os, syslog: !!options.syslog, windowsChannels: options.windowsChannels, files: options.files.length } });
  return issued;
}

export function checkForwarderConfig(text: string) {
  return verifyConfig(text, sign);
}

export function configStatus(state: ForwarderState | null, hash: string): ConfigStatus {
  if (state?.current?.hash === hash) return "current";
  if (state?.history.some((h) => h.hash === hash)) return "outdated";
  return "unknown";
}

// Recorded at most every ten minutes per forwarder, and at once when it changes.
const recent = new Map<string, { hash: string; at: number }>();

export async function noteForwarderConfig(integration: Pick<Integration, "id" | "name" | "config" | "tenantId">, hash: string) {
  const last = recent.get(integration.id);
  if (last && last.hash === hash && Date.now() - last.at < 10 * 60_000) return;
  recent.set(integration.id, { hash, at: Date.now() });
  const state = forwarderState(integration);
  const status = configStatus(state, hash);
  const changed = state?.seen?.hash !== hash;
  const config = (integration.config ?? {}) as IntegrationConfig & { forwarder?: ForwarderState };
  const next: ForwarderState = { ...(state ?? { history: [] }), seen: { hash, at: new Date().toISOString(), status } };
  await db.integration.update({ where: { id: integration.id }, data: { config: { ...config, forwarder: next } as unknown as Prisma.InputJsonValue } });
  if (changed && status !== "current") {
    const what = status === "outdated" ? "an older configuration than the one last issued" : "a configuration HELIOS didn't issue";
    await logAction({ action: "forwarder.config_drift", detail: { integrationId: integration.id, hash, status } });
    await notify(await staffFor(["SOC_MANAGER", "DETECTION_ENGINEER"]), {
      kind: "ingest",
      title: `${integration.name}: the forwarder runs ${what}`,
      body: status === "outdated" ? "Deploy the current configuration from the integration's Forwarder tab." : "Someone may have edited it on the box. Check the file against HELIOS's signature, then redeploy.",
      href: `/integrations?open=${integration.id}`,
    });
  }
}
