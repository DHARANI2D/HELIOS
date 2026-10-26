import type { Integration, PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { ConnectorError, createHttp, type Http } from "@/lib/connectors/http";
import { connectorByKey } from "@/lib/connectors/registry";
import type { ConnectorCtx, NativeConnector, VendorRef, Verification } from "@/lib/connectors/types";
import { readSecrets, type IntegrationConfig } from "@/lib/integrations/dispatch";

// Running a native connector for one action: preflight, then (unless the
// target is already in that state, or the connector is in dry-run mode)
// execute with the response action's id as the idempotency key, then one
// immediate verification. Anything not yet confirmed comes back pending and
// the verification job (lib/connectors/verify) keeps checking.

export interface NativeResult {
  dispatched: true;
  integration: string;
  integrationId: string;
  native: string;
  ok: boolean;
  pending?: boolean;
  dryRun?: boolean;
  ref?: VendorRef;
  message: string;
}

// The native connector set up on an integration, or null; with what's
// missing when it's chosen but incomplete.
export async function nativeSetup(i: Pick<Integration, "config" | "secretCipher">): Promise<{ connector: NativeConnector; missing: string[]; dryRun: boolean } | null> {
  const config = (i.config ?? {}) as IntegrationConfig;
  const connector = connectorByKey(config.connector);
  if (!connector) return null;
  const values = { ...(config.connectorConfig ?? {}), ...((await readSecrets(i.secretCipher)).connector ?? {}) };
  const missing = connector.fields.filter((f) => f.required && !values[f.key]).map((f) => f.label);
  return { connector, missing, dryRun: config.connectorMode === "dry_run" };
}

export async function contextFor(i: Pick<Integration, "id" | "config" | "secretCipher">, http: Http = createHttp()): Promise<ConnectorCtx> {
  const config = (i.config ?? {}) as IntegrationConfig;
  return { config: config.connectorConfig ?? {}, secrets: (await readSecrets(i.secretCipher)).connector ?? {}, http, cacheKey: i.id };
}

export async function findNativeConnector(tenantId: string | null, actionType: PlaybookActionType) {
  const candidates = await db.integration.findMany({ where: { tenantId, enabled: true, status: { not: "DISCONNECTED" } }, orderBy: { createdAt: "asc" } });
  for (const integration of candidates) {
    const setup = await nativeSetup(integration);
    if (setup && !setup.missing.length && setup.connector.actions.includes(actionType)) return { integration, ...setup };
  }
  return undefined;
}

async function health(i: Integration, ok: boolean, error?: string) {
  await db.integration.update({ where: { id: i.id }, data: ok ? { status: "CONNECTED", lastError: null } : { status: "DEGRADED", lastError: error?.slice(0, 500) } });
}

export async function runNative(
  integration: Integration,
  connector: NativeConnector,
  req: { action: PlaybookActionType; target: string; idempotencyKey: string; comment: string; dryRun?: boolean },
  http?: Http,
): Promise<NativeResult> {
  const ctx = await contextFor(integration, http);
  const base = { dispatched: true as const, integration: integration.name, integrationId: integration.id, native: connector.key };
  const request = { ...req, ctx };
  try {
    const pre = await connector.preflight(request);
    // A target that doesn't exist is the target's problem, not the connector's.
    if (!pre.ok) return { ...base, ok: false, message: `${connector.label}: ${pre.reason}` };
    if (pre.alreadyDone) {
      await health(integration, true);
      return { ...base, ok: true, ref: { resolvedId: pre.resolved.id }, message: `${connector.label} already shows ${pre.resolved.name} in that state` };
    }
    if (req.dryRun) return { ...base, ok: false, dryRun: true, message: `Dry run: ${connector.label} would act on ${pre.resolved.name} (${pre.resolved.id}${pre.resolved.state ? `, now ${pre.resolved.state}` : ""}); nothing was changed` };
    const done = await connector.execute(request, pre.resolved);
    const check = done.confirmed ? { state: "confirmed" as const, message: done.message } : await connector.verify(request, done.ref);
    await health(integration, true);
    if (check.state === "failed") return { ...base, ok: false, ref: done.ref, message: `${done.message}, but ${check.message}` };
    return { ...base, ok: true, pending: check.state === "pending", ref: done.ref, message: check.state === "pending" ? `${done.message}; ${check.message}` : `${done.message}; ${check.message}` };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await health(integration, false, message);
    return { ...base, ok: false, message: `${connector.label}: ${message}` };
  }
}

export async function verifyNative(integrationId: string, action: PlaybookActionType, ref: VendorRef, http?: Http): Promise<Verification> {
  const integration = await db.integration.findUnique({ where: { id: integrationId } });
  const setup = integration && (await nativeSetup(integration));
  if (!integration || !setup) return { state: "failed", message: "The connector that carried this out is gone" };
  try {
    return await setup.connector.verify({ action, target: "", ctx: await contextFor(integration, http) }, ref);
  } catch (err) {
    // A failed check isn't a failed action: try again on the next round.
    return { state: "pending", message: err instanceof ConnectorError ? err.message : String(err) };
  }
}

export async function checkNative(integration: Integration, http?: Http) {
  const setup = await nativeSetup(integration);
  if (!setup) return { ok: false, message: "No native connector chosen for this tool" };
  if (setup.missing.length) return { ok: false, message: `Missing: ${setup.missing.join(", ")}` };
  try {
    const result = await setup.connector.check(await contextFor(integration, http));
    await health(integration, result.ok, result.ok ? undefined : result.message);
    return result;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await health(integration, false, message);
    return { ok: false, message };
  }
}
