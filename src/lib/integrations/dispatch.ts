import { createHmac } from "node:crypto";
import type { Integration, PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { unseal } from "@/lib/secrets";
import { getCatalogTool } from "@/lib/integrations/tools";

// Response connectors: an onboarded tool with a responseWebhookUrl carries out
// the containment actions its catalog entry supports. HELIOS POSTs a signed
// JSON request; the receiving automation (the vendor's API through n8n /
// Tines / a script, or a SOAR) does the work and answers 2xx. Without a
// connector the action is left for an analyst to carry out by hand
// (MANUAL_REQUIRED) — never pretended done, never silently dropped.

export interface DispatchResult {
  dispatched: boolean;
  integration?: string;
  ok?: boolean;
  message: string;
}

export interface IntegrationConfig {
  responseWebhookUrl?: string;
  telemetrySource?: string;
  notes?: string;
}

export interface IntegrationSecrets {
  // HMAC key for signing response-connector requests.
  webhookSecret?: string;
  // Incoming webhook for chat tools (Slack, Teams); it embeds a credential.
  chatWebhookUrl?: string;
  apiKey?: string;
}

export function readSecrets(cipher: string | null): IntegrationSecrets {
  if (!cipher) return {};
  try {
    return JSON.parse(unseal(cipher)) as IntegrationSecrets;
  } catch {
    return {};
  }
}

export function signPayload(secret: string, timestamp: string, body: string) {
  return `sha256=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

export async function findConnector(tenantId: string | null, actionType: PlaybookActionType) {
  const candidates = await db.integration.findMany({
    where: { tenantId, enabled: true, status: { not: "DISCONNECTED" } },
    orderBy: { createdAt: "asc" },
  });
  for (const i of candidates) {
    const tool = await getCatalogTool(i.vendor);
    const config = (i.config ?? {}) as IntegrationConfig;
    if (tool?.actions.includes(actionType) && config.responseWebhookUrl) return i;
  }
  return undefined;
}

export async function dispatchAction(input: {
  tenantId: string | null;
  actionType: PlaybookActionType;
  target: string;
  caseRef: { id: string; title: string; severity: string } | null;
  requestId?: string;
}): Promise<DispatchResult> {
  const connector = await findConnector(input.tenantId, input.actionType);
  if (!connector) return { dispatched: false, message: "no response connector configured" };

  return postSigned(connector, {
    id: input.requestId,
    action: input.actionType,
    target: input.target,
    tool: connector.vendor,
    case: input.caseRef,
    requestedAt: new Date().toISOString(),
  });
}

// A signed no-op the receiving automation should acknowledge with 2xx: proves
// the URL, the network path and the signature check without acting on
// anything.
export async function pingConnector(connector: Integration): Promise<DispatchResult> {
  const config = (connector.config ?? {}) as IntegrationConfig;
  if (!config.responseWebhookUrl) return { dispatched: false, message: "no response webhook set on this integration" };
  const result = await postSigned(connector, { action: "PING", tool: connector.vendor, requestedAt: new Date().toISOString() });
  if (result.ok) await db.integration.update({ where: { id: connector.id }, data: { status: "CONNECTED", lastError: null } });
  return result;
}

async function postSigned(connector: Integration, payload: Record<string, unknown>): Promise<DispatchResult> {
  const config = (connector.config ?? {}) as IntegrationConfig;
  const { webhookSecret } = readSecrets(connector.secretCipher);
  const body = JSON.stringify(payload);
  const timestamp = String(Math.floor(Date.now() / 1000));
  try {
    const res = await fetch(config.responseWebhookUrl!, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-helios-timestamp": timestamp,
        ...(webhookSecret ? { "x-helios-signature": signPayload(webhookSecret, timestamp, body) } : {}),
      },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    const text = (await res.text()).slice(0, 300);
    if (!res.ok) {
      await db.integration.update({ where: { id: connector.id }, data: { status: "DEGRADED", lastError: `Response webhook HTTP ${res.status}` } });
      return { dispatched: true, integration: connector.name, ok: false, message: `${connector.name} returned HTTP ${res.status}${text ? `: ${text}` : ""}` };
    }
    return { dispatched: true, integration: connector.name, ok: true, message: `sent to ${connector.name}` };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await db.integration.update({ where: { id: connector.id }, data: { status: "DEGRADED", lastError: message } });
    return { dispatched: true, integration: connector.name, ok: false, message: `${connector.name} unreachable: ${message}` };
  }
}
