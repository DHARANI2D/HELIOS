"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import type { UserRole } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requirePermission, type SessionUser } from "@/lib/session";
import { ROLE_ORDER } from "@/lib/rbac";
import { seal } from "@/lib/secrets";
import { resolveTenantInput } from "@/lib/tenants";
import { getCatalogTool } from "@/lib/integrations/tools";
import { pingConnector } from "@/lib/integrations/dispatch";
import { readSecrets, type IntegrationConfig } from "@/lib/integrations/dispatch";
import { onboardIntegration, rotateIngestToken } from "@/lib/integrations/service";

function revalidate() {
  revalidatePath("/integrations");
  revalidatePath("/endpoints");
  revalidatePath("/");
}

const ROLES = ROLE_ORDER as [UserRole, ...UserRole[]];

const onboardSchema = z.object({
  vendor: z.string(),
  tenantId: z.string().optional(),
  name: z.string().trim().max(120).optional(),
  allowedRoles: z.array(z.enum(ROLES)).max(20),
  assignedUserIds: z.array(z.string()).max(100),
  responseWebhookUrl: z.string().trim().url().optional().or(z.literal("")),
  webhookSecret: z.string().trim().max(200).optional(),
  chatWebhookUrl: z.string().trim().url().optional().or(z.literal("")),
});

async function integrationInScope(user: SessionUser, id: string) {
  const integration = await db.integration.findUniqueOrThrow({ where: { id } });
  if (user.isClient && integration.tenantId !== user.tenantId) throw new Error("Not found");
  return integration;
}

export async function onboardIntegrationAction(input: z.input<typeof onboardSchema>) {
  const user = await requirePermission("integrations.manage");
  const data = onboardSchema.parse(input);
  const tool = await getCatalogTool(data.vendor);
  if (!tool) throw new Error("Unknown tool");
  const tenantId = await resolveTenantInput(user, data.tenantId);
  // Client admins onboard tools for their own estate; SOC roles stay as chosen.
  const assigned = data.assignedUserIds.length
    ? (await db.user.findMany({ where: { id: { in: data.assignedUserIds }, active: true, OR: [{ tenantId: null }, { tenantId }] }, select: { id: true } })).map((u) => u.id)
    : [];
  const { integration, token } = await onboardIntegration(
    {
      tenantId,
      vendor: tool.key,
      name: data.name,
      allowedRoles: data.allowedRoles,
      assignedUserIds: assigned,
      config: data.responseWebhookUrl ? { responseWebhookUrl: data.responseWebhookUrl } : {},
      secrets: { webhookSecret: data.webhookSecret || undefined, chatWebhookUrl: data.chatWebhookUrl || undefined },
    },
    user.id,
  );
  revalidate();
  return { id: integration.id, token, ingestPath: `/api/ingest/${integration.id}` };
}

export async function rotateTokenAction(id: string) {
  const user = await requirePermission("integrations.manage");
  await integrationInScope(user, id);
  const token = await rotateIngestToken(id, user.id);
  revalidate();
  return { token, ingestPath: `/api/ingest/${id}` };
}

export async function setIntegrationEnabledAction(id: string, enabled: boolean) {
  const user = await requirePermission("integrations.manage");
  await integrationInScope(user, id);
  await db.integration.update({ where: { id }, data: { enabled, status: enabled ? "PENDING" : "DISCONNECTED" } });
  await logAction({ actorId: user.id, action: enabled ? "integration.enabled" : "integration.disabled", detail: { integrationId: id } });
  revalidate();
}

const accessSchema = z.object({
  allowedRoles: z.array(z.enum(ROLES)).max(20),
  assignedUserIds: z.array(z.string()).max(100),
  responseWebhookUrl: z.string().trim().url().optional().or(z.literal("")),
  webhookSecret: z.string().trim().max(200).optional(),
  chatWebhookUrl: z.string().trim().url().optional().or(z.literal("")),
});

export async function updateIntegrationAction(id: string, input: z.input<typeof accessSchema>) {
  const user = await requirePermission("integrations.manage");
  const integration = await integrationInScope(user, id);
  const data = accessSchema.parse(input);
  const config = { ...((integration.config ?? {}) as IntegrationConfig), responseWebhookUrl: data.responseWebhookUrl || undefined };
  const secrets = { ...readSecrets(integration.secretCipher) };
  if (data.webhookSecret) secrets.webhookSecret = data.webhookSecret;
  if (data.chatWebhookUrl) secrets.chatWebhookUrl = data.chatWebhookUrl;
  await db.$transaction([
    db.integrationAssignment.deleteMany({ where: { integrationId: id } }),
    db.integration.update({
      where: { id },
      data: {
        allowedRoles: data.allowedRoles,
        config: config as never,
        secretCipher: Object.keys(secrets).length ? seal(JSON.stringify(secrets)) : null,
        assignments: { create: data.assignedUserIds.map((userId) => ({ userId })) },
      },
    }),
  ]);
  await logAction({ actorId: user.id, action: "integration.updated", detail: { integrationId: id, roles: data.allowedRoles, users: data.assignedUserIds.length, connector: !!data.responseWebhookUrl } });
  revalidate();
}

// Sends a signed PING to the response connector; nothing is created.
export async function testConnectorAction(id: string) {
  const user = await requirePermission("integrations.manage");
  const integration = await integrationInScope(user, id);
  const result = await pingConnector(integration);
  await logAction({ actorId: user.id, action: "integration.connector_tested", detail: { integrationId: id, ok: !!result.ok, message: result.message } });
  revalidate();
  if (!result.dispatched) throw new Error(result.message);
  if (!result.ok) throw new Error(result.message);
  return result;
}

// ---------------------------------------------------------------- native connectors

const nativeSchema = z.object({
  on: z.boolean(),
  mode: z.enum(["live", "dry_run"]),
  values: z.record(z.string(), z.string().trim().max(2000)),
  credentialExpiresAt: z.string().trim().max(40).optional().or(z.literal("")),
});

// Set up (or switch off) the native connector for an onboarded tool. Secret
// fields left blank keep what's stored; secrets are sealed and never logged.
export async function saveNativeConnectorAction(id: string, input: z.input<typeof nativeSchema>) {
  const user = await requirePermission("integrations.manage");
  const integration = await integrationInScope(user, id);
  const data = nativeSchema.parse(input);
  const { connectorForTool } = await import("@/lib/connectors/registry");
  const connector = connectorForTool(integration.vendor);
  if (!connector) throw new Error("This tool has no native connector; use the response webhook");
  if (data.credentialExpiresAt && Number.isNaN(Date.parse(data.credentialExpiresAt))) throw new Error("Credential expiry must be a date");
  for (const f of connector.fields) {
    const v = data.values[f.key];
    if (v && /url|base|host/i.test(f.key) && !/^https:\/\//.test(v)) throw new Error(`${f.label} must start with https://`);
  }
  const config = { ...((integration.config ?? {}) as IntegrationConfig) };
  const secrets = { ...readSecrets(integration.secretCipher) };
  const plain: Record<string, string> = { ...(config.connectorConfig ?? {}) };
  const hidden: Record<string, string> = { ...(secrets.connector ?? {}) };
  for (const f of connector.fields) {
    const v = data.values[f.key];
    if (f.secret) {
      if (v) hidden[f.key] = v;
    } else plain[f.key] = v ?? "";
  }
  if (data.on) {
    config.connector = connector.key;
    config.connectorMode = data.mode;
  } else {
    delete config.connector;
  }
  config.connectorConfig = plain;
  config.credentialExpiresAt = data.credentialExpiresAt || undefined;
  secrets.connector = hidden;
  await db.integration.update({ where: { id }, data: { config: config as never, secretCipher: seal(JSON.stringify(secrets)) } });
  const { forgetToken } = await import("@/lib/connectors/http");
  forgetToken(id);
  await logAction({ actorId: user.id, action: "integration.native_connector_saved", detail: { integrationId: id, connector: connector.key, on: data.on, mode: data.mode, fields: Object.keys(plain), secretsSet: Object.keys(hidden) } });
  revalidate();
}

// Signs in with the connector's credentials and reads something harmless.
export async function testNativeConnectorAction(id: string) {
  const user = await requirePermission("integrations.manage");
  const integration = await integrationInScope(user, id);
  const { checkNative } = await import("@/lib/connectors/run");
  const result = await checkNative(integration);
  await logAction({ actorId: user.id, action: "integration.native_connector_tested", detail: { integrationId: id, ok: result.ok, message: result.message.slice(0, 300) } });
  revalidate();
  return result;
}
