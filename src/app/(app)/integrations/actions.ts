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
import { getTool } from "@/lib/integrations/catalog";
import { readSecrets, type IntegrationConfig } from "@/lib/integrations/dispatch";
import { ingestForIntegration, onboardIntegration, rotateIngestToken } from "@/lib/integrations/service";
import { samplePayloadFor } from "@/lib/integrations/samples";

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
  const tool = getTool(data.vendor);
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

// Pushes the tool's sample payload through the real ingest path — proves the
// mapping and shows what its alerts look like as cases.
export async function sendTestEventAction(id: string) {
  const user = await requirePermission("integrations.manage");
  const integration = await integrationInScope(user, id);
  const sample = samplePayloadFor(integration.vendor);
  if (!sample) throw new Error("This tool doesn't push data");
  const result = await ingestForIntegration(integration, sample);
  await logAction({ actorId: user.id, action: "integration.test_event", detail: { integrationId: id, ...result } });
  revalidate();
  revalidatePath("/cases");
  return result;
}
