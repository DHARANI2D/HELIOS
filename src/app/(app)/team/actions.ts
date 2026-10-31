"use server";

import { randomBytes } from "node:crypto";
import { revalidatePath } from "next/cache";
import bcrypt from "bcryptjs";
import { z } from "zod";
import type { SecurityDomain, UserRole } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requirePermission } from "@/lib/session";
import { ROLE_ORDER, SECURITY_DOMAINS, isClientRole } from "@/lib/rbac";
import { action } from "@/lib/action";

const ROLES = ROLE_ORDER as [UserRole, ...UserRole[]];
const DOMAINS = SECURITY_DOMAINS as [SecurityDomain, ...SecurityDomain[]];

function tempPassword() {
  // Unambiguous characters; 14 of them ≈ 80 bits.
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  return [...randomBytes(14)].map((b) => alphabet[b % alphabet.length]).join("");
}

const userSchema = z.object({
  name: z.string().trim().min(2).max(120),
  email: z.string().trim().toLowerCase().email().max(200),
  role: z.enum(ROLES),
  tenantId: z.string().nullable(),
  domains: z.array(z.enum(DOMAINS)).max(6),
  title: z.string().trim().max(120).optional(),
});

async function validTenant(role: UserRole, tenantId: string | null) {
  if (isClientRole(role)) {
    if (!tenantId) throw new Error("Client roles must belong to a client");
    await db.tenant.findUniqueOrThrow({ where: { id: tenantId } });
    return tenantId;
  }
  return null;
}

export const inviteUserAction = action(async function inviteUserAction(input: z.input<typeof userSchema>) {
  const admin = await requirePermission("users.manage");
  const data = userSchema.parse(input);
  if (await db.user.findUnique({ where: { email: data.email } })) throw new Error("A user with that email already exists");
  const password = tempPassword();
  const user = await db.user.create({
    data: {
      name: data.name,
      email: data.email,
      role: data.role,
      tenantId: await validTenant(data.role, data.tenantId),
      domains: isClientRole(data.role) ? [] : data.domains,
      title: data.title || null,
      passwordHash: await bcrypt.hash(password, 10),
    },
  });
  await logAction({ actorId: admin.id, action: "user.invited", detail: { userId: user.id, email: user.email, role: user.role, tenantId: user.tenantId } });
  revalidatePath("/team");
  return { email: user.email, password };
});

export const updateUserAction = action(async function updateUserAction(userId: string, input: Omit<z.input<typeof userSchema>, "email">) {
  const admin = await requirePermission("users.manage");
  const data = userSchema.omit({ email: true }).parse(input);
  if (userId === admin.id && data.role !== admin.role) throw new Error("You can't change your own role — ask another admin");
  const before = await db.user.findUniqueOrThrow({ where: { id: userId }, select: { role: true, tenantId: true, domains: true } });
  await db.user.update({
    where: { id: userId },
    data: { name: data.name, role: data.role, tenantId: await validTenant(data.role, data.tenantId), domains: isClientRole(data.role) ? [] : data.domains, title: data.title || null },
  });
  await logAction({ actorId: admin.id, action: "user.updated", detail: { userId, from: before, to: { role: data.role, tenantId: data.tenantId, domains: data.domains } } });
  revalidatePath("/team");
});

export const setUserActiveAction = action(async function setUserActiveAction(userId: string, active: boolean) {
  const admin = await requirePermission("users.manage");
  if (userId === admin.id && !active) throw new Error("You can't deactivate yourself");
  await db.user.update({ where: { id: userId }, data: { active, ...(active ? { failedLogins: 0, lockedUntil: null } : {}) } });
  // Deactivation also ends their sessions: requireUser re-reads `active`.
  await logAction({ actorId: admin.id, action: active ? "user.reactivated" : "user.deactivated", detail: { userId } });
  revalidatePath("/team");
});

export const resetPasswordAction = action(async function resetPasswordAction(userId: string) {
  const admin = await requirePermission("users.manage");
  const password = tempPassword();
  const user = await db.user.update({ where: { id: userId }, data: { passwordHash: await bcrypt.hash(password, 10), failedLogins: 0, lockedUntil: null } });
  await logAction({ actorId: admin.id, action: "user.password_reset", detail: { userId } });
  revalidatePath("/team");
  return { email: user.email, password };
});

// For a lost phone: turns two-step sign-in off for the account, which then
// sets it up again at its next sign-in if the organization requires it.
export const resetMfaAction = action(async function resetMfaAction(userId: string) {
  const admin = await requirePermission("users.manage");
  if (userId === admin.id) throw new Error("Ask another admin to reset your own two-step sign-in");
  await db.user.update({ where: { id: userId }, data: { mfaEnabledAt: null, mfaSecretCipher: null, mfaRecoveryHashes: [], mfaLastStep: null } });
  await logAction({ actorId: admin.id, action: "auth.mfa_reset", detail: { userId } });
  revalidatePath("/team");
});
