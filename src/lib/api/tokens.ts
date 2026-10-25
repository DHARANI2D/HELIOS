import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { hashToken, newToken } from "@/lib/secrets";
import { can, isClientRole } from "@/lib/rbac";
import type { SessionUser } from "@/lib/session";

// Personal access tokens for /api/v1. The token string is shown once; only
// its SHA-256 hash is kept. A token acts as its owner, so it can never see
// or do more than the owner can in the app.

export const API_TOKEN_PREFIX = "hpat";
const MAX_TOKENS_PER_USER = 20;

export async function issueApiToken(user: SessionUser, input: { name: string; canWrite: boolean; expiresInDays: number | null }) {
  if ((await db.apiToken.count({ where: { userId: user.id, revokedAt: null } })) >= MAX_TOKENS_PER_USER) {
    throw new Error(`At most ${MAX_TOKENS_PER_USER} active tokens per account — revoke one first`);
  }
  const { token, hash } = newToken(API_TOKEN_PREFIX);
  const record = await db.apiToken.create({
    data: {
      name: input.name,
      userId: user.id,
      tokenHash: hash,
      prefix: token.slice(0, API_TOKEN_PREFIX.length + 7),
      canWrite: input.canWrite,
      expiresAt: input.expiresInDays ? new Date(Date.now() + input.expiresInDays * 86_400_000) : null,
    },
  });
  await logAction({ actorId: user.id, action: "api.token_issued", detail: { tokenId: record.id, name: input.name, canWrite: input.canWrite, expiresAt: record.expiresAt } });
  return { token, record };
}

// Owners revoke their own tokens; a platform admin can revoke anyone's.
export async function revokeApiToken(user: SessionUser, tokenId: string) {
  const token = await db.apiToken.findUnique({ where: { id: tokenId } });
  if (!token || (token.userId !== user.id && user.role !== "ADMIN")) throw new Error("Token not found");
  if (token.revokedAt) return;
  await db.apiToken.update({ where: { id: tokenId }, data: { revokedAt: new Date() } });
  await logAction({ actorId: user.id, action: "api.token_revoked", detail: { tokenId, owner: token.userId } });
}

export interface ApiPrincipal extends SessionUser {
  tokenId: string;
  canWrite: boolean;
}

const LAST_USED_RESOLUTION_MS = 60_000;

export async function principalForToken(authorization: string | null): Promise<ApiPrincipal | null> {
  const token = authorization?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (!token?.startsWith(`${API_TOKEN_PREFIX}_`)) return null;
  const record = await db.apiToken.findUnique({
    where: { tokenHash: hashToken(token) },
    include: { user: { select: { id: true, role: true, name: true, email: true, active: true, tenantId: true, domains: true, tenant: { select: { name: true, status: true } } } } },
  });
  if (!record || record.revokedAt || (record.expiresAt && record.expiresAt < new Date())) return null;
  const u = record.user;
  if (!u.active || u.tenant?.status === "SUSPENDED") return null;
  if (!record.lastUsedAt || Date.now() - record.lastUsedAt.getTime() > LAST_USED_RESOLUTION_MS) {
    await db.apiToken.update({ where: { id: record.id }, data: { lastUsedAt: new Date() } });
  }
  const principal: ApiPrincipal = {
    id: u.id,
    role: u.role,
    name: u.name,
    email: u.email,
    tenantId: u.tenantId,
    tenantName: u.tenant?.name ?? null,
    domains: u.domains,
    isClient: isClientRole(u.role),
    tokenId: record.id,
    canWrite: record.canWrite,
  };
  return can(principal, "api.tokens") ? principal : null;
}
