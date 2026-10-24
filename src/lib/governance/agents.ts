import { db } from "@/lib/db";
import { generateAgentIdentity } from "@/lib/governance/identity";
import { hashToken, newToken } from "@/lib/secrets";
import { logAction } from "@/lib/audit";

// Governed AI agents: an Ed25519 identity plus the API token the agent uses
// to ask POST /api/governance/evaluate before acting. The token is shown
// once; only its hash is stored.

export async function issueAgentIdentity(name: string, actorId?: string, tenantId: string | null = null) {
  if (await db.agent.findUnique({ where: { name } })) throw new Error(`An agent named "${name}" already exists`);
  const { publicKeyB64 } = generateAgentIdentity();
  const { token, hash, display } = newToken("hga");
  const agent = await db.agent.create({
    data: { name, tenantId, publicKey: publicKeyB64, trust: 100, level: 10, status: "ACTIVE", mode: "FULL_ACCESS", apiTokenHash: hash, tokenPrefix: display },
  });
  await logAction({ actorId, action: "governance.identity_issued", detail: { agentId: agent.id, name, tenantId } });
  return { agent, token };
}

export async function rotateAgentToken(agentId: string, actorId?: string) {
  const { token, hash, display } = newToken("hga");
  const agent = await db.agent.update({ where: { id: agentId }, data: { apiTokenHash: hash, tokenPrefix: display } });
  await logAction({ actorId, action: "governance.token_rotated", detail: { agentId, name: agent.name } });
  return { agent, token };
}

export async function agentForToken(authorization: string | null) {
  const token = authorization?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (!token?.startsWith("hga_")) return null;
  return db.agent.findUnique({ where: { apiTokenHash: hashToken(token) } });
}

// Revokes every agent in a client (all clients when tenantId is null).
export async function globalPurge(actorId?: string, tenantId?: string | null) {
  const agents = await db.agent.updateManyAndReturn({
    where: tenantId ? { tenantId } : {},
    data: { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" },
  });
  await logAction({ actorId, action: "governance.global_purge", detail: { affectedAgents: agents.length, tenantId: tenantId ?? "all" } });
  return agents.length;
}
