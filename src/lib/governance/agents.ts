import { db } from "@/lib/db";
import { generateAgentIdentity } from "@/lib/governance/identity";
import { logAction } from "@/lib/audit";

export async function issueAgentIdentity(name: string, organizationId: string | null, actorId?: string) {
  const { publicKeyB64 } = generateAgentIdentity();

  const existing = await db.agent.findFirst({ where: { name, organizationId } });
  const agent = existing
    ? await db.agent.update({
        where: { id: existing.id },
        data: { publicKey: publicKeyB64, status: "ACTIVE", trust: 100, level: 10 },
      })
    : await db.agent.create({
        data: {
          organizationId,
          name,
          publicKey: publicKeyB64,
          trust: 100,
          level: 10,
          status: "ACTIVE",
          mode: "FULL_ACCESS",
        },
      });

  await logAction({
    actorId,
    organizationId,
    action: "governance.identity_issued",
    detail: { agentId: agent.id, name },
  });

  return agent;
}
