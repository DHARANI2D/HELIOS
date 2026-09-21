import { db } from "@/lib/db";
import { generateAgentIdentity } from "@/lib/governance/identity";
import { logAction } from "@/lib/audit";

export async function issueAgentIdentity(name: string, actorId?: string) {
  const { publicKeyB64 } = generateAgentIdentity();

  const agent = await db.agent.upsert({
    where: { name },
    update: { publicKey: publicKeyB64, status: "ACTIVE", trust: 100, level: 10 },
    create: {
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
    action: "governance.identity_issued",
    detail: { agentId: agent.id, name },
  });

  return agent;
}
