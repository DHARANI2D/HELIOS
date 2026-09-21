import { db } from "@/lib/db";

// Ported from aegis's governance/trust.py AdaptiveTrustEngine. Fixes the
// original's `trust` vs `trust_score` field-name bug (the Agent model field
// is `trust`; the Python engine and identity module read/wrote
// `trust_score`, which never actually persisted).

const DECAY_RATE = 0.05; // points per minute
const INITIAL_TRUST = 100;

export async function getDecayedTrust(agentId: string): Promise<number> {
  const agent = await db.agent.findUniqueOrThrow({ where: { id: agentId } });

  const elapsedMinutes =
    (Date.now() - agent.lastUpdateAt.getTime()) / 1000 / 60;
  const decay = elapsedMinutes * DECAY_RATE;
  const newTrust = Math.max(0, agent.trust - decay);

  const updated = await db.agent.update({
    where: { id: agentId },
    data: { trust: newTrust },
  });

  return Math.round(updated.trust * 100) / 100;
}

export async function applyPenalty(agentId: string, points: number) {
  const agent = await db.agent.findUniqueOrThrow({ where: { id: agentId } });
  return db.agent.update({
    where: { id: agentId },
    data: { trust: Math.max(0, agent.trust - points) },
  });
}

export async function boostTrust(agentId: string, points: number) {
  const agent = await db.agent.findUniqueOrThrow({ where: { id: agentId } });
  return db.agent.update({
    where: { id: agentId },
    data: { trust: Math.min(INITIAL_TRUST, agent.trust + points) },
  });
}
