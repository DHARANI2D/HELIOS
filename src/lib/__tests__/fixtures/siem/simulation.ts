import type { SimulationScenario } from "@/lib/siem/types";
import { collectionScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/collection";
import { commandControlScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/commandControl";
import { credentialAccessScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/credentialAccess";
import { defenseEvasionScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/defenseEvasion";
import { discoveryScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/discovery";
import { executionScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/execution";
import { exfiltrationScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/exfiltration";
import { impactScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/impact";
import { initialAccessScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/initialAccess";
import { lateralMovementScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/lateralMovement";
import { persistenceScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/persistence";
import { privilegeEscalationScenarios } from "@/lib/__tests__/fixtures/siem/scenarios/privilegeEscalation";
import { ingestTelemetry, type IngestItem } from "@/lib/siem/service";

// Ported from signal-fusion's simulation/engine.ts: 48 attack scenarios
// across 12 ATT&CK tactics, replayed through the real ingestion + detection
// path (no shortcuts), so the resulting cases are exactly what live telemetry
// with the same shape would produce.

export function allScenarios(): SimulationScenario[] {
  return [
    ...initialAccessScenarios(),
    ...executionScenarios(),
    ...persistenceScenarios(),
    ...privilegeEscalationScenarios(),
    ...defenseEvasionScenarios(),
    ...credentialAccessScenarios(),
    ...discoveryScenarios(),
    ...lateralMovementScenarios(),
    ...collectionScenarios(),
    ...exfiltrationScenarios(),
    ...commandControlScenarios(),
    ...impactScenarios(),
  ];
}

export function availableTactics(): string[] {
  return [...new Set(allScenarios().flatMap((s) => s.mitreTactics))].sort();
}

export interface SimulationConfig {
  tactics?: string[];
  scenarioIds?: string[];
  count?: number;
  intensity?: "low" | "medium" | "high";
}

export function selectScenarios(config: SimulationConfig, random: () => number = Math.random): SimulationScenario[] {
  const scenarios = allScenarios();
  if (config.scenarioIds?.length) return scenarios.filter((s) => config.scenarioIds!.includes(s.id));
  if (config.tactics?.length) return scenarios.filter((s) => s.mitreTactics.some((t) => config.tactics!.includes(t)));

  let pool = scenarios;
  if (config.intensity === "high") pool = pool.filter((s) => s.severity === "High");
  if (config.intensity === "low") pool = pool.filter((s) => s.severity !== "High");
  // Fisher–Yates (signal-fusion's sort(() => 0.5 - Math.random()) is biased).
  const shuffled = [...pool];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled.slice(0, Math.min(config.count ?? 10, shuffled.length));
}

export async function runSimulation(config: SimulationConfig, actorId?: string, tenantId: string | null = null) {
  const scenarios = selectScenarios(config);
  const items: IngestItem[] = scenarios.flatMap((s) => s.logs.map((log) => ({ source: log.source, data: log.data })));
  const summary = await ingestTelemetry(items, { actorId, tenantId, label: `simulation: ${scenarios.map((s) => s.id).join(", ")}` });
  return { scenarios: scenarios.map((s) => ({ id: s.id, name: s.name, severity: s.severity, tactics: s.mitreTactics })), summary };
}
