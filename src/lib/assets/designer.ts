import { toolLabel, type ToolDefinition } from "@/lib/integrations/catalog";
import { PLATFORM_CAPABILITIES, PLATFORM_LABEL, capabilityName, type Capability } from "@/lib/assets/capabilities";
import { COMPANY_TYPES, DELIVERY, ENVIRONMENTS, INDUSTRIES, MATURITY, usersBracket } from "@/lib/assets/estate";
import { ASSET_CLASSES, type AssetClass, type AssetClassInfo, type Priority } from "@/lib/assets/surface";
import { surfaceCoverage } from "@/lib/assets/coverage";
import { ACTION_LABEL } from "@/lib/response/labels";
import { normalizeConfig, stackTools, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";
import { adviseStack, type Advice, type AdviceAudience, type AdvisorGoal } from "@/lib/pricing/advisor";

// "Design my cybersecurity solution": turns the organization's answers and
// its attack surface into a company-wide design. For every asset group it
// has: its priority, what to deploy (already in place, suggested, or still a
// gap), the telemetry to collect, what gets detected and how the SOC
// responds; then the central architecture those groups feed and a phased
// rollout in priority order. The tool suggestions are the stack advisor's.
// Pure; platform facts (detector and ATT&CK counts) come in from the server.

export interface PlatformFacts {
  detectors: number;
  techniques: number;
  tactics: number;
  playbooks: number;
}

export type DeployStatus = "in-place" | "suggested" | "gap";

export interface DeployItem {
  capability: Capability;
  required: boolean;
  status: DeployStatus;
  by: string[];
}

export interface GroupDesign {
  info: AssetClassInfo;
  priority: Priority;
  reasons: string[];
  describe: string;
  inScope: boolean; // within what is being delivered
  deploy: DeployItem[];
}

export interface SolutionDesign {
  title: string;
  profile: Array<{ label: string; value: string }>;
  groups: GroupDesign[];
  notCounted: AssetClassInfo[];
  architecture: Array<{ layer: string; items: string[] }>;
  phases: Array<{ phase: number; title: string; items: string[] }>;
  guidance: string[];
  advice: Advice;
  coverageBefore: number;
  coverageAfter: number;
}

// What "endpoint security deployment" covers; everything else is later.
const EDR_SCOPE: AssetClass[] = ["user", "mobile", "server"];

export function designSolution(input: QuoteConfig, ctx: PricingContext, goal: AdvisorGoal, audience: AdviceAudience, facts: PlatformFacts | null): SolutionDesign {
  const cfg = normalizeConfig(input);
  const c = cfg.context;
  const advice = adviseStack(cfg, ctx, goal, audience);
  const before = surfaceCoverage(cfg, ctx);
  const after = surfaceCoverage(advice.config, ctx);
  const your = audience === "public" ? "your" : "the client's";

  const current = new Map<Capability, string[]>();
  const add = (m: Map<Capability, string[]>, cap: Capability, by: string) => m.set(cap, [...new Set([...(m.get(cap) ?? []), by])]);
  for (const { tool, own } of stackTools(cfg, ctx)) for (const cap of tool.controls) add(current, cap, own ? `${toolLabel(tool)} (${audience === "public" ? "yours" : "client's"})` : toolLabel(tool));
  const suggested = new Map<Capability, string[]>();
  for (const p of advice.picks) if (p.tool && (p.change === "add" || p.change === "switch")) for (const cap of p.tool.controls) add(suggested, cap, toolLabel(p.tool));

  const scope = c.delivery === "edr" ? EDR_SCOPE : null;
  const groups: GroupDesign[] = after.classes.map((g) => {
    const items = (caps: Capability[], required: boolean): DeployItem[] =>
      caps.map((cap) => {
        // The design is for the managed service, so its platform is part of it.
        if (PLATFORM_CAPABILITIES.includes(cap)) return { capability: cap, required, status: "in-place", by: [PLATFORM_LABEL] };
        const now = current.get(cap);
        if (now?.length) return { capability: cap, required, status: "in-place", by: now };
        const next = suggested.get(cap);
        if (next?.length) return { capability: cap, required, status: "suggested", by: next };
        return { capability: cap, required, status: "gap", by: [] };
      });
    return {
      info: g.info,
      priority: g.priority,
      reasons: g.reasons,
      describe: g.describe,
      inScope: !scope || scope.includes(g.info.key),
      deploy: [...items(g.info.required, true), ...items([...g.info.recommended, ...(goal === "protection" ? g.info.advanced : [])], false)],
    };
  });

  // The central architecture the asset groups feed.
  const finalTools = stackTools(advice.config, ctx).map((t) => t.tool);
  const alerting = finalTools.filter((t) => t.ingest);
  const silent = finalTools.filter((t) => !t.ingest);
  const actions = [...new Set(finalTools.flatMap((t) => t.actions))].map((a) => ACTION_LABEL[a]);
  const list = (tools: ToolDefinition[]) => tools.map(toolLabel).join(", ");
  const architecture = [
    {
      layer: "Endpoint & asset layer",
      items: groups.map((g) => `${g.info.label}: ${g.describe}`),
    },
    {
      layer: "Telemetry, alerts, configuration and asset data",
      items: [
        ...(alerting.length ? [`Alerts stream in from ${list(alerting)}`] : ["No tool sends alerts yet: onboard the first ones in phase 1"]),
        ...(silent.length ? [`Posture and inventory from ${list(silent)}`] : []),
        `Device inventory with each endpoint's protection status`,
      ],
    },
    {
      layer: "Central security data platform",
      items: [
        `${PLATFORM_LABEL}: log collection and correlation into cases${facts ? `, ${facts.detectors} built-in detectors` : ""}`,
        "Asset inventory and coverage by asset group",
        "Shared threat-intelligence store with public feeds",
      ],
    },
    {
      layer: "Detection & correlation",
      items: [
        facts ? `Detections mapped to MITRE ATT&CK: ${facts.techniques} techniques across ${facts.tactics} tactics` : "Detections mapped to MITRE ATT&CK",
        cfg.ai.mode !== "none" ? `AI first response triages every alert (${cfg.ai.mode === "local" ? "local model, data stays inside" : "cloud model"}); analysts do the primary analysis` : "Analysts triage every alert; AI first response can be added",
        "Related alerts are correlated into one case; threat hunting across clients",
      ],
    },
    {
      layer: "Response & remediation",
      items: [
        actions.length ? `Response actions through ${your} tools: ${actions.join(", ")}` : "Response actions are carried out by hand until a tool with response actions is onboarded",
        facts ? `${facts.playbooks} approval-gated playbooks` : "Approval-gated playbooks",
        "Signed response webhooks to any SOAR or script; every action audited and reversible",
      ],
    },
  ];

  // Rollout in priority order: what to add, and the gaps to close.
  const phaseItems = (p: Priority) =>
    groups
      .filter((g) => g.priority === p && g.inScope)
      .map((g) => {
        const next = g.deploy.filter((d) => d.status === "suggested");
        const gaps = g.deploy.filter((d) => d.status === "gap" && d.required);
        const tools = [...new Set(next.flatMap((d) => d.by))];
        const parts = [tools.length ? `deploy ${tools.join(", ")}` : g.deploy.every((d) => d.status === "in-place" || !d.required) ? "already covered; onboard its telemetry" : ""];
        if (gaps.length) parts.push(`still to choose: ${gaps.map((d) => capabilityName(d.capability)).join(", ")}`);
        return `${g.info.label}: ${parts.filter(Boolean).join("; ")}`;
      });
  const phases = [
    { phase: 1, title: "Phase 1 · P1 asset groups", items: [...phaseItems("P1"), "Connect every tool's alerts to the SOC and turn on AI first response"] },
    { phase: 2, title: "Phase 2 · P2 asset groups", items: phaseItems("P2") },
    { phase: 3, title: "Phase 3 · P3 groups, hunting and tuning", items: [...phaseItems("P3"), ...(scope ? groups.filter((g) => !g.inScope).map((g) => `${g.info.label}: plan coverage beyond the endpoint deployment`) : []), "Tune detections and run threat hunts on the collected telemetry"] },
  ].filter((p) => p.items.length);

  const guidance: string[] = [];
  if (c.maturity === "none") guidance.push("No security tools yet: start with EDR on every device, MFA and email protection. The managed service provides the SIEM, so there is nothing separate to buy for logs.");
  if (c.maturity === "some") guidance.push(`Onboard the tools ${audience === "public" ? "you" : "the client"} already ${audience === "public" ? "have" : "has"} first: their alerts flow from day one. Then close the gaps in priority order.`);
  if (c.maturity === "mature") guidance.push(`Keep ${your} SIEM: forward its alerts to the managed service through an ingest URL, and use the SOC for round-the-clock triage, response and hunting.`);
  if (c.delivery === "edr") guidance.push("Scope: endpoint security deployment. User endpoints, servers and mobile come first; the rest of the attack surface is listed for later phases.");
  if (c.delivery === "soc") guidance.push("Scope: centralized SOC monitoring. Every tool's alerts and logs flow to the SOC; gaps are flagged for a decision rather than bought by default.");
  if (c.delivery === "complete") guidance.push("Scope: complete cybersecurity solution covering every asset group, in priority order.");
  if (c.delivery === "ai") guidance.push(`Scope: AI-driven security. AI agents triage every alert and propose containment within the autonomy ${audience === "public" ? "you consent" : "the client consents"} to, on a cloud or a local model.${cfg.ai.mode === "none" ? " Choose cloud or local AI in the estimate." : ""}`);
  if (c.companyType === "regulated") guidance.push("Regulated: the audit trail, monthly reports and compliance evidence packs support audits.");
  if (c.environment === "ot" || groups.some((g) => g.info.key === "iot_ot" && g.priority === "P1")) guidance.push("OT is monitored passively; containment there is coordinated with plant or clinical engineering and never automatic.");

  const profile = [
    { label: "Company", value: c.companyType ? COMPANY_TYPES[c.companyType] : "—" },
    { label: "Industry", value: INDUSTRIES[c.industry] },
    { label: "Users", value: usersBracket(cfg.profile.users) ?? "—" },
    { label: "IT environment", value: c.environment ? ENVIRONMENTS[c.environment] : "—" },
    { label: "Delivering", value: c.delivery ? DELIVERY[c.delivery] : "—" },
    { label: "Security maturity", value: c.maturity ? MATURITY[c.maturity] : "—" },
  ];
  const title = `${c.delivery ? DELIVERY[c.delivery] : "Security design"} for ${c.companyType ? `a ${COMPANY_TYPES[c.companyType].toLowerCase()}` : "the organization"}${c.industry !== "general" ? ` in ${INDUSTRIES[c.industry].toLowerCase()}` : ""}`;

  return {
    title,
    profile,
    groups,
    notCounted: ASSET_CLASSES.filter((a) => !after.classes.some((g) => g.info.key === a.key)),
    architecture,
    phases,
    guidance,
    advice,
    coverageBefore: before.score,
    coverageAfter: after.score,
  };
}
