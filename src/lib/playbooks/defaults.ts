import type { PlaybookActionType } from "@prisma/client";

import type { TriggerCondition } from "@/lib/playbooks/trigger";

// Starter playbooks, adapted from signal-fusion's scripts/createPlaybooks.ts
// and extended to the other three case sources. Seeded once; analysts edit
// them from the Response Playbooks page.

export interface PlaybookTemplate {
  name: string;
  description: string;
  triggerCondition: TriggerCondition;
  autoExecute: boolean;
  requireApproval: boolean;
  priority: number;
  actions: Array<{ name: string; actionType: PlaybookActionType; parameters: Record<string, unknown> }>;
}

export const DEFAULT_PLAYBOOKS: PlaybookTemplate[] = [
  {
    name: "Contain ransomware / credential dumping host",
    description:
      "Isolate the affected endpoint, pull surrounding telemetry into the case, and open a ticket when ransomware or credential-dumping techniques are detected.",
    triggerCondition: {
      minSeverity: "HIGH",
      sourceTypes: ["SIEM_ALERT", "SOC_INVESTIGATION"],
      techniques: ["T1486", "T1490", "T1003"],
    },
    autoExecute: false,
    requireApproval: true,
    priority: 100,
    actions: [
      { name: "Isolate host", actionType: "ISOLATE_HOST", parameters: { method: "edr_network_containment" } },
      { name: "Collect surrounding telemetry", actionType: "COLLECT_LOGS", parameters: { windowMinutes: 60 } },
      {
        name: "Notify SOC channel",
        actionType: "NOTIFY_SLACK",
        parameters: { channel: "#soc-critical", message: "Host {{host}} isolated: {{case.title}} ({{case.severity}})" },
      },
      {
        name: "Open incident ticket",
        actionType: "CREATE_TICKET",
        parameters: { system: "jira", project: "SEC", title: "Investigate isolated host {{host}}" },
      },
    ],
  },
  {
    name: "Block threat-intel matched IPs",
    description: "Add every public IP linked to the case to the HELIOS blocklist when a threat-intel match fires.",
    triggerCondition: { detectionSources: ["THREAT_INTEL_MATCH"] },
    autoExecute: true,
    requireApproval: false,
    priority: 90,
    actions: [
      { name: "Block case IPs", actionType: "BLOCK_IP", parameters: { scope: "case_indicators", duration: "24h" } },
      {
        name: "Notify SOC channel",
        actionType: "NOTIFY_SLACK",
        parameters: { channel: "#soc-alerts", message: "Blocked {{ips}} for {{case.title}}" },
      },
    ],
  },
  {
    name: "Phishing response",
    description: "Block infrastructure behind a malicious email and open a ticket for mailbox sweep.",
    triggerCondition: { sourceTypes: ["EMAIL_ANALYSIS"], verdicts: ["malicious"] },
    autoExecute: false,
    requireApproval: true,
    priority: 80,
    actions: [
      { name: "Block sender / URL IPs", actionType: "BLOCK_IP", parameters: { scope: "case_indicators" } },
      {
        name: "Open mailbox-sweep ticket",
        actionType: "CREATE_TICKET",
        parameters: { system: "jira", project: "SEC", title: "Sweep mailboxes for: {{case.title}}" },
      },
    ],
  },
  {
    name: "Revoke misbehaving AI agent",
    description:
      "Revoke the agent behind a high-severity governance case the pipeline flagged but didn't auto-revoke, pending analyst approval.",
    // Critical / constitution breaches are already revoked by the governance
    // pipeline itself (verdict "malicious"); this covers the "suspicious" ones.
    triggerCondition: { sourceTypes: ["AGENT_GOVERNANCE"], minSeverity: "HIGH", verdicts: ["suspicious"] },
    autoExecute: false,
    requireApproval: true,
    priority: 70,
    actions: [
      { name: "Revoke agent identity", actionType: "REVOKE_AGENT", parameters: {} },
      {
        name: "Open review ticket",
        actionType: "CREATE_TICKET",
        parameters: { system: "jira", project: "AIGOV", title: "Review revoked agent for {{case.title}}" },
      },
    ],
  },
  {
    name: "Page on critical cases",
    description: "Notify the on-call channel for any critical case regardless of source.",
    triggerCondition: { minSeverity: "CRITICAL" },
    autoExecute: true,
    requireApproval: false,
    priority: 10,
    actions: [
      {
        name: "Page on-call",
        actionType: "NOTIFY_SLACK",
        parameters: { channel: "#soc-oncall", message: "CRITICAL {{case.source}} case: {{case.title}}" },
      },
    ],
  },
];
