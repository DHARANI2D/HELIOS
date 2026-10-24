import type { PlaybookActionType, UserRole } from "@prisma/client";

import type { ProtectionControl } from "@/lib/endpoints/controls";
import type { TelemetrySource } from "@/lib/siem/types";

// Every security tool HELIOS can onboard, grouped by category. Used by
// Tools & Integrations (onboarding, ingest mapping, response connectors)
// and by Build & Price (vendor comparison and default prices).
//
// Prices are indicative monthly USD per unit. "list" means the vendor's
// published list price at the time of writing; "estimate" means the vendor
// sells by quote and the figure is a planning estimate. Both are defaults:
// the price book (Build & Price → Price book) overrides them with your own
// distributor or partner pricing, and every quote should be checked against
// a current vendor quote before it goes to a client.

export type CategoryKey =
  | "edr"
  | "epp"
  | "mdm"
  | "vuln"
  | "email"
  | "identity"
  | "network"
  | "dlp"
  | "siem"
  | "backup"
  | "awareness"
  | "ticketing"
  | "chatops"
  | "automation";

export interface ToolCategory {
  key: CategoryKey;
  label: string;
  description: string;
  // Default telemetry source for raw events pushed through this tool.
  telemetry: TelemetrySource;
  // Roles that see tools in this category by default.
  defaultRoles: UserRole[];
  // Shown in the Build & Price stack builder.
  priced: boolean;
}

const SOC: UserRole[] = ["SOC_MANAGER", "TRIAGE_ANALYST", "ANALYST", "INCIDENT_RESPONDER", "THREAT_HUNTER", "DETECTION_ENGINEER"];

export const CATEGORIES: ToolCategory[] = [
  { key: "edr", label: "EDR / XDR", description: "Endpoint detection, response and remote isolation", telemetry: "endpoint", defaultRoles: SOC, priced: true },
  { key: "epp", label: "Antivirus / NGAV", description: "Malware prevention on every endpoint", telemetry: "endpoint", defaultRoles: SOC, priced: true },
  { key: "mdm", label: "Device management (MDM/UEM)", description: "Enrollment, baselines, encryption and patch policy", telemetry: "endpoint", defaultRoles: ["SOC_MANAGER", "INCIDENT_RESPONDER", "DETECTION_ENGINEER"], priced: true },
  { key: "vuln", label: "Patch & vulnerability management", description: "Find and fix exposures before attackers do", telemetry: "endpoint", defaultRoles: ["SOC_MANAGER", "ANALYST", "THREAT_HUNTER", "DETECTION_ENGINEER"], priced: true },
  { key: "email", label: "Email security", description: "Phishing, BEC and malicious attachment protection", telemetry: "endpoint", defaultRoles: SOC, priced: true },
  { key: "identity", label: "Identity, SSO & MFA", description: "Account protection, sign-in telemetry, user suspension", telemetry: "auth", defaultRoles: SOC, priced: true },
  { key: "network", label: "Firewall, DNS & web filtering", description: "Perimeter and egress control, IP/domain blocking", telemetry: "network", defaultRoles: SOC, priced: true },
  { key: "dlp", label: "Data loss prevention", description: "Sensitive-data discovery and exfiltration control", telemetry: "endpoint", defaultRoles: ["SOC_MANAGER", "INCIDENT_RESPONDER", "THREAT_HUNTER"], priced: true },
  { key: "siem", label: "SIEM & log management", description: "Central log retention and correlation", telemetry: "endpoint", defaultRoles: SOC, priced: true },
  { key: "backup", label: "Backup & ransomware recovery", description: "Immutable backups and restore", telemetry: "endpoint", defaultRoles: ["SOC_MANAGER", "INCIDENT_RESPONDER"], priced: true },
  { key: "awareness", label: "Security awareness training", description: "Phishing simulation and training for staff", telemetry: "auth", defaultRoles: ["SOC_MANAGER"], priced: true },
  { key: "ticketing", label: "Ticketing & ITSM", description: "Cases sync to the client's service desk", telemetry: "cloud", defaultRoles: ["SOC_MANAGER", "ANALYST", "INCIDENT_RESPONDER"], priced: false },
  { key: "chatops", label: "Chat & paging", description: "Alert routing to Slack, Teams and on-call", telemetry: "cloud", defaultRoles: SOC, priced: false },
  { key: "automation", label: "Automation / SOAR", description: "Signed webhooks that carry out response actions anywhere", telemetry: "cloud", defaultRoles: ["SOC_MANAGER", "DETECTION_ENGINEER", "INCIDENT_RESPONDER"], priced: false },
];

export type PriceUnit = "endpoint" | "user" | "server" | "gb" | "flat";

export const UNIT_LABEL: Record<PriceUnit, string> = {
  endpoint: "per endpoint / month",
  user: "per user / month",
  server: "per server / month",
  gb: "per GB ingested",
  flat: "per month",
};

// How a pushed payload is mapped (src/lib/integrations/mappers.ts).
export type IngestFormat = "crowdstrike" | "defender" | "sentinelone" | "wazuh" | "entra" | "okta" | "generic";

export interface ToolDefinition {
  key: string;
  name: string;
  vendor: string;
  category: CategoryKey;
  description: string;
  controls: ProtectionControl[];
  // Response actions this tool can carry out once its response connector is set.
  actions: PlaybookActionType[];
  ingest: IngestFormat | null;
  platforms: string[];
  deployment: "cloud" | "self-hosted" | "hybrid";
  // Works without internet access (on-prem / air-gapped estates).
  offlineCapable: boolean;
  price: { unit: PriceUnit; amount: number; basis: "list" | "estimate" | "included"; note?: string };
}

export const TOOLS: ToolDefinition[] = [
  // --- EDR / XDR
  {
    key: "crowdstrike_falcon_enterprise", name: "Falcon Enterprise", vendor: "CrowdStrike", category: "edr",
    description: "EDR + NGAV + device control + firewall management on one agent.",
    controls: ["edr", "av", "device_control", "host_firewall"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "KILL_PROCESS", "QUARANTINE_FILE"],
    ingest: "crowdstrike", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    price: { unit: "endpoint", amount: 15.42, basis: "list", note: "Published at $184.99/device/year" },
  },
  {
    key: "defender_endpoint_p2", name: "Defender for Endpoint P2", vendor: "Microsoft", category: "edr",
    description: "EDR, attack-surface reduction, automated investigation; included in Microsoft 365 E5.",
    controls: ["edr", "av", "host_firewall", "device_control", "app_control", "vuln_scan"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "KILL_PROCESS", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Windows", "macOS", "Linux", "iOS", "Android"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 5.2, basis: "list", note: "Per user, up to 5 devices each" },
  },
  {
    key: "defender_business", name: "Defender for Business", vendor: "Microsoft", category: "edr",
    description: "SMB edition of Defender for Endpoint (≤300 users); included in Microsoft 365 Business Premium.",
    controls: ["edr", "av", "host_firewall", "vuln_scan"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Windows", "macOS", "Linux", "iOS", "Android"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 3, basis: "list" },
  },
  {
    key: "sentinelone_complete", name: "Singularity Complete", vendor: "SentinelOne", category: "edr",
    description: "EDR with autonomous remediation and ransomware rollback.",
    controls: ["edr", "av", "device_control", "host_firewall"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "KILL_PROCESS", "QUARANTINE_FILE"],
    ingest: "sentinelone", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    price: { unit: "endpoint", amount: 15, basis: "list", note: "Published at $179.99/endpoint/year" },
  },
  {
    key: "sophos_intercept_x", name: "Intercept X Advanced with XDR", vendor: "Sophos", category: "edr",
    description: "EDR/XDR with CryptoGuard anti-ransomware, managed from Sophos Central.",
    controls: ["edr", "av", "device_control", "app_control", "web_filtering"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "QUARANTINE_FILE"],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    price: { unit: "endpoint", amount: 6, basis: "estimate", note: "Sold through partners by quote" },
  },
  {
    key: "wazuh", name: "Wazuh (open source)", vendor: "Wazuh", category: "edr",
    description: "Open-source XDR/SIEM: FIM, threat detection, vulnerability detection, active response. Self-hosted, works fully offline.",
    controls: ["edr", "vuln_scan"], actions: ["BLOCK_IP", "KILL_PROCESS", "DISABLE_USER"],
    ingest: "wazuh", platforms: ["Windows", "macOS", "Linux"], deployment: "self-hosted", offlineCapable: true,
    price: { unit: "endpoint", amount: 0, basis: "included", note: "No license fee; budget hosting and engineering time" },
  },
  // --- EPP / NGAV
  {
    key: "defender_antivirus", name: "Defender Antivirus", vendor: "Microsoft", category: "epp",
    description: "Built into Windows; NGAV with cloud protection and tamper protection.",
    controls: ["av", "host_firewall"], actions: ["QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Windows"], deployment: "hybrid", offlineCapable: true,
    price: { unit: "endpoint", amount: 0, basis: "included", note: "Included with Windows" },
  },
  {
    key: "crowdstrike_falcon_pro", name: "Falcon Pro", vendor: "CrowdStrike", category: "epp",
    description: "NGAV with device control and firewall management (no EDR).",
    controls: ["av", "device_control", "host_firewall"], actions: ["QUARANTINE_FILE"],
    ingest: "crowdstrike", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    price: { unit: "endpoint", amount: 8.33, basis: "list", note: "Published at $99.99/device/year" },
  },
  {
    key: "sentinelone_core", name: "Singularity Core", vendor: "SentinelOne", category: "epp",
    description: "NGAV with behavioral AI and rollback.",
    controls: ["av"], actions: ["QUARANTINE_FILE"],
    ingest: "sentinelone", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    price: { unit: "endpoint", amount: 5.83, basis: "list", note: "Published at $69.99/endpoint/year" },
  },
  {
    key: "clamav", name: "ClamAV", vendor: "Cisco Talos (open source)", category: "epp",
    description: "Open-source scanner for Linux servers, mail gateways and file shares.",
    controls: ["av"], actions: [],
    ingest: "generic", platforms: ["Linux", "macOS", "Windows"], deployment: "self-hosted", offlineCapable: true,
    price: { unit: "server", amount: 0, basis: "included" },
  },
  // --- MDM / UEM
  {
    key: "intune_p1", name: "Intune Plan 1", vendor: "Microsoft", category: "mdm",
    description: "Device enrollment, compliance, BitLocker/FileVault policy and update rings; included in Microsoft 365 E3/E5/Business Premium.",
    controls: ["mdm", "disk_encryption", "patching", "app_control"], actions: [],
    ingest: "generic", platforms: ["Windows", "macOS", "iOS", "Android", "Linux"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 8, basis: "list" },
  },
  {
    key: "jamf_pro", name: "Jamf Pro", vendor: "Jamf", category: "mdm",
    description: "Apple device management: enrollment, FileVault, patching and app deployment.",
    controls: ["mdm", "disk_encryption", "patching"], actions: [],
    ingest: "generic", platforms: ["macOS", "iOS"], deployment: "cloud", offlineCapable: false,
    price: { unit: "endpoint", amount: 7.5, basis: "estimate", note: "Priced per device by quote" },
  },
  // --- Patch & vulnerability
  {
    key: "defender_vm", name: "Defender Vulnerability Management add-on", vendor: "Microsoft", category: "vuln",
    description: "Adds full vulnerability assessment and baselines to Defender for Endpoint P2.",
    controls: ["vuln_scan"], actions: [],
    ingest: "defender", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 2, basis: "list" },
  },
  {
    key: "tenable_vm", name: "Tenable Vulnerability Management", vendor: "Tenable", category: "vuln",
    description: "Agent and network scanning with risk-based prioritization.",
    controls: ["vuln_scan"], actions: [],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux", "Network"], deployment: "cloud", offlineCapable: false,
    price: { unit: "endpoint", amount: 4.5, basis: "estimate", note: "Annual per-asset licensing by quote" },
  },
  {
    key: "patch_service", name: "Managed patching (your team)", vendor: "In-house", category: "vuln",
    description: "Your engineers run patch cycles through the client's MDM/RMM.",
    controls: ["patching"], actions: [],
    ingest: null, platforms: ["Windows", "macOS", "Linux"], deployment: "hybrid", offlineCapable: true,
    price: { unit: "endpoint", amount: 2.5, basis: "estimate", note: "Labour; set to your rate" },
  },
  // --- Email
  {
    key: "defender_o365_p1", name: "Defender for Office 365 P1", vendor: "Microsoft", category: "email",
    description: "Safe Links, Safe Attachments, anti-phishing for Exchange Online.",
    controls: [], actions: ["BLOCK_SENDER", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Microsoft 365"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 2, basis: "list" },
  },
  {
    key: "defender_o365_p2", name: "Defender for Office 365 P2", vendor: "Microsoft", category: "email",
    description: "P1 plus threat explorer, automated investigation and attack simulation training.",
    controls: [], actions: ["BLOCK_SENDER", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Microsoft 365"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 5, basis: "list" },
  },
  {
    key: "proofpoint_essentials", name: "Proofpoint Essentials", vendor: "Proofpoint", category: "email",
    description: "SMB secure email gateway with URL defense and attachment sandboxing.",
    controls: [], actions: ["BLOCK_SENDER", "QUARANTINE_FILE"],
    ingest: "generic", platforms: ["Microsoft 365", "Google Workspace"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 3, basis: "estimate", note: "Sold through partners by quote" },
  },
  // --- Identity
  {
    key: "entra_p1", name: "Entra ID P1", vendor: "Microsoft", category: "identity",
    description: "Conditional Access, MFA, sign-in logs; included in Microsoft 365 E3/Business Premium.",
    controls: [], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "entra", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 6, basis: "list" },
  },
  {
    key: "entra_p2", name: "Entra ID P2", vendor: "Microsoft", category: "identity",
    description: "P1 plus ID Protection (risky sign-ins) and privileged identity management.",
    controls: [], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "entra", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 9, basis: "list" },
  },
  {
    key: "okta_workforce", name: "Workforce Identity (SSO + MFA)", vendor: "Okta", category: "identity",
    description: "SSO and adaptive MFA with System Log streaming.",
    controls: [], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "okta", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 5, basis: "list", note: "SSO $2 + MFA $3 starting prices" },
  },
  {
    key: "duo_advantage", name: "Duo Advantage", vendor: "Cisco", category: "identity",
    description: "MFA with device trust and risk-based authentication.",
    controls: [], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 6, basis: "list" },
  },
  // --- Network
  {
    key: "cloudflare_zero_trust", name: "Zero Trust (Gateway + Access)", vendor: "Cloudflare", category: "network",
    description: "DNS/HTTP filtering and zero-trust access; free tier up to 50 users.",
    controls: ["web_filtering"], actions: ["BLOCK_IP"],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux", "iOS", "Android"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 7, basis: "list" },
  },
  {
    key: "opnsense", name: "OPNsense / pfSense", vendor: "Open source", category: "network",
    description: "Open-source firewall; HELIOS blocks IPs through a firewall alias.",
    controls: ["web_filtering"], actions: ["BLOCK_IP", "UNBLOCK_IP"],
    ingest: "generic", platforms: ["Appliance"], deployment: "self-hosted", offlineCapable: true,
    price: { unit: "flat", amount: 0, basis: "included", note: "Hardware priced separately" },
  },
  {
    key: "fortigate", name: "FortiGate NGFW", vendor: "Fortinet", category: "network",
    description: "Next-generation firewall with IPS, web filtering and SD-WAN.",
    controls: ["web_filtering"], actions: ["BLOCK_IP", "UNBLOCK_IP"],
    ingest: "generic", platforms: ["Appliance"], deployment: "hybrid", offlineCapable: true,
    price: { unit: "flat", amount: 150, basis: "estimate", note: "Small-office appliance + UTP bundle, amortized" },
  },
  // --- DLP
  {
    key: "purview_e5_compliance", name: "Purview (E5 Compliance add-on)", vendor: "Microsoft", category: "dlp",
    description: "Endpoint and cloud DLP, insider-risk management, sensitivity labels.",
    controls: ["dlp"], actions: [],
    ingest: "defender", platforms: ["Windows", "macOS", "Microsoft 365"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 12, basis: "list" },
  },
  // --- SIEM
  {
    key: "ms_sentinel", name: "Microsoft Sentinel", vendor: "Microsoft", category: "siem",
    description: "Cloud SIEM billed on data ingested; free for many Microsoft 365 sources.",
    controls: [], actions: [],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "gb", amount: 5.2, basis: "estimate", note: "Pay-as-you-go varies by region and tier" },
  },
  {
    key: "splunk_cloud", name: "Splunk Cloud Platform", vendor: "Splunk", category: "siem",
    description: "Enterprise SIEM; ingest- or workload-based licensing.",
    controls: [], actions: [],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "gb", amount: 6, basis: "estimate", note: "Sold by quote" },
  },
  {
    key: "helios_siem", name: "HELIOS built-in detection", vendor: "HELIOS", category: "siem",
    description: "This platform's own detection engine and 30-day telemetry store.",
    controls: [], actions: [],
    ingest: "generic", platforms: ["Any"], deployment: "hybrid", offlineCapable: true,
    price: { unit: "gb", amount: 0, basis: "included", note: "Included in the service plan" },
  },
  // --- Backup
  {
    key: "m365_backup", name: "Microsoft 365 Backup", vendor: "Microsoft", category: "backup",
    description: "Fast-restore backup for Exchange, OneDrive and SharePoint.",
    controls: ["backup"], actions: [],
    ingest: null, platforms: ["Microsoft 365"], deployment: "cloud", offlineCapable: false,
    price: { unit: "gb", amount: 0.15, basis: "list", note: "Per GB of protected data per month" },
  },
  {
    key: "acronis_cyber_protect", name: "Cyber Protect", vendor: "Acronis", category: "backup",
    description: "Endpoint backup with immutable storage and anti-ransomware.",
    controls: ["backup"], actions: [],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux"], deployment: "hybrid", offlineCapable: true,
    price: { unit: "endpoint", amount: 4, basis: "estimate", note: "Per workload, by quote" },
  },
  // --- Awareness
  {
    key: "awareness_training", name: "Phishing simulation & training", vendor: "Any provider", category: "awareness",
    description: "Monthly phishing simulations and micro-training for every user.",
    controls: [], actions: [],
    ingest: null, platforms: ["Web"], deployment: "cloud", offlineCapable: false,
    price: { unit: "user", amount: 1.5, basis: "estimate" },
  },
  // --- Ticketing, chat, automation (not priced: the client's existing tools)
  {
    key: "jira_sm", name: "Jira Service Management", vendor: "Atlassian", category: "ticketing",
    description: "Sync HELIOS cases to the client's service desk.",
    controls: [], actions: ["CREATE_TICKET"], ingest: null, platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "flat", amount: 0, basis: "included" },
  },
  {
    key: "servicenow", name: "ServiceNow ITSM", vendor: "ServiceNow", category: "ticketing",
    description: "Sync HELIOS cases to ServiceNow incidents.",
    controls: [], actions: ["CREATE_TICKET"], ingest: null, platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "flat", amount: 0, basis: "included" },
  },
  {
    key: "slack", name: "Slack", vendor: "Salesforce", category: "chatops",
    description: "Post alerts and approvals to a channel through an incoming webhook.",
    controls: [], actions: ["NOTIFY_SLACK"], ingest: null, platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "flat", amount: 0, basis: "included" },
  },
  {
    key: "teams", name: "Microsoft Teams", vendor: "Microsoft", category: "chatops",
    description: "Post alerts to a Teams channel through a workflow webhook.",
    controls: [], actions: ["NOTIFY_SLACK"], ingest: null, platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    price: { unit: "flat", amount: 0, basis: "included" },
  },
  {
    key: "response_webhook", name: "Response webhook (SOAR, n8n, Tines, scripts)", vendor: "Generic", category: "automation",
    description: "HELIOS POSTs each approved response action as signed JSON; your automation carries it out and the result lands on the case.",
    controls: [], actions: ["ISOLATE_HOST", "RELEASE_HOST", "BLOCK_IP", "UNBLOCK_IP", "DISABLE_USER", "ENABLE_USER", "KILL_PROCESS", "QUARANTINE_FILE", "BLOCK_SENDER"],
    ingest: "generic", platforms: ["Any"], deployment: "hybrid", offlineCapable: true,
    price: { unit: "flat", amount: 0, basis: "included" },
  },
];

const TOOL_INDEX = new Map(TOOLS.map((t) => [t.key, t]));

export function getTool(key: string): ToolDefinition | undefined {
  return TOOL_INDEX.get(key);
}

export function getCategory(key: string): ToolCategory | undefined {
  return CATEGORIES.find((c) => c.key === key);
}

export function toolsIn(category: CategoryKey): ToolDefinition[] {
  return TOOLS.filter((t) => t.category === category);
}
