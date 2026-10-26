import type { PlaybookActionType, UserRole } from "@prisma/client";

import type { Capability } from "@/lib/assets/capabilities";
import type { TelemetrySource } from "@/lib/siem/types";

// The taxonomy of security tools HELIOS can onboard. The tools themselves
// live in the catalog_tools table (seeded from prisma/seed-data/tools.ts and
// editable in Build & Price → Tool catalog); this module is client-safe and
// only describes their shape.

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
  | "mtd"
  | "cloud"
  | "ndr"
  | "pam"
  | "ot"
  | "webapp"
  | "code"
  | "netmgmt"
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
  { key: "mtd", label: "Mobile threat defense", description: "Malicious apps, phishing and network attacks on phones and tablets", telemetry: "endpoint", defaultRoles: SOC, priced: true },
  { key: "cloud", label: "Cloud security (CSPM / CWPP)", description: "Posture, permissions and workload protection across AWS, Azure, Google Cloud and SaaS", telemetry: "cloud", defaultRoles: SOC, priced: true },
  { key: "ndr", label: "Network detection & IDS", description: "Intrusion detection and traffic analysis inside the network", telemetry: "network", defaultRoles: ["SOC_MANAGER", "ANALYST", "THREAT_HUNTER", "DETECTION_ENGINEER", "INCIDENT_RESPONDER"], priced: true },
  { key: "pam", label: "Privileged access (PAM)", description: "Vaulted admin credentials, just-in-time elevation and session recording", telemetry: "auth", defaultRoles: ["SOC_MANAGER", "INCIDENT_RESPONDER", "DETECTION_ENGINEER"], priced: true },
  { key: "ot", label: "IoT / OT security", description: "Passive discovery and monitoring of industrial, medical and IoT devices", telemetry: "network", defaultRoles: ["SOC_MANAGER", "INCIDENT_RESPONDER", "THREAT_HUNTER"], priced: true },
  { key: "netmgmt", label: "Network device management", description: "Configuration backup, change tracking and firmware for firewalls, VPNs, switches and access points", telemetry: "network", defaultRoles: ["SOC_MANAGER", "DETECTION_ENGINEER", "INCIDENT_RESPONDER"], priced: true },
  { key: "webapp", label: "Web application & API protection", description: "WAF and API protection for internet-facing apps, portals and APIs", telemetry: "cloud", defaultRoles: ["SOC_MANAGER", "DETECTION_ENGINEER", "ANALYST"], priced: true },
  { key: "code", label: "Code & secrets security", description: "Code, dependency and secrets scanning in repositories and CI/CD pipelines", telemetry: "cloud", defaultRoles: ["SOC_MANAGER", "DETECTION_ENGINEER", "THREAT_HUNTER"], priced: true },
  { key: "ticketing", label: "Ticketing & ITSM", description: "Cases sync to the client's service desk", telemetry: "cloud", defaultRoles: ["SOC_MANAGER", "ANALYST", "INCIDENT_RESPONDER"], priced: false },
  { key: "chatops", label: "Chat & paging", description: "Alert routing to Slack, Teams and on-call", telemetry: "cloud", defaultRoles: SOC, priced: false },
  { key: "automation", label: "Automation / SOAR", description: "Signed webhooks that carry out response actions anywhere", telemetry: "cloud", defaultRoles: ["SOC_MANAGER", "DETECTION_ENGINEER", "INCIDENT_RESPONDER"], priced: false },
];

export type PriceUnit = "endpoint" | "user" | "server" | "gb" | "flat" | "workload" | "account" | "device" | "asset" | "app" | "developer" | "admin";

export const UNIT_LABEL: Record<PriceUnit, string> = {
  endpoint: "per endpoint / month",
  user: "per user / month",
  server: "per server / month",
  gb: "per GB ingested",
  flat: "per month",
  workload: "per cloud workload / month",
  account: "per cloud account / month",
  device: "per network device / month",
  asset: "per IoT/OT device / month",
  app: "per app or domain / month",
  developer: "per developer / month",
  admin: "per privileged account / month",
};

// How a pushed payload is mapped (src/lib/integrations/mappers.ts).
export type IngestFormat = "crowdstrike" | "defender" | "sentinelone" | "wazuh" | "entra" | "okta" | "forwarder" | "cloudtrail" | "gcp_audit" | "azure_activity" | "google_workspace" | "generic";

export interface ToolDefinition {
  key: string;
  name: string;
  vendor: string;
  category: CategoryKey;
  description: string;
  // Security capabilities it provides (device controls and the wider
  // attack surface; lib/assets/capabilities.ts).
  controls: Capability[];
  // Response actions this tool can carry out once its response connector is set.
  actions: PlaybookActionType[];
  ingest: IngestFormat | null;
  platforms: string[];
  deployment: "cloud" | "self-hosted" | "hybrid";
  // Works without internet access (on-prem / air-gapped estates).
  offlineCapable: boolean;
  // list: the vendor's published price (null when sold by quote);
  // custom: what you actually pay or resell at, set in the tool catalog.
  price: { unit: PriceUnit; list: number | null; custom: number | null; source: string | null };
  active: boolean;
}

// Shape of a catalog_tools row, without importing Prisma into client code.
export interface CatalogToolRow {
  key: string;
  name: string;
  vendor: string;
  category: string;
  description: string;
  controls: string[];
  actions: PlaybookActionType[];
  ingest: string | null;
  platforms: string[];
  deployment: string;
  offlineCapable: boolean;
  priceUnit: string;
  listPrice: number | null;
  priceSource: string | null;
  customPrice: number | null;
  active: boolean;
}

const INGEST_FORMATS = new Set<IngestFormat>(["crowdstrike", "defender", "sentinelone", "wazuh", "entra", "okta", "forwarder", "cloudtrail", "gcp_audit", "azure_activity", "google_workspace", "generic"]);
const PRICE_UNITS = new Set<PriceUnit>(Object.keys(UNIT_LABEL) as PriceUnit[]);

export function toolFromRow(row: CatalogToolRow): ToolDefinition {
  return {
    key: row.key,
    name: row.name,
    vendor: row.vendor,
    category: (getCategory(row.category)?.key ?? "automation") as CategoryKey,
    description: row.description,
    controls: row.controls as Capability[],
    actions: row.actions,
    ingest: row.ingest && INGEST_FORMATS.has(row.ingest as IngestFormat) ? (row.ingest as IngestFormat) : null,
    platforms: row.platforms,
    deployment: row.deployment === "self-hosted" || row.deployment === "hybrid" ? row.deployment : "cloud",
    offlineCapable: row.offlineCapable,
    price: { unit: PRICE_UNITS.has(row.priceUnit as PriceUnit) ? (row.priceUnit as PriceUnit) : "flat", list: row.listPrice, custom: row.customPrice, source: row.priceSource },
    active: row.active,
  };
}

// The price quotes use: yours if set, else the vendor's list price, else
// none (the vendor sells by quote and you haven't entered yours yet).
export function toolUnitPrice(tool: ToolDefinition): number | null {
  return tool.price.custom ?? tool.price.list;
}

const GENERIC_VENDORS = new Set(["HELIOS", "Generic", "Open source"]);

export function toolLabel(tool: Pick<ToolDefinition, "name" | "vendor">) {
  return GENERIC_VENDORS.has(tool.vendor) || tool.name.startsWith(tool.vendor) ? tool.name : `${tool.vendor} ${tool.name}`;
}

export function getCategory(key: string): ToolCategory | undefined {
  return CATEGORIES.find((c) => c.key === key);
}
