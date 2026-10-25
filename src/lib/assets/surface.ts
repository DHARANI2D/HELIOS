import type { Capability } from "@/lib/assets/capabilities";
import { PLATFORM_CAPABILITIES } from "@/lib/assets/capabilities";
import type { Estate, OrgContext } from "@/lib/assets/estate";
import { mixMobile, type EndpointMix } from "@/lib/pricing/endpoint-mix";

// The attack surface a managed security service has to cover: every device,
// workload, identity, network entry point and application, not just
// laptops. Each asset group says what it includes, what threatens it, what
// to deploy, what telemetry to collect, what to detect and how to respond.
// Priorities follow the usual order for a mid-sized company and move with
// the organization (OT is P1 for a hospital or a factory). Client-safe.

export type AssetClass = "user" | "mobile" | "server" | "cloud" | "network" | "identity" | "iot_ot" | "email" | "apps";
export type Priority = "P1" | "P2" | "P3";

export interface AssetClassInfo {
  key: AssetClass;
  label: string;
  description: string;
  examples: string[];
  risk: string;
  defaultPriority: Priority;
  // What to deploy: required for the group to count as protected,
  // recommended for good coverage, advanced for the strongest.
  required: Capability[];
  recommended: Capability[];
  advanced: Capability[];
  telemetry: string[];
  detections: string[];
  response: string[];
}

export const ASSET_CLASSES: AssetClassInfo[] = [
  {
    key: "user",
    label: "User endpoints",
    description: "Laptops and desktops people work on, wherever they are.",
    examples: ["Corporate laptops and desktops (Windows, macOS, Linux)", "Employee-owned devices (BYOD)", "Developer and administrator workstations", "Remote and hybrid workforce devices", "Virtual desktops (VDI)", "Shared kiosks and meeting-room computers"],
    risk: "Malware, ransomware, phishing",
    defaultPriority: "P1",
    required: ["edr", "av", "host_firewall", "disk_encryption", "patching", "mdm", "app_control"],
    recommended: ["web_filtering", "vuln_scan", "backup"],
    advanced: ["device_control", "dlp"],
    telemetry: ["Process, file, registry and network events from the EDR agent", "Windows Security and Sysmon logs; macOS and Linux audit logs", "Device compliance, encryption and patch status", "DNS and web activity"],
    detections: ["Ransomware behaviour and mass file encryption", "Malicious macros, scripts and living-off-the-land binaries", "Credential dumping and persistence (services, scheduled tasks, run keys)", "Phishing payloads and drive-by downloads"],
    response: ["Isolate the device", "Kill the process and quarantine the file", "Collect forensic logs", "Restore or re-image"],
  },
  {
    key: "mobile",
    label: "Mobile endpoints",
    description: "Phones and tablets, corporate or personal, that reach company data.",
    examples: ["Android and iOS phones", "Tablets", "Corporate and BYOD devices", "Devices accessing corporate email, VPNs and SaaS apps"],
    risk: "Lost or stolen devices, malicious apps, phishing by text and messaging",
    defaultPriority: "P2",
    required: ["mdm", "mfa"],
    recommended: ["mtd"],
    advanced: [],
    telemetry: ["Device compliance, jailbreak and root status", "Risky apps and network threats from mobile threat defense", "Conditional-access sign-in decisions"],
    detections: ["Jailbroken or rooted devices", "Malicious or side-loaded apps", "Phishing links opened on mobile"],
    response: ["Block access through conditional access", "Selective or full remote wipe", "Revoke sessions and tokens"],
  },
  {
    key: "server",
    label: "Servers & infrastructure",
    description: "The systems the business runs on, and the backups that bring it back.",
    examples: ["Windows Server and Linux servers", "Active Directory domain controllers", "DNS, DHCP, file, print and database servers", "Web and application servers", "Virtual machines, hypervisors and containers", "Backup servers and storage systems"],
    risk: "Business disruption, data loss",
    defaultPriority: "P1",
    required: ["edr", "patching", "vuln_scan", "backup"],
    recommended: ["pam", "host_firewall"],
    advanced: ["av", "app_control"],
    telemetry: ["Server EDR telemetry", "Windows Security, Linux auditd and syslog", "Domain-controller events (Kerberos, NTLM, group changes)", "Backup job status; hypervisor and container runtime events"],
    detections: ["Lateral movement (PsExec, WMI, RDP)", "Kerberoasting and DCSync against domain controllers", "Shadow-copy and backup deletion", "Web shells on application servers"],
    response: ["Isolate the server", "Disable the compromised service account", "Restore from immutable backup", "Block attacker IPs at the firewall"],
  },
  {
    key: "cloud",
    label: "Cloud & workloads",
    description: "Cloud accounts, the workloads running in them and the SaaS platforms holding company data.",
    examples: ["AWS EC2, Lambda, ECS/EKS", "Microsoft Azure VMs, Functions, AKS", "Google Cloud workloads", "Kubernetes nodes and containers", "Cloud storage, databases and serverless functions", "SaaS platforms such as Microsoft 365, Salesforce and Google Workspace"],
    risk: "Misconfiguration, data exposure",
    defaultPriority: "P2",
    required: ["cspm", "cwpp"],
    recommended: ["sspm"],
    advanced: [],
    telemetry: ["Cloud audit logs (CloudTrail, Azure Activity, Google Cloud Audit Logs)", "Posture findings and permission changes", "Workload runtime alerts", "SaaS audit logs (Microsoft 365 unified audit log)"],
    detections: ["Public storage and exposed access keys", "Unusual API calls and privilege grants", "Crypto-mining and other unexpected workloads", "Suspicious SaaS sign-ins and OAuth grants"],
    response: ["Revoke keys and sessions", "Quarantine the workload", "Fix the misconfiguration in code"],
  },
  {
    key: "network",
    label: "Network & security devices",
    description: "The perimeter and the paths between everything else.",
    examples: ["Firewalls and VPN gateways", "Routers, switches and wireless access points", "IDS/IPS sensors", "Web proxies and secure web gateways", "DNS security appliances", "Load balancers and network access control"],
    risk: "Unauthorized access, lateral movement",
    defaultPriority: "P2",
    required: ["net_config", "siem"],
    recommended: ["ndr"],
    advanced: ["web_filtering", "pam"],
    telemetry: ["Firewall, VPN and proxy logs", "NetFlow and DNS logs", "Configuration changes and firmware versions", "IDS/IPS alerts"],
    detections: ["Brute force and exploitation of VPNs and edge devices", "Command-and-control beacons", "DNS tunnelling", "Internal scanning and lateral movement"],
    response: ["Block the IP or domain at the firewall", "Disable the VPN account", "Quarantine the network segment"],
  },
  {
    key: "identity",
    label: "Identity & access",
    description: "Every account, credential and secret, and the systems that grant access.",
    examples: ["Microsoft Entra ID, Active Directory and LDAP", "Identity providers and SSO", "MFA and authentication systems", "Privileged access management (PAM)", "Service accounts, API keys, tokens and secrets", "Privileged administrator workstations"],
    risk: "Account takeover, privilege escalation",
    defaultPriority: "P1",
    required: ["mfa", "itdr"],
    recommended: ["pam"],
    advanced: [],
    telemetry: ["Sign-in and audit logs (Entra ID, Okta, Active Directory)", "MFA events", "Privileged role and group changes", "Service-account and token use"],
    detections: ["Password spraying and MFA fatigue", "Impossible travel and anomalous sign-ins", "New privileged role assignments", "Token and session theft"],
    response: ["Disable the account and revoke sessions", "Reset credentials and require MFA re-registration", "Rotate exposed secrets"],
  },
  {
    key: "iot_ot",
    label: "IoT & operational technology",
    description: "Devices that can't run an agent but can stop operations when compromised.",
    examples: ["CCTV cameras, printers and smart devices", "Industrial controllers (PLCs), SCADA and HMIs", "Medical devices and building management systems", "Manufacturing equipment and sensors"],
    risk: "Exploitation, operational disruption",
    defaultPriority: "P3",
    required: ["ot_monitoring"],
    recommended: ["ndr"],
    advanced: ["net_config"],
    telemetry: ["Passive monitoring of OT protocols on a SPAN port", "Asset inventory with firmware versions", "Controller program and configuration changes"],
    detections: ["Unauthorized PLC program changes", "New or unknown devices on the OT network", "Traffic crossing from IT into OT"],
    response: ["Block at the IT/OT boundary firewall", "Coordinate with plant or clinical engineering: no automatic isolation of OT", "Carefully tested patching"],
  },
  {
    key: "email",
    label: "Email & collaboration",
    description: "Where most attacks on smaller organizations start.",
    examples: ["Email gateways and mailboxes", "Collaboration tools (Teams, Slack)", "Web browsers"],
    risk: "Phishing, business email compromise",
    defaultPriority: "P1",
    required: ["email_security", "mfa"],
    recommended: ["web_filtering"],
    advanced: ["sspm"],
    telemetry: ["Mail flow and delivery logs", "User-reported phishing", "Mailbox rule and forwarding changes"],
    detections: ["Phishing and malicious attachments", "Business email compromise and invoice fraud", "Suspicious inbox forwarding rules"],
    response: ["Purge the message from every mailbox", "Block the sender", "Reset the compromised account"],
  },
  {
    key: "apps",
    label: "Applications, APIs & developer systems",
    description: "Internet-facing services, the code behind them and the pipelines that ship it.",
    examples: ["Internet-facing applications and remote-access portals", "APIs and API gateways", "Git repositories, CI/CD runners and developer tools", "Third-party integrations and vendor access"],
    risk: "Source-code compromise, secrets theft, application attacks",
    defaultPriority: "P2",
    required: ["waf", "code_security"],
    recommended: ["api_security"],
    advanced: [],
    telemetry: ["WAF and API-gateway logs", "Repository and CI/CD audit logs", "Secret-scanning and dependency alerts"],
    detections: ["Injection and credential-stuffing attacks", "Secrets committed to repositories", "Malicious pipeline or dependency changes"],
    response: ["Block the attacker at the WAF", "Rotate leaked secrets", "Revert the pipeline change and revoke tokens"],
  },
];

const INDEX = new Map(ASSET_CLASSES.map((c) => [c.key, c]));
export const assetClass = (key: AssetClass) => INDEX.get(key)!;

export interface SurfaceProfile {
  workstations: number;
  servers: number;
  users: number;
  mix: EndpointMix | null;
  estate: Estate;
}

// How much of each group the client has. Workstations and servers come from
// a normalized config (the mix's totals when there is one).
export function classCounts(p: SurfaceProfile): Record<AssetClass, number> {
  const e = p.estate;
  return {
    user: p.workstations,
    mobile: p.mix ? mixMobile(p.mix) : 0,
    server: p.servers,
    cloud: e.cloudAccounts + e.cloudWorkloads + e.saasApps,
    network: e.networkDevices,
    identity: p.users + e.privilegedAccounts,
    iot_ot: e.iotDevices + e.otDevices,
    email: p.users,
    apps: e.internetApps + e.developers,
  };
}

export function describeClassCount(key: AssetClass, p: SurfaceProfile): string {
  const e = p.estate;
  const n = (v: number, one: string, many = `${one}s`) => `${v.toLocaleString("en-US")} ${v === 1 ? one : many}`;
  const parts = (xs: Array<[number, string, string?]>) => xs.filter(([v]) => v > 0).map(([v, one, many]) => n(v, one, many)).join(", ");
  switch (key) {
    case "user":
      return n(p.workstations, "computer");
    case "mobile":
      return n(p.mix ? mixMobile(p.mix) : 0, "phone or tablet", "phones and tablets");
    case "server":
      return n(p.servers, "server");
    case "cloud":
      return parts([[e.cloudAccounts, "cloud account"], [e.cloudWorkloads, "workload"], [e.saasApps, "SaaS platform"]]);
    case "network":
      return n(e.networkDevices, "device");
    case "identity":
      return parts([[p.users, "user"], [e.privilegedAccounts, "admin or service account"]]);
    case "iot_ot":
      return parts([[e.iotDevices, "IoT device"], [e.otDevices, "OT or medical device"]]);
    case "email":
      return n(p.users, "mailbox", "mailboxes");
    case "apps":
      return parts([[e.internetApps, "internet-facing app"], [e.developers, "developer"]]);
  }
}

export interface ClassPriority {
  priority: Priority;
  reasons: string[];
}

const OT_INDUSTRY: Partial<Record<OrgContext["industry"], string>> = {
  healthcare: "Medical devices affect patient safety",
  manufacturing: "Production depends on OT",
  energy: "Critical infrastructure runs on OT",
};

// The priority of each group for this organization, with the reason when it
// differs from the usual order.
export function assetPriorities(ctx: OrgContext): Record<AssetClass, ClassPriority> {
  const out = Object.fromEntries(ASSET_CLASSES.map((c) => [c.key, { priority: c.defaultPriority, reasons: [] as string[] }])) as Record<AssetClass, ClassPriority>;
  const raise = (key: AssetClass, to: Priority, reason: string) => {
    if (to < out[key].priority) out[key] = { priority: to, reasons: [...out[key].reasons, reason] };
  };
  const lower = (key: AssetClass, to: Priority, reason: string) => {
    if (to > out[key].priority) out[key] = { priority: to, reasons: [...out[key].reasons, reason] };
  };
  if (ctx.environment === "cloud") raise("cloud", "P1", "Cloud-first: the business runs on cloud workloads and SaaS");
  if (ctx.environment === "onprem") lower("cloud", "P3", "On-premises first: little runs in the cloud");
  if (ctx.environment === "ot") raise("iot_ot", "P1", "Industrial / OT-heavy environment");
  const ot = OT_INDUSTRY[ctx.industry];
  if (ot) raise("iot_ot", "P1", ot);
  if (ctx.industry === "technology") raise("apps", "P1", "Source code and online services are the product");
  if (ctx.industry === "finance" || ctx.companyType === "regulated") raise("apps", "P1", "Regulators expect secure internet-facing applications");
  if (ctx.industry === "retail") raise("apps", "P1", "Online sales depend on internet-facing applications");
  if (ctx.companyType === "large") raise("network", "P1", "A large network makes lateral movement the main risk");
  return out;
}

export const PRIORITY_WEIGHT: Record<Priority, number> = { P1: 3, P2: 2, P3: 1 };

export type CoverageGoal = "budget" | "balanced" | "protection";

// What a goal asks to cover, for the groups the client has: lowest cost
// covers what P1 groups require; best value covers every group's
// requirements and the P1 groups' recommendations; strongest protection
// adds every recommended and advanced capability. The platform's own
// capabilities are always there.
export function wantedCapabilities(goal: CoverageGoal, present: AssetClass[], priorities: Record<AssetClass, ClassPriority>): Set<Capability> {
  const out = new Set<Capability>();
  for (const key of present) {
    const c = assetClass(key);
    const p1 = priorities[key].priority === "P1";
    if (goal !== "budget" || p1) c.required.forEach((x) => out.add(x));
    if (goal === "protection" || (goal === "balanced" && p1)) c.recommended.forEach((x) => out.add(x));
    if (goal === "protection") c.advanced.forEach((x) => out.add(x));
  }
  PLATFORM_CAPABILITIES.forEach((x) => out.delete(x));
  return out;
}

// How much a capability matters to this client: the highest priority of the
// groups it protects (required counts fully, recommended half, advanced a
// quarter).
export function capabilityValue(cap: Capability, present: AssetClass[], priorities: Record<AssetClass, ClassPriority>): number {
  let best = 0;
  for (const key of present) {
    const c = assetClass(key);
    const w = PRIORITY_WEIGHT[priorities[key].priority];
    if (c.required.includes(cap)) best = Math.max(best, w);
    else if (c.recommended.includes(cap)) best = Math.max(best, w / 2);
    else if (c.advanced.includes(cap)) best = Math.max(best, w / 4);
  }
  return best;
}

export function presentClasses(p: SurfaceProfile): AssetClass[] {
  const counts = classCounts(p);
  return ASSET_CLASSES.filter((c) => counts[c.key] > 0).map((c) => c.key);
}
