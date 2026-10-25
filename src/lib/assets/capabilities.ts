import { CONTROLS, type ProtectionControl } from "@/lib/endpoints/controls";

// Security capabilities across the whole attack surface. The first twelve
// are the per-device protection controls the endpoint inventory tracks
// (lib/endpoints/controls.ts); the rest protect identities, cloud,
// networks, OT and applications. Catalog tools list the capabilities they
// provide in their `controls`. Client-safe and pure.

export type SurfaceCapability =
  | "mtd"
  | "mfa"
  | "itdr"
  | "pam"
  | "email_security"
  | "cspm"
  | "cwpp"
  | "sspm"
  | "ndr"
  | "net_config"
  | "ot_monitoring"
  | "waf"
  | "api_security"
  | "code_security"
  | "siem"
  | "soar";

export type Capability = ProtectionControl | SurfaceCapability;

export interface CapabilityInfo {
  key: Capability;
  label: string;
  short: string;
  description: string;
  // A per-device control tracked on each endpoint.
  device: boolean;
}

const SURFACE: Array<Omit<CapabilityInfo, "device">> = [
  { key: "mtd", label: "Mobile threat defense", short: "MTD", description: "Malicious apps, phishing and risky networks on phones and tablets" },
  { key: "mfa", label: "MFA & conditional access", short: "MFA", description: "Strong sign-in, device-compliance and location rules for every account" },
  { key: "itdr", label: "Identity threat detection", short: "ITDR", description: "Account takeover, password spraying and directory attacks (Kerberoasting, DCSync)" },
  { key: "pam", label: "Privileged access management", short: "PAM", description: "Vaulted admin credentials, just-in-time elevation and recorded privileged sessions" },
  { key: "email_security", label: "Email protection", short: "MAIL", description: "Phishing, business email compromise and malicious attachments and links" },
  { key: "cspm", label: "Cloud posture management", short: "CSPM", description: "Misconfigurations, exposed storage and excessive permissions across cloud accounts" },
  { key: "cwpp", label: "Cloud workload protection", short: "CWPP", description: "Runtime threat detection and vulnerability scanning for VMs, containers and Kubernetes" },
  { key: "sspm", label: "SaaS security", short: "SSPM", description: "Risky settings, OAuth apps and data sharing in Microsoft 365, Google Workspace and Salesforce" },
  { key: "ndr", label: "Network detection & IDS", short: "NDR", description: "Intrusion detection and traffic analysis: command and control, scanning, lateral movement" },
  { key: "net_config", label: "Network device management", short: "NET", description: "Configuration change tracking, firmware patching and admin access on firewalls, VPNs and switches" },
  { key: "ot_monitoring", label: "IoT / OT monitoring", short: "OT", description: "Passive asset discovery and threat detection for PLCs, SCADA, medical and building systems" },
  { key: "waf", label: "Web application firewall", short: "WAF", description: "Blocks attacks on internet-facing websites and portals" },
  { key: "api_security", label: "API security", short: "API", description: "Discovery and abuse detection for APIs and API gateways" },
  { key: "code_security", label: "Code & secrets security", short: "CODE", description: "SAST, dependency and secrets scanning in repositories and CI/CD pipelines" },
  { key: "siem", label: "Central log collection & correlation", short: "SIEM", description: "Telemetry from every source in one place, correlated into cases" },
  { key: "soar", label: "Automated response", short: "SOAR", description: "Playbooks that isolate devices, disable accounts and block indicators" },
];

export const CAPABILITIES: CapabilityInfo[] = [
  ...CONTROLS.map((c) => ({ key: c.key, label: c.label, short: c.short, description: c.description, device: true })),
  ...SURFACE.map((c) => ({ ...c, device: false })),
];

export const CAPABILITY_KEYS = CAPABILITIES.map((c) => c.key);
const INDEX = new Map(CAPABILITIES.map((c) => [c.key as string, c]));

export function capabilityInfo(key: string): CapabilityInfo | undefined {
  return INDEX.get(key);
}

export const capabilityShort = (key: string) => INDEX.get(key)?.short ?? key;
export const capabilityName = (key: string) => INDEX.get(key)?.label ?? key;

export function isDeviceControl(key: string): key is ProtectionControl {
  return INDEX.get(key)?.device === true;
}

// What the managed service itself provides on every plan: HELIOS is the
// central data platform (detection engine, correlation, threat intel) and
// runs the playbooks and response connectors.
export const PLATFORM_CAPABILITIES: Capability[] = ["siem", "soar"];
export const PLATFORM_LABEL = "Managed service (HELIOS)";
