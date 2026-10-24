// Endpoint protection controls: the layers a well-protected endpoint has.
// Each onboarded tool declares which controls it provides; the endpoint
// inventory and the configurator's coverage check both read this list.

export type ProtectionControl =
  | "edr"
  | "av"
  | "host_firewall"
  | "disk_encryption"
  | "patching"
  | "vuln_scan"
  | "mdm"
  | "device_control"
  | "app_control"
  | "web_filtering"
  | "dlp"
  | "backup";

export interface ControlInfo {
  key: ProtectionControl;
  label: string;
  short: string;
  description: string;
  // Baseline controls every managed endpoint should have.
  essential: boolean;
}

export const CONTROLS: ControlInfo[] = [
  { key: "edr", label: "Endpoint detection & response", short: "EDR", essential: true, description: "Behavioral detection, telemetry and remote isolation" },
  { key: "av", label: "Antivirus / NGAV", short: "AV", essential: true, description: "Signature and ML malware prevention" },
  { key: "host_firewall", label: "Host firewall", short: "FW", essential: true, description: "Managed inbound/outbound host firewall policy" },
  { key: "disk_encryption", label: "Disk encryption", short: "ENC", essential: true, description: "BitLocker / FileVault / LUKS with escrowed keys" },
  { key: "patching", label: "Patch management", short: "PATCH", essential: true, description: "OS and third-party patching on a defined cadence" },
  { key: "mdm", label: "Device management", short: "MDM", essential: false, description: "Enrollment, configuration baselines, remote wipe" },
  { key: "vuln_scan", label: "Vulnerability scanning", short: "VULN", essential: false, description: "Continuous vulnerability and misconfiguration assessment" },
  { key: "device_control", label: "Device control", short: "USB", essential: false, description: "Removable media and peripheral control" },
  { key: "app_control", label: "Application control", short: "APP", essential: false, description: "Allowlisting / attack-surface reduction rules" },
  { key: "web_filtering", label: "Web & DNS filtering", short: "WEB", essential: false, description: "Malicious domain and category blocking" },
  { key: "dlp", label: "Data loss prevention", short: "DLP", essential: false, description: "Sensitive-data exfiltration controls" },
  { key: "backup", label: "Backup & recovery", short: "BKP", essential: false, description: "Immutable backups for ransomware recovery" },
];

export const CONTROL_KEYS = CONTROLS.map((c) => c.key);
export const ESSENTIAL_CONTROLS = CONTROLS.filter((c) => c.essential).map((c) => c.key);

export type ControlStatus = "active" | "degraded" | "missing";

export interface ControlState {
  status: ControlStatus;
  product?: string;
  updatedAt?: string;
}

export type EndpointProtections = Partial<Record<ProtectionControl, ControlState>>;

export function parseProtections(value: unknown): EndpointProtections {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out: EndpointProtections = {};
  for (const key of CONTROL_KEYS) {
    const v = (value as Record<string, unknown>)[key];
    if (v && typeof v === "object" && "status" in v) {
      const s = (v as ControlState).status;
      if (s === "active" || s === "degraded" || s === "missing") out[key] = v as ControlState;
    }
  }
  return out;
}

// 0-100: essential controls weigh double.
export function coverageScore(p: EndpointProtections): number {
  let earned = 0;
  let possible = 0;
  for (const c of CONTROLS) {
    const weight = c.essential ? 2 : 1;
    possible += weight;
    const s = p[c.key]?.status;
    if (s === "active") earned += weight;
    else if (s === "degraded") earned += weight / 2;
  }
  return Math.round((earned / possible) * 100);
}

export function missingEssentials(p: EndpointProtections): ProtectionControl[] {
  return ESSENTIAL_CONTROLS.filter((k) => p[k]?.status !== "active");
}
