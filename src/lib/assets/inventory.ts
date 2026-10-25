import { ASSET_CLASSES, type AssetClass } from "@/lib/assets/surface";
import { classifyOs } from "@/lib/pricing/endpoint-mix";

// What each inventory row is: an asset group and, optionally, a type within
// it. Hosts seen in telemetry carry neither and are placed by their OS;
// imports and tools can say exactly what a row is (a firewall, a PLC, a
// cloud VM). Client-safe and pure.

export const ASSET_TYPES: Record<AssetClass, Array<{ key: string; label: string }>> = {
  user: [
    { key: "laptop", label: "Laptop" },
    { key: "desktop", label: "Desktop" },
    { key: "vdi", label: "Virtual desktop (VDI)" },
    { key: "kiosk", label: "Kiosk / meeting-room computer" },
    { key: "byod", label: "Employee-owned (BYOD)" },
    { key: "admin_workstation", label: "Admin workstation" },
    { key: "developer_workstation", label: "Developer workstation" },
  ],
  mobile: [
    { key: "phone", label: "Phone" },
    { key: "tablet", label: "Tablet" },
  ],
  server: [
    { key: "domain_controller", label: "Domain controller" },
    { key: "file_server", label: "File / print server" },
    { key: "database_server", label: "Database server" },
    { key: "web_server", label: "Web / application server" },
    { key: "infrastructure_server", label: "DNS / DHCP server" },
    { key: "hypervisor", label: "Hypervisor" },
    { key: "container_host", label: "Container host" },
    { key: "backup_server", label: "Backup server / storage" },
  ],
  cloud: [
    { key: "cloud_vm", label: "Cloud VM" },
    { key: "kubernetes_node", label: "Kubernetes node" },
    { key: "serverless", label: "Serverless function" },
    { key: "cloud_storage", label: "Cloud storage / database" },
    { key: "cloud_account", label: "Cloud account / subscription" },
    { key: "saas", label: "SaaS platform" },
  ],
  network: [
    { key: "firewall", label: "Firewall" },
    { key: "vpn", label: "VPN gateway" },
    { key: "router", label: "Router" },
    { key: "switch", label: "Switch" },
    { key: "access_point", label: "Wireless access point" },
    { key: "ids", label: "IDS/IPS sensor" },
    { key: "proxy", label: "Web proxy / gateway" },
    { key: "load_balancer", label: "Load balancer" },
    { key: "nac", label: "Network access control" },
  ],
  identity: [
    { key: "directory", label: "Directory (AD, Entra ID, LDAP)" },
    { key: "idp", label: "Identity provider / SSO" },
    { key: "pam", label: "PAM platform" },
    { key: "service_account", label: "Service account / API key" },
  ],
  iot_ot: [
    { key: "camera", label: "CCTV camera" },
    { key: "printer", label: "Printer" },
    { key: "smart_device", label: "Smart device" },
    { key: "plc", label: "PLC" },
    { key: "scada", label: "SCADA / HMI" },
    { key: "medical", label: "Medical device" },
    { key: "building", label: "Building management" },
    { key: "sensor", label: "Industrial sensor / equipment" },
  ],
  email: [
    { key: "mail_gateway", label: "Email gateway" },
    { key: "collaboration", label: "Collaboration tool" },
  ],
  apps: [
    { key: "web_app", label: "Internet-facing application" },
    { key: "api", label: "API / API gateway" },
    { key: "remote_access", label: "Remote-access portal" },
    { key: "repository", label: "Code repository" },
    { key: "ci_runner", label: "CI/CD runner" },
  ],
};

// Industrial, medical and building systems, as opposed to everyday IoT.
export const OT_TYPES = new Set(["plc", "scada", "medical", "building", "sensor"]);

// Groups that are computers, servers or phones: the ones the device
// controls and the endpoint mix apply to.
export const DEVICE_CLASSES: AssetClass[] = ["user", "mobile", "server"];

export function classFromOs(os: string | null | undefined): AssetClass {
  const t = classifyOs(os);
  return t === "windowsServer" || t === "linuxServer" ? "server" : t === "ios" || t === "android" ? "mobile" : "user";
}

export function endpointClass(e: { assetClass?: string | null; os?: string | null }): AssetClass {
  return isAssetClass(e.assetClass) ? e.assetClass : classFromOs(e.os);
}

export function isAssetClass(v: unknown): v is AssetClass {
  return typeof v === "string" && ASSET_CLASSES.some((c) => c.key === v);
}

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "");

// From an import: the key ("iot_ot"), the label ("IoT & operational
// technology") or a type that implies the group ("firewall").
export function parseAssetClass(text: string | null | undefined, type?: string | null): AssetClass | null {
  if (text) {
    const n = norm(text);
    const hit = ASSET_CLASSES.find((c) => norm(c.key) === n || norm(c.label) === n || norm(c.label).startsWith(n));
    if (hit) return hit.key;
  }
  const t = parseAssetType(type);
  return t ? t.class : null;
}

export function parseAssetType(text: string | null | undefined): { class: AssetClass; type: string } | null {
  if (!text) return null;
  const n = norm(text);
  for (const [cls, types] of Object.entries(ASSET_TYPES) as Array<[AssetClass, Array<{ key: string; label: string }>]>) {
    const hit = types.find((t) => norm(t.key) === n || norm(t.label) === n);
    if (hit) return { class: cls, type: hit.key };
  }
  return null;
}

export function assetTypeLabel(cls: AssetClass, type: string | null | undefined) {
  return ASSET_TYPES[cls].find((t) => t.key === type)?.label ?? null;
}
