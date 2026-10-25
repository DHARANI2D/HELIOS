import { z } from "zod";

// What a client has beyond computers, servers and phones (those are the
// endpoint mix), and what kind of organization it is. Both live in the
// quote config; the organization drives which asset groups come first.
// Client-safe and pure.

const count = z.number().int().min(0).max(1_000_000).default(0);

export const estateSchema = z.object({
  cloudAccounts: count, // AWS accounts, Azure subscriptions, GCP projects
  cloudWorkloads: count, // VMs, Kubernetes nodes, serverless and container workloads
  saasApps: count, // Microsoft 365, Google Workspace, Salesforce…
  networkDevices: count, // firewalls, VPNs, routers, switches, access points, proxies
  privilegedAccounts: count, // admin and service accounts
  iotDevices: count, // cameras, printers, smart devices
  otDevices: count, // PLCs, SCADA/HMI, medical and building systems
  internetApps: count, // internet-facing websites, portals and APIs
  developers: count, // people committing code to the organization's repositories
});
export type Estate = z.infer<typeof estateSchema>;
export const EMPTY_ESTATE: Estate = estateSchema.parse({});

export const ESTATE_FIELDS: Array<{ key: keyof Estate; label: string; hint: string }> = [
  { key: "cloudAccounts", label: "Cloud accounts", hint: "AWS accounts, Azure subscriptions, Google Cloud projects" },
  { key: "cloudWorkloads", label: "Cloud workloads", hint: "VMs, Kubernetes nodes, containers and serverless functions" },
  { key: "saasApps", label: "SaaS platforms", hint: "Microsoft 365, Google Workspace, Salesforce…" },
  { key: "networkDevices", label: "Network & security devices", hint: "Firewalls, VPN gateways, routers, switches, access points, proxies" },
  { key: "privilegedAccounts", label: "Admin & service accounts", hint: "Privileged users, service accounts, API keys" },
  { key: "iotDevices", label: "IoT devices", hint: "CCTV cameras, printers, smart devices" },
  { key: "otDevices", label: "OT / medical devices", hint: "PLCs, SCADA and HMIs, medical devices, building management" },
  { key: "internetApps", label: "Internet-facing apps & APIs", hint: "Websites, customer portals, APIs, remote-access portals" },
  { key: "developers", label: "Developers", hint: "People committing to your repositories and CI/CD" },
];

export const COMPANY_TYPES = { small: "Small business", mid: "Mid-sized enterprise", large: "Large enterprise", regulated: "Regulated / industrial company" } as const;
export const INDUSTRIES = {
  general: "General business",
  healthcare: "Healthcare",
  manufacturing: "Manufacturing",
  energy: "Energy & utilities",
  finance: "Finance & insurance",
  retail: "Retail & e-commerce",
  technology: "Technology & software",
  education: "Education",
  public: "Public sector",
} as const;
export const ENVIRONMENTS = { onprem: "On-premises infrastructure", cloud: "Cloud-first", hybrid: "Hybrid: on-premises and cloud", ot: "Industrial / OT-heavy" } as const;
export const MATURITY = { none: "No dedicated security tools", some: "Some security tools deployed", mature: "Mature SOC and existing SIEM" } as const;
export const DELIVERY = {
  edr: "Endpoint security deployment (EDR/XDR)",
  soc: "Centralized SOC monitoring",
  complete: "Complete cybersecurity solution",
  ai: "AI-driven security platform",
} as const;

const key = <T extends Record<string, string>>(o: T) => Object.keys(o) as [keyof T & string, ...(keyof T & string)[]];

export const contextSchema = z.object({
  companyType: z.enum(key(COMPANY_TYPES)).nullable().default(null),
  industry: z.enum(key(INDUSTRIES)).default("general"),
  environment: z.enum(key(ENVIRONMENTS)).nullable().default(null),
  maturity: z.enum(key(MATURITY)).nullable().default(null),
  delivery: z.enum(key(DELIVERY)).nullable().default(null),
});
export type OrgContext = z.infer<typeof contextSchema>;
export const EMPTY_CONTEXT: OrgContext = contextSchema.parse({});

export function usersBracket(users: number) {
  if (users <= 0) return null;
  if (users < 100) return "Under 100 users";
  if (users <= 500) return "100–500 users";
  if (users <= 2000) return "500–2,000 users";
  return "Over 2,000 users";
}
