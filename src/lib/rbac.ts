import type { SecurityDomain, UserRole } from "@prisma/client";

// Role-based access for an MSSP: who can do what, and who sees which
// tenants and queues. Client-safe (no database access) so navigation and
// components can hide what a role can't use; every Server Action and page
// still re-checks on the server through lib/session.

export const PERMISSIONS = {
  "dashboard.view": "See the overview dashboard",
  "cases.view": "See cases in their queues (or their own tenant, for clients)",
  "cases.view_all": "See every queue, regardless of assigned security domains",
  "cases.triage": "Acknowledge cases, change status and severity",
  "cases.assign": "Assign cases to other analysts",
  "cases.escalate": "Escalate or hand off a case to the next tier",
  "cases.comment": "Comment on cases and @mention teammates",
  "cases.share": "Share cases with the client and external channels",
  "containment.request": "Run containment playbooks (subject to approval)",
  "containment.approve": "Approve or reject pending containment",
  "investigations.run": "Run log investigations",
  "forensics.run": "Submit emails and files for forensic analysis",
  "governance.manage": "Run AI-agent governance scenarios",
  "simulation.run": "Replay attack simulations and ingest test telemetry",
  "intel.view": "Look up threat indicators",
  "intel.manage": "Edit the blocklist and indicator store",
  "playbooks.view": "See response playbooks",
  "playbooks.manage": "Author and enable response playbooks",
  "mitre.view": "See ATT&CK coverage",
  "audit.view": "Read the audit chain",
  "audit.export": "Export the audit chain",
  "ai.view": "See AI agent runs and configuration",
  "ai.dispatch": "Dispatch AI agents onto a case",
  "ai.feedback": "Rate AI agent output",
  "ai.configure": "Configure AI providers, agent profiles and autonomy",
  "integrations.view": "See onboarded security tools",
  "integrations.manage": "Onboard and configure security tools",
  "endpoints.view": "See the endpoint inventory and protection coverage",
  "endpoints.contain": "Isolate and release endpoints directly",
  "tenants.view": "See client tenants",
  "tenants.manage": "Create and edit client tenants",
  "users.manage": "Invite users and change roles",
  "pricing.view": "Use the Build & Price configurator",
  "pricing.margin": "See internal cost and margin",
  "pricing.manage": "Edit the price book",
  "reports.view": "Read client-facing incident reports",
} as const;

export type Permission = keyof typeof PERMISSIONS;

export type RoleGroup = "Leadership" | "Security operations" | "Engineering" | "Governance" | "Commercial" | "Client";

export interface RoleInfo {
  label: string;
  group: RoleGroup;
  description: string;
  client?: boolean;
}

export const ROLES: Record<UserRole, RoleInfo> = {
  ADMIN: { label: "Platform admin", group: "Leadership", description: "Owns the platform: users, AI configuration, price book, everything else." },
  SOC_MANAGER: { label: "SOC manager", group: "Leadership", description: "Runs the SOC: every queue, approvals, AI autonomy, tool onboarding." },
  TRIAGE_ANALYST: { label: "Tier-1 triage analyst", group: "Security operations", description: "Works the first-line queue: acknowledges, validates AI triage, escalates." },
  ANALYST: { label: "Tier-2 security analyst", group: "Security operations", description: "Primary analysis: investigations, forensics, containment requests." },
  INCIDENT_RESPONDER: { label: "Tier-3 incident responder", group: "Security operations", description: "Owns major incidents: approves containment, isolates endpoints, client comms." },
  THREAT_HUNTER: { label: "Threat hunter", group: "Security operations", description: "Hunts across all tenants with investigations, forensics and intel." },
  DETECTION_ENGINEER: { label: "Detection engineer", group: "Engineering", description: "Maintains playbooks, detections, tool integrations and ATT&CK coverage." },
  AUDITOR: { label: "Auditor / compliance", group: "Governance", description: "Read-only oversight: cases, AI decisions and the audit chain." },
  SALES: { label: "Account manager", group: "Commercial", description: "Client onboarding, Build & Price quotes and margins." },
  CLIENT_ADMIN: { label: "Client admin", group: "Client", client: true, description: "Client-side: their own tenant's cases and tools; approves containment on their estate." },
  CLIENT_VIEWER: { label: "Client stakeholder", group: "Client", client: true, description: "Client-side read-only: dashboards, incident reports and endpoint coverage." },
};

export const ROLE_ORDER: UserRole[] = [
  "ADMIN",
  "SOC_MANAGER",
  "TRIAGE_ANALYST",
  "ANALYST",
  "INCIDENT_RESPONDER",
  "THREAT_HUNTER",
  "DETECTION_ENGINEER",
  "AUDITOR",
  "SALES",
  "CLIENT_ADMIN",
  "CLIENT_VIEWER",
];

const ALL = Object.keys(PERMISSIONS) as Permission[];
const SOC_BASE: Permission[] = ["dashboard.view", "cases.view", "cases.comment", "intel.view", "playbooks.view", "mitre.view", "ai.view", "endpoints.view", "integrations.view", "tenants.view"];

export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  ADMIN: ALL,
  SOC_MANAGER: ALL.filter((p) => !["users.manage", "pricing.manage", "pricing.margin"].includes(p)),
  TRIAGE_ANALYST: [...SOC_BASE, "cases.triage", "cases.escalate", "containment.request", "ai.dispatch", "ai.feedback"],
  ANALYST: [
    ...SOC_BASE,
    "cases.triage",
    "cases.assign",
    "cases.escalate",
    "cases.share",
    "containment.request",
    "investigations.run",
    "forensics.run",
    "governance.manage",
    "simulation.run",
    "intel.manage",
    "ai.dispatch",
    "ai.feedback",
    "reports.view",
  ],
  INCIDENT_RESPONDER: [
    ...SOC_BASE,
    "cases.view_all",
    "cases.triage",
    "cases.assign",
    "cases.escalate",
    "cases.share",
    "containment.request",
    "containment.approve",
    "investigations.run",
    "forensics.run",
    "governance.manage",
    "simulation.run",
    "intel.manage",
    "ai.dispatch",
    "ai.feedback",
    "endpoints.contain",
    "reports.view",
  ],
  THREAT_HUNTER: [...SOC_BASE, "cases.view_all", "cases.escalate", "investigations.run", "forensics.run", "simulation.run", "intel.manage", "ai.dispatch", "ai.feedback"],
  DETECTION_ENGINEER: [...SOC_BASE, "cases.view_all", "playbooks.manage", "simulation.run", "integrations.manage", "ai.dispatch"],
  AUDITOR: ["dashboard.view", "cases.view", "cases.view_all", "audit.view", "audit.export", "ai.view", "playbooks.view", "mitre.view", "intel.view", "integrations.view", "endpoints.view", "tenants.view", "reports.view"],
  SALES: ["dashboard.view", "tenants.view", "tenants.manage", "pricing.view", "pricing.margin", "integrations.view"],
  CLIENT_ADMIN: ["dashboard.view", "cases.view", "cases.comment", "containment.approve", "reports.view", "integrations.view", "integrations.manage", "endpoints.view"],
  CLIENT_VIEWER: ["dashboard.view", "cases.view", "reports.view", "endpoints.view"],
};

export interface AccessSubject {
  id: string;
  role: UserRole;
  tenantId: string | null;
  domains: SecurityDomain[];
}

export function can(user: Pick<AccessSubject, "role"> | null | undefined, permission: Permission): boolean {
  if (!user) return false;
  return ROLE_PERMISSIONS[user.role]?.includes(permission) ?? false;
}

export function isClientRole(role: UserRole): boolean {
  return !!ROLES[role]?.client;
}

export function roleLabel(role: UserRole | string): string {
  return ROLES[role as UserRole]?.label ?? role;
}

export const SECURITY_DOMAINS: SecurityDomain[] = ["ENDPOINT", "EMAIL", "IDENTITY", "NETWORK", "CLOUD", "AI_AGENTS"];

export const DOMAIN_LABEL: Record<SecurityDomain, string> = {
  ENDPOINT: "Endpoint",
  EMAIL: "Email",
  IDENTITY: "Identity",
  NETWORK: "Network",
  CLOUD: "Cloud",
  AI_AGENTS: "AI agents",
};
