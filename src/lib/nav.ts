import type { LucideIcon } from "lucide-react";
import type { UserRole } from "@prisma/client";
import {
  BarChart3,
  Bot,
  Building2,
  Calculator,
  KeyRound,
  Crosshair,
  Globe2,
  LayoutDashboard,
  Laptop,
  Mail,
  Network,
  Plug,
  ScrollText,
  Search,
  Settings,
  ShieldAlert,
  UserCog,
  Users,
  Workflow,
} from "lucide-react";

import { can, isClientRole, type Permission } from "@/lib/rbac";

export type NavGroup = "Operate" | "Analyze" | "Intelligence" | "Platform" | "Commercial";

export interface NavItem {
  title: string;
  // What client users see instead (they look at their own estate, not a SOC).
  clientTitle?: string;
  href: string;
  icon: LucideIcon;
  description: string;
  group: NavGroup;
  permission: Permission;
}

export const NAV_GROUPS: NavGroup[] = ["Operate", "Analyze", "Intelligence", "Platform", "Commercial"];

export const NAV_ITEMS: NavItem[] = [
  { title: "Overview", href: "/", icon: LayoutDashboard, group: "Operate", permission: "dashboard.view", description: "Live posture, queues, SLAs and AI activity" },
  { title: "Cases & Alerts", clientTitle: "Incidents", href: "/cases", icon: ShieldAlert, group: "Operate", permission: "cases.view", description: "Unified detection and case stream" },
  { title: "Endpoints", href: "/endpoints", icon: Laptop, group: "Operate", permission: "endpoints.view", description: "Endpoint inventory, protection coverage and isolation" },
  { title: "Reports", clientTitle: "Service reports", href: "/reports", icon: BarChart3, group: "Operate", permission: "reports.view", description: "Volume, response times, SLA and AI performance by period" },
  { title: "AI Agents", href: "/ai", icon: Bot, group: "Operate", permission: "ai.view", description: "AI first responders, providers, autonomy and run log" },
  { title: "Investigations", href: "/investigations", icon: Search, group: "Analyze", permission: "investigations.run", description: "Multi-agent root-cause analysis" },
  { title: "Email & File Forensics", href: "/forensics", icon: Mail, group: "Analyze", permission: "forensics.run", description: "Sandbox detonation and document forensics" },
  { title: "Response Playbooks", href: "/playbooks", icon: Workflow, group: "Analyze", permission: "playbooks.view", description: "Automated containment workflows" },
  { title: "Agent Governance", href: "/governance", icon: UserCog, group: "Analyze", permission: "governance.manage", description: "AI agent identity, trust, and policy" },
  { title: "Threat Intelligence", href: "/threat-intel", icon: Globe2, group: "Intelligence", permission: "intel.view", description: "Shared IOC lookups and enrichment" },
  { title: "Attack Graph", href: "/attack-graph", icon: Network, group: "Intelligence", permission: "cases.view", description: "Cases joined by shared hosts, accounts and indicators; attack chains across tactics" },
  { title: "MITRE ATT&CK Coverage", href: "/mitre", icon: Crosshair, group: "Intelligence", permission: "mitre.view", description: "Technique coverage across all sources" },
  { title: "Tools & Integrations", clientTitle: "Security tools", href: "/integrations", icon: Plug, group: "Platform", permission: "integrations.view", description: "Onboard security tools per client, role and user" },
  { title: "Clients", href: "/tenants", icon: Building2, group: "Platform", permission: "tenants.view", description: "Client tenants, plans and SLAs" },
  { title: "Team & Roles", href: "/team", icon: Users, group: "Platform", permission: "users.manage", description: "Users, roles, queues and what each role can see" },
  { title: "Audit Log", href: "/audit", icon: ScrollText, group: "Platform", permission: "audit.view", description: "Hash-chained record of every action" },
  { title: "API Tokens", href: "/api-tokens", icon: KeyRound, group: "Platform", permission: "api.tokens", description: "Personal tokens and the REST API reference" },
  { title: "Settings", href: "/settings", icon: Settings, group: "Platform", permission: "settings.manage", description: "Environment, company profile, provider keys and forensics" },
  { title: "Build & Price", href: "/pricing", icon: Calculator, group: "Commercial", permission: "pricing.view", description: "Configure a protection stack and estimate costs" },
];

export function navFor(role: UserRole): NavItem[] {
  const client = isClientRole(role);
  return NAV_ITEMS.filter((item) => can({ role }, item.permission)).map((item) =>
    client && item.clientTitle ? { ...item, title: item.clientTitle } : item,
  );
}

export function navItemFor(pathname: string, items: NavItem[] = NAV_ITEMS): NavItem | undefined {
  return items
    .filter((item) => (item.href === "/" ? pathname === "/" : pathname === item.href || pathname.startsWith(`${item.href}/`)))
    .sort((a, b) => b.href.length - a.href.length)[0];
}
