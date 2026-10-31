import type { LucideIcon } from "lucide-react";
import type { UserRole } from "@prisma/client";
import {
  Archive,
  BarChart3,
  Bot,
  Building2,
  Calculator,
  CheckSquare,
  KeyRound,
  Crosshair,
  FileSignature,
  GitPullRequestArrow,
  Landmark,
  Globe2,
  LayoutDashboard,
  Laptop,
  ListChecks,
  PhoneCall,
  Mail,
  Network,
  Plug,
  ScrollText,
  Search,
  Settings,
  SlidersHorizontal,
  ShieldAlert,
  ShieldCheck,
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
  { title: "Approvals", href: "/approvals", icon: CheckSquare, group: "Operate", permission: "containment.approve", description: "Containment, playbooks, regulatory notices and rulebooks waiting on someone's yes" },
  { title: "Endpoints", href: "/endpoints", icon: Laptop, group: "Operate", permission: "endpoints.view", description: "Endpoint inventory, protection coverage and isolation" },
  { title: "Reports", clientTitle: "Service reports", href: "/reports", icon: BarChart3, group: "Operate", permission: "reports.view", description: "Volume, response times, SLA and AI performance by period" },
  { title: "Compliance", href: "/compliance", icon: Landmark, group: "Operate", permission: "compliance.view", description: "CERT-In and DPDP reporting clocks, notices and ISO 27001 evidence" },
  { title: "AI Agents", href: "/ai", icon: Bot, group: "Operate", permission: "ai.view", description: "AI first responders, providers, autonomy and run log" },
  { title: "SOC Operations", href: "/operations", icon: PhoneCall, group: "Operate", permission: "operations.view", description: "Who is on call and the pages they get, weekly QA of what the AI did on its own, and the daily digests" },
  { title: "Investigations", href: "/investigations", icon: Search, group: "Analyze", permission: "investigations.run", description: "Multi-agent root-cause analysis" },
  { title: "Email & File Forensics", href: "/forensics", icon: Mail, group: "Analyze", permission: "forensics.run", description: "Sandbox detonation and document forensics" },
  { title: "Response Playbooks", href: "/playbooks", icon: Workflow, group: "Analyze", permission: "playbooks.view", description: "Automated containment workflows" },
  { title: "Runbooks", href: "/runbooks", icon: ListChecks, group: "Analyze", permission: "operations.view", description: "Procedures for analysts, attached to the cases they match and worked as a checklist" },
  { title: "Detection Engineering", href: "/detections", icon: SlidersHorizontal, group: "Analyze", permission: "detections.tune", description: "Built-in detectors, Sigma rules tested before they go live, and per-client tuning" },
  { title: "Agent Governance", href: "/governance", icon: UserCog, group: "Analyze", permission: "governance.manage", description: "AI agent identity, trust, and policy" },
  { title: "Threat Intelligence", href: "/threat-intel", icon: Globe2, group: "Intelligence", permission: "intel.view", description: "Shared IOC lookups and enrichment" },
  { title: "Attack Graph", href: "/attack-graph", icon: Network, group: "Intelligence", permission: "cases.view", description: "Cases joined by shared hosts, accounts and indicators; attack chains across tactics" },
  { title: "MITRE ATT&CK Coverage", href: "/mitre", icon: Crosshair, group: "Intelligence", permission: "mitre.view", description: "Technique coverage across all sources" },
  { title: "Tools & Integrations", clientTitle: "Security tools", href: "/integrations", icon: Plug, group: "Platform", permission: "integrations.view", description: "Onboard security tools per client, role and user" },
  { title: "Rulebooks", clientTitle: "Our rulebook", href: "/rulebook", icon: ShieldCheck, group: "Platform", permission: "rulebook.view", description: "Each client's rules for what HELIOS may do: protected assets, actions, hours, approvers" },
  { title: "Rule changes", href: "/changes", icon: GitPullRequestArrow, group: "Platform", permission: "rulebook.view", description: "Changes to the rules containment runs under, waiting for the client's and HELIOS's approval" },
  { title: "Clients", href: "/tenants", icon: Building2, group: "Platform", permission: "tenants.view", description: "Client tenants, plans and SLAs" },
  { title: "Team & Roles", href: "/team", icon: Users, group: "Platform", permission: "users.manage", description: "Users, roles, queues and what each role can see" },
  { title: "Data Retention", href: "/retention", icon: Archive, group: "Platform", permission: "audit.view", description: "Where each client's logs are kept, for how long, the archive and legal holds" },
  { title: "Audit Log", href: "/audit", icon: ScrollText, group: "Platform", permission: "audit.view", description: "Hash-chained record of every action" },
  { title: "API Tokens", href: "/api-tokens", icon: KeyRound, group: "Platform", permission: "api.tokens", description: "Personal tokens and the REST API reference" },
  { title: "Settings", href: "/settings", icon: Settings, group: "Platform", permission: "settings.manage", description: "Environment, company profile, provider keys and forensics" },
  { title: "Build & Price", href: "/pricing", icon: Calculator, group: "Commercial", permission: "pricing.view", description: "Configure a protection stack and estimate costs" },
  { title: "Contracts & Billing", clientTitle: "Contracts & invoices", href: "/billing", icon: FileSignature, group: "Commercial", permission: "billing.view", description: "Pilots with measured success criteria, contracts, and GST invoices" },
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

// Pages that aren't in the sidebar but still need a title in the top bar.
export const OTHER_PAGES: Array<Pick<NavItem, "href" | "title" | "description">> = [
  { href: "/account/alerts", title: "My alerts", description: "Which notifications also reach you by email, SMS or WhatsApp" },
  { href: "/digest", title: "Daily digests", description: "What HELIOS did on its own each day, what was waiting, and the deadlines coming up" },
];

export const otherPageFor = (pathname: string) => OTHER_PAGES.find((p) => pathname === p.href || pathname.startsWith(`${p.href}/`));
