import type { LucideIcon } from "lucide-react";
import {
  LayoutDashboard,
  ShieldAlert,
  Search,
  UserCog,
  Mail,
  Globe2,
  Workflow,
  Crosshair,
  ScrollText,
  CreditCard,
  Target,
  Plug,
  Building2,
  Tags,
  Receipt,
} from "lucide-react";

export interface NavItem {
  title: string;
  href: string;
  icon: LucideIcon;
  description: string;
}

const OVERVIEW: NavItem = {
  title: "Overview",
  href: "/",
  icon: LayoutDashboard,
  description: "Cross-source KPIs and system health",
};
const CASES: NavItem = {
  title: "Cases & Alerts",
  href: "/cases",
  icon: ShieldAlert,
  description: "Unified detection and case stream",
};
const INVESTIGATIONS: NavItem = {
  title: "Investigations",
  href: "/investigations",
  icon: Search,
  description: "Multi-agent root-cause analysis",
};
const GOVERNANCE: NavItem = {
  title: "Agent Governance",
  href: "/governance",
  icon: UserCog,
  description: "AI agent identity, trust, and policy",
};
const FORENSICS: NavItem = {
  title: "Email & File Forensics",
  href: "/forensics",
  icon: Mail,
  description: "Sandbox detonation and document forensics",
};
const THREAT_INTEL: NavItem = {
  title: "Threat Intelligence",
  href: "/threat-intel",
  icon: Globe2,
  description: "Shared IOC lookups and enrichment",
};
const PLAYBOOKS: NavItem = {
  title: "Response Playbooks",
  href: "/playbooks",
  icon: Workflow,
  description: "Automated containment workflows",
};
const MITRE: NavItem = {
  title: "MITRE ATT&CK Coverage",
  href: "/mitre",
  icon: Crosshair,
  description: "Technique coverage across all sources",
};
const AUDIT: NavItem = {
  title: "Audit Log",
  href: "/audit",
  icon: ScrollText,
  description: "Hash-chained record of every action",
};
const BILLING: NavItem = {
  title: "Billing",
  href: "/billing",
  icon: CreditCard,
  description: "Plan, usage, and invoices",
};
const PENTEST: NavItem = {
  title: "Pentest",
  href: "/pentest",
  icon: Target,
  description: "Request and track penetration tests",
};
const INTEGRATIONS: NavItem = {
  title: "Integrations",
  href: "/integrations",
  icon: Plug,
  description: "Connect your existing security tools",
};
const ADMIN_ORGANIZATIONS: NavItem = {
  title: "Organizations",
  href: "/admin/organizations",
  icon: Building2,
  description: "Provision and manage tenants",
};
const ADMIN_PLANS: NavItem = {
  title: "Plan Catalog",
  href: "/admin/plans",
  icon: Tags,
  description: "Service x AI tier pricing",
};
const ADMIN_BILLING: NavItem = {
  title: "Platform Billing",
  href: "/admin/billing",
  icon: Receipt,
  description: "Invoices across every tenant",
};

const OPERATIONS: NavItem[] = [
  CASES,
  INVESTIGATIONS,
  GOVERNANCE,
  FORENSICS,
  THREAT_INTEL,
  PLAYBOOKS,
  MITRE,
  AUDIT,
];

// Role-aware nav: platform roles operate across every tenant and get the
// Admin section; org roles only ever see their own tenant's operational
// pages plus the pages a customer actually needs (Billing/Pentest/
// Integrations). ORG_VIEWER is a deliberately reduced read-only subset.
export function getNavItems(role: string): NavItem[] {
  switch (role) {
    case "PLATFORM_OWNER":
    case "PLATFORM_ANALYST":
      return [OVERVIEW, ...OPERATIONS, PENTEST, ADMIN_ORGANIZATIONS, ADMIN_PLANS, ADMIN_BILLING];
    case "ORG_ADMIN":
      return [OVERVIEW, ...OPERATIONS, BILLING, PENTEST, INTEGRATIONS];
    case "ORG_ANALYST":
      return [OVERVIEW, ...OPERATIONS, PENTEST, INTEGRATIONS];
    case "ORG_VIEWER":
    default:
      return [OVERVIEW, CASES];
  }
}

// Kept for any code that still wants "the full set" (e.g. route-title
// lookups that should recognize every possible page regardless of who's
// viewing it).
export const ALL_NAV_ITEMS: NavItem[] = [
  OVERVIEW,
  ...OPERATIONS,
  BILLING,
  PENTEST,
  INTEGRATIONS,
  ADMIN_ORGANIZATIONS,
  ADMIN_PLANS,
  ADMIN_BILLING,
];
