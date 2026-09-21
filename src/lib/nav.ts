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
} from "lucide-react";

export interface NavItem {
  title: string;
  href: string;
  icon: LucideIcon;
  description: string;
}

export const NAV_ITEMS: NavItem[] = [
  {
    title: "Overview",
    href: "/",
    icon: LayoutDashboard,
    description: "Cross-source KPIs and system health",
  },
  {
    title: "Cases & Alerts",
    href: "/cases",
    icon: ShieldAlert,
    description: "Unified detection and case stream",
  },
  {
    title: "Investigations",
    href: "/investigations",
    icon: Search,
    description: "Multi-agent root-cause analysis",
  },
  {
    title: "Agent Governance",
    href: "/governance",
    icon: UserCog,
    description: "AI agent identity, trust, and policy",
  },
  {
    title: "Email & File Forensics",
    href: "/forensics",
    icon: Mail,
    description: "Sandbox detonation and document forensics",
  },
  {
    title: "Threat Intelligence",
    href: "/threat-intel",
    icon: Globe2,
    description: "Shared IOC lookups and enrichment",
  },
  {
    title: "Response Playbooks",
    href: "/playbooks",
    icon: Workflow,
    description: "Automated containment workflows",
  },
  {
    title: "MITRE ATT&CK Coverage",
    href: "/mitre",
    icon: Crosshair,
    description: "Technique coverage across all sources",
  },
  {
    title: "Audit Log",
    href: "/audit",
    icon: ScrollText,
    description: "Hash-chained record of every action",
  },
];
