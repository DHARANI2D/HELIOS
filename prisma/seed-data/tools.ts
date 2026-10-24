import type { PlaybookActionType } from "@prisma/client";

// Real products HELIOS can onboard, with what each one does and the vendor's
// own published list price where the vendor publishes one (USD per unit per
// month). Vendors that sell by quote have no price: the admin enters what
// they actually pay in Build & Price → Tool catalog before quoting them.
// Re-seeding refreshes these facts but never touches customPrice or active.

export interface SeedTool {
  key: string;
  name: string;
  vendor: string;
  category: string;
  description: string;
  controls: string[];
  actions: PlaybookActionType[];
  ingest: string | null;
  platforms: string[];
  deployment: "cloud" | "self-hosted" | "hybrid";
  offlineCapable: boolean;
  priceUnit: "endpoint" | "user" | "server" | "gb" | "flat";
  listPrice: number | null;
  priceSource: string | null;
}

const QUOTE_ONLY = "Sold by quote through the vendor or its partners";
const OPEN_SOURCE = "Open source; no licence fee";

export const CATALOG_TOOLS: SeedTool[] = [
  // --- EDR / XDR
  {
    key: "crowdstrike_falcon_enterprise", name: "Falcon Enterprise", vendor: "CrowdStrike", category: "edr",
    description: "EDR + NGAV + device control + firewall management on one agent.",
    controls: ["edr", "av", "device_control", "host_firewall"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "KILL_PROCESS", "QUARANTINE_FILE"],
    ingest: "crowdstrike", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: 15.42, priceSource: "$184.99 per device per year — crowdstrike.com/pricing",
  },
  {
    key: "defender_endpoint_p2", name: "Defender for Endpoint P2", vendor: "Microsoft", category: "edr",
    description: "EDR, attack-surface reduction, automated investigation; included in Microsoft 365 E5.",
    controls: ["edr", "av", "host_firewall", "device_control", "app_control", "vuln_scan"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "KILL_PROCESS", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Windows", "macOS", "Linux", "iOS", "Android"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 5.2, priceSource: "$5.20 per user per month (up to 5 devices) — microsoft.com/security/business/endpoint-security/microsoft-defender-endpoint",
  },
  {
    key: "defender_business", name: "Defender for Business", vendor: "Microsoft", category: "edr",
    description: "SMB edition of Defender for Endpoint (up to 300 users); included in Microsoft 365 Business Premium.",
    controls: ["edr", "av", "host_firewall", "vuln_scan"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Windows", "macOS", "Linux", "iOS", "Android"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 3, priceSource: "$3.00 per user per month — microsoft.com/security/business/endpoint-security/microsoft-defender-business",
  },
  {
    key: "sentinelone_complete", name: "Singularity Complete", vendor: "SentinelOne", category: "edr",
    description: "EDR with autonomous remediation and ransomware rollback.",
    controls: ["edr", "av", "device_control", "host_firewall"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "KILL_PROCESS", "QUARANTINE_FILE"],
    ingest: "sentinelone", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: 15, priceSource: "$179.99 per endpoint per year — sentinelone.com/platform-packages",
  },
  {
    key: "sophos_intercept_x", name: "Intercept X Advanced with XDR", vendor: "Sophos", category: "edr",
    description: "EDR/XDR with CryptoGuard anti-ransomware, managed from Sophos Central.",
    controls: ["edr", "av", "device_control", "app_control", "web_filtering"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "QUARANTINE_FILE"],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "wazuh", name: "Wazuh", vendor: "Wazuh", category: "edr",
    description: "Open-source XDR/SIEM: file integrity, threat detection, vulnerability detection, active response. Self-hosted, works fully offline.",
    controls: ["edr", "vuln_scan"], actions: ["BLOCK_IP", "KILL_PROCESS", "DISABLE_USER"],
    ingest: "wazuh", platforms: ["Windows", "macOS", "Linux"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "endpoint", listPrice: 0, priceSource: `${OPEN_SOURCE} — budget hosting and engineering time`,
  },
  // --- EPP / NGAV
  {
    key: "defender_antivirus", name: "Defender Antivirus", vendor: "Microsoft", category: "epp",
    description: "Built into Windows; NGAV with cloud protection and tamper protection.",
    controls: ["av", "host_firewall"], actions: ["QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Windows"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "endpoint", listPrice: 0, priceSource: "Included with Windows",
  },
  {
    key: "crowdstrike_falcon_pro", name: "Falcon Pro", vendor: "CrowdStrike", category: "epp",
    description: "NGAV with device control and firewall management (no EDR).",
    controls: ["av", "device_control", "host_firewall"], actions: ["QUARANTINE_FILE"],
    ingest: "crowdstrike", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: 8.33, priceSource: "$99.99 per device per year — crowdstrike.com/pricing",
  },
  {
    key: "sentinelone_core", name: "Singularity Core", vendor: "SentinelOne", category: "epp",
    description: "NGAV with behavioral AI and rollback.",
    controls: ["av"], actions: ["QUARANTINE_FILE"],
    ingest: "sentinelone", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: 5.83, priceSource: "$69.99 per endpoint per year — sentinelone.com/platform-packages",
  },
  {
    key: "clamav", name: "ClamAV", vendor: "Cisco Talos", category: "epp",
    description: "Open-source scanner for Linux servers, mail gateways and file shares.",
    controls: ["av"], actions: [],
    ingest: "generic", platforms: ["Linux", "macOS", "Windows"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "server", listPrice: 0, priceSource: OPEN_SOURCE,
  },
  // --- MDM / UEM
  {
    key: "intune_p1", name: "Intune Plan 1", vendor: "Microsoft", category: "mdm",
    description: "Device enrollment, compliance, BitLocker/FileVault policy and update rings; included in Microsoft 365 E3/E5/Business Premium.",
    controls: ["mdm", "disk_encryption", "patching", "app_control"], actions: [],
    ingest: "generic", platforms: ["Windows", "macOS", "iOS", "Android", "Linux"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 8, priceSource: "$8.00 per user per month — microsoft.com/security/business/microsoft-intune-pricing",
  },
  {
    key: "jamf_pro", name: "Jamf Pro", vendor: "Jamf", category: "mdm",
    description: "Apple device management: enrollment, FileVault, patching and app deployment.",
    controls: ["mdm", "disk_encryption", "patching"], actions: [],
    ingest: "generic", platforms: ["macOS", "iOS"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: null, priceSource: QUOTE_ONLY,
  },
  // --- Patch & vulnerability
  {
    key: "defender_vm", name: "Defender Vulnerability Management add-on", vendor: "Microsoft", category: "vuln",
    description: "Adds full vulnerability assessment and security baselines to Defender for Endpoint P2.",
    controls: ["vuln_scan"], actions: [],
    ingest: "defender", platforms: ["Windows", "macOS", "Linux"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 2, priceSource: "$2.00 per user per month — microsoft.com/security/business/threat-protection/microsoft-defender-vulnerability-management",
  },
  {
    key: "tenable_vm", name: "Tenable Vulnerability Management", vendor: "Tenable", category: "vuln",
    description: "Agent and network scanning with risk-based prioritization.",
    controls: ["vuln_scan"], actions: [],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux", "Network"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: null, priceSource: QUOTE_ONLY,
  },
  // --- Email
  {
    key: "defender_o365_p1", name: "Defender for Office 365 P1", vendor: "Microsoft", category: "email",
    description: "Safe Links, Safe Attachments and anti-phishing for Exchange Online.",
    controls: [], actions: ["BLOCK_SENDER", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Microsoft 365"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 2, priceSource: "$2.00 per user per month — microsoft.com/security/business/siem-and-xdr/microsoft-defender-office-365",
  },
  {
    key: "defender_o365_p2", name: "Defender for Office 365 P2", vendor: "Microsoft", category: "email",
    description: "P1 plus Threat Explorer, automated investigation and attack simulation training.",
    controls: [], actions: ["BLOCK_SENDER", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Microsoft 365"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 5, priceSource: "$5.00 per user per month — microsoft.com/security/business/siem-and-xdr/microsoft-defender-office-365",
  },
  {
    key: "proofpoint_essentials", name: "Proofpoint Essentials", vendor: "Proofpoint", category: "email",
    description: "SMB secure email gateway with URL defense and attachment sandboxing.",
    controls: [], actions: ["BLOCK_SENDER", "QUARANTINE_FILE"],
    ingest: "generic", platforms: ["Microsoft 365", "Google Workspace"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: null, priceSource: QUOTE_ONLY,
  },
  // --- Identity
  {
    key: "entra_p1", name: "Entra ID P1", vendor: "Microsoft", category: "identity",
    description: "Conditional Access, MFA and sign-in logs; included in Microsoft 365 E3/Business Premium.",
    controls: [], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "entra", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 6, priceSource: "$6.00 per user per month — microsoft.com/security/business/microsoft-entra-pricing",
  },
  {
    key: "entra_p2", name: "Entra ID P2", vendor: "Microsoft", category: "identity",
    description: "P1 plus ID Protection (risky sign-ins) and Privileged Identity Management.",
    controls: [], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "entra", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 9, priceSource: "$9.00 per user per month — microsoft.com/security/business/microsoft-entra-pricing",
  },
  {
    key: "okta_workforce", name: "Workforce Identity (SSO + MFA)", vendor: "Okta", category: "identity",
    description: "SSO and adaptive MFA with System Log streaming.",
    controls: [], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "okta", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 5, priceSource: "SSO from $2 + MFA from $3 per user per month — okta.com/pricing",
  },
  {
    key: "duo_advantage", name: "Duo Advantage", vendor: "Cisco", category: "identity",
    description: "MFA with device trust and risk-based authentication.",
    controls: [], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 6, priceSource: "$6 per user per month — duo.com/pricing",
  },
  // --- Network
  {
    key: "cloudflare_zero_trust", name: "Zero Trust (Gateway + Access)", vendor: "Cloudflare", category: "network",
    description: "DNS/HTTP filtering and zero-trust access; free tier up to 50 users.",
    controls: ["web_filtering"], actions: ["BLOCK_IP"],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux", "iOS", "Android"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 7, priceSource: "$7 per user per month (pay-as-you-go) — cloudflare.com/plans/zero-trust-services",
  },
  {
    key: "opnsense", name: "OPNsense / pfSense", vendor: "Open source", category: "network",
    description: "Open-source firewall; HELIOS blocks IPs through a firewall alias.",
    controls: ["web_filtering"], actions: ["BLOCK_IP", "UNBLOCK_IP"],
    ingest: "generic", platforms: ["Appliance"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "flat", listPrice: 0, priceSource: `${OPEN_SOURCE}; hardware is separate`,
  },
  {
    key: "fortigate", name: "FortiGate NGFW", vendor: "Fortinet", category: "network",
    description: "Next-generation firewall with IPS, web filtering and SD-WAN.",
    controls: ["web_filtering"], actions: ["BLOCK_IP", "UNBLOCK_IP"],
    ingest: "generic", platforms: ["Appliance"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "flat", listPrice: null, priceSource: QUOTE_ONLY,
  },
  // --- DLP
  {
    key: "purview_e5_compliance", name: "Purview (E5 Compliance add-on)", vendor: "Microsoft", category: "dlp",
    description: "Endpoint and cloud DLP, insider-risk management, sensitivity labels.",
    controls: ["dlp"], actions: [],
    ingest: "defender", platforms: ["Windows", "macOS", "Microsoft 365"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 12, priceSource: "$12.00 per user per month — microsoft.com/microsoft-365/enterprise/microsoft365-plans-and-pricing",
  },
  // --- SIEM
  {
    key: "ms_sentinel", name: "Microsoft Sentinel", vendor: "Microsoft", category: "siem",
    description: "Cloud SIEM billed on data ingested; many Microsoft 365 sources ingest free.",
    controls: [], actions: [],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "gb", listPrice: null, priceSource: "Pay-as-you-go per GB, varies by region and commitment tier — azure.microsoft.com/pricing/details/microsoft-sentinel",
  },
  {
    key: "splunk_cloud", name: "Splunk Cloud Platform", vendor: "Splunk", category: "siem",
    description: "Enterprise SIEM; ingest- or workload-based licensing.",
    controls: [], actions: [],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "gb", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "helios_siem", name: "HELIOS built-in detection", vendor: "HELIOS", category: "siem",
    description: "This platform's own detection engine and telemetry store.",
    controls: [], actions: [],
    ingest: "generic", platforms: ["Any"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "gb", listPrice: 0, priceSource: "Part of the HELIOS service plan",
  },
  // --- Backup
  {
    key: "m365_backup", name: "Microsoft 365 Backup", vendor: "Microsoft", category: "backup",
    description: "Fast-restore backup for Exchange, OneDrive and SharePoint.",
    controls: ["backup"], actions: [],
    ingest: null, platforms: ["Microsoft 365"], deployment: "cloud", offlineCapable: false,
    priceUnit: "gb", listPrice: 0.15, priceSource: "$0.15 per GB of protected data per month — learn.microsoft.com/microsoft-365/backup/backup-pricing",
  },
  {
    key: "acronis_cyber_protect", name: "Cyber Protect", vendor: "Acronis", category: "backup",
    description: "Endpoint backup with immutable storage and anti-ransomware.",
    controls: ["backup"], actions: [],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "endpoint", listPrice: null, priceSource: QUOTE_ONLY,
  },
  // --- Ticketing, chat, automation: the client's existing tools, not resold.
  {
    key: "jira_sm", name: "Jira Service Management", vendor: "Atlassian", category: "ticketing",
    description: "Sync HELIOS cases to the client's service desk.",
    controls: [], actions: ["CREATE_TICKET"], ingest: null, platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "flat", listPrice: null, priceSource: null,
  },
  {
    key: "servicenow", name: "ServiceNow ITSM", vendor: "ServiceNow", category: "ticketing",
    description: "Sync HELIOS cases to ServiceNow incidents.",
    controls: [], actions: ["CREATE_TICKET"], ingest: null, platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "flat", listPrice: null, priceSource: null,
  },
  {
    key: "slack", name: "Slack", vendor: "Salesforce", category: "chatops",
    description: "Post alerts and approvals to a channel through an incoming webhook.",
    controls: [], actions: ["NOTIFY_SLACK"], ingest: null, platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "flat", listPrice: null, priceSource: null,
  },
  {
    key: "teams", name: "Microsoft Teams", vendor: "Microsoft", category: "chatops",
    description: "Post alerts to a Teams channel through a workflow webhook.",
    controls: [], actions: ["NOTIFY_SLACK"], ingest: null, platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "flat", listPrice: null, priceSource: null,
  },
  {
    key: "response_webhook", name: "Response webhook (SOAR, n8n, Tines, scripts)", vendor: "Generic", category: "automation",
    description: "HELIOS POSTs each approved response action as signed JSON; your automation carries it out and the result lands on the case.",
    controls: [], actions: ["ISOLATE_HOST", "RELEASE_HOST", "BLOCK_IP", "UNBLOCK_IP", "DISABLE_USER", "ENABLE_USER", "KILL_PROCESS", "QUARANTINE_FILE", "BLOCK_SENDER", "CREATE_TICKET"],
    ingest: "generic", platforms: ["Any"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "flat", listPrice: null, priceSource: null,
  },
];
