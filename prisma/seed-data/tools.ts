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
  priceUnit: "endpoint" | "user" | "server" | "gb" | "flat" | "workload" | "account" | "device" | "asset" | "app" | "developer" | "admin";
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
    controls: ["edr", "av", "host_firewall", "device_control", "app_control", "vuln_scan", "mtd"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "KILL_PROCESS", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Windows", "macOS", "Linux", "iOS", "Android"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 5.2, priceSource: "$5.20 per user per month (up to 5 devices) — microsoft.com/security/business/endpoint-security/microsoft-defender-endpoint",
  },
  {
    key: "defender_business", name: "Defender for Business", vendor: "Microsoft", category: "edr",
    description: "SMB edition of Defender for Endpoint (up to 300 users); included in Microsoft 365 Business Premium.",
    controls: ["edr", "av", "host_firewall", "vuln_scan", "mtd"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "QUARANTINE_FILE"],
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
    controls: ["edr", "vuln_scan", "siem"], actions: ["BLOCK_IP", "KILL_PROCESS", "DISABLE_USER"],
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
    controls: ["email_security"], actions: ["BLOCK_SENDER", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Microsoft 365"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 2, priceSource: "$2.00 per user per month — microsoft.com/security/business/siem-and-xdr/microsoft-defender-office-365",
  },
  {
    key: "defender_o365_p2", name: "Defender for Office 365 P2", vendor: "Microsoft", category: "email",
    description: "P1 plus Threat Explorer, automated investigation and attack simulation training.",
    controls: ["email_security"], actions: ["BLOCK_SENDER", "QUARANTINE_FILE"],
    ingest: "defender", platforms: ["Microsoft 365"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 5, priceSource: "$5.00 per user per month — microsoft.com/security/business/siem-and-xdr/microsoft-defender-office-365",
  },
  {
    key: "proofpoint_essentials", name: "Proofpoint Essentials", vendor: "Proofpoint", category: "email",
    description: "SMB secure email gateway with URL defense and attachment sandboxing.",
    controls: ["email_security"], actions: ["BLOCK_SENDER", "QUARANTINE_FILE"],
    ingest: "generic", platforms: ["Microsoft 365", "Google Workspace"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: null, priceSource: QUOTE_ONLY,
  },
  // --- Identity
  {
    key: "entra_p1", name: "Entra ID P1", vendor: "Microsoft", category: "identity",
    description: "Conditional Access, MFA and sign-in logs; included in Microsoft 365 E3/Business Premium.",
    controls: ["mfa"], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "entra", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 6, priceSource: "$6.00 per user per month — microsoft.com/security/business/microsoft-entra-pricing",
  },
  {
    key: "entra_p2", name: "Entra ID P2", vendor: "Microsoft", category: "identity",
    description: "P1 plus ID Protection (risky sign-ins) and Privileged Identity Management.",
    controls: ["mfa", "itdr", "pam"], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "entra", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 9, priceSource: "$9.00 per user per month — microsoft.com/security/business/microsoft-entra-pricing",
  },
  {
    key: "okta_workforce", name: "Workforce Identity (SSO + MFA)", vendor: "Okta", category: "identity",
    description: "SSO and adaptive MFA with System Log streaming.",
    controls: ["mfa"], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "okta", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: 5, priceSource: "SSO from $2 + MFA from $3 per user per month — okta.com/pricing",
  },
  {
    key: "google_workspace", name: "Workspace", vendor: "Google", category: "identity",
    description: "Google Workspace sign-ins and account warnings from the Admin SDK Reports API.",
    controls: ["mfa"], actions: [],
    ingest: "google_workspace", platforms: ["Google Workspace"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "duo_advantage", name: "Duo Advantage", vendor: "Cisco", category: "identity",
    description: "MFA with device trust and risk-based authentication.",
    controls: ["mfa"], actions: ["DISABLE_USER", "ENABLE_USER"],
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
    controls: ["web_filtering", "ndr"], actions: ["BLOCK_IP", "UNBLOCK_IP"],
    ingest: "generic", platforms: ["Appliance"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "flat", listPrice: 0, priceSource: `${OPEN_SOURCE}; hardware is separate`,
  },
  {
    key: "fortigate", name: "FortiGate NGFW", vendor: "Fortinet", category: "network",
    description: "Next-generation firewall with IPS, web filtering and SD-WAN.",
    controls: ["web_filtering", "ndr"], actions: ["BLOCK_IP", "UNBLOCK_IP"],
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
    controls: ["siem"], actions: [],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "gb", listPrice: null, priceSource: "Pay-as-you-go per GB, varies by region and commitment tier — azure.microsoft.com/pricing/details/microsoft-sentinel",
  },
  {
    key: "splunk_cloud", name: "Splunk Cloud Platform", vendor: "Splunk", category: "siem",
    description: "Enterprise SIEM; ingest- or workload-based licensing.",
    controls: ["siem"], actions: [],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "gb", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "helios_forwarder", name: "HELIOS log forwarder", vendor: "HELIOS", category: "siem",
    description: "A HELIOS-configured Fluent Bit that collects syslog from firewalls and network gear, Windows event logs and log files, buffers to disk and sends them compressed over HTTPS.",
    controls: ["siem"], actions: [],
    ingest: "forwarder", platforms: ["Windows", "Linux"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "flat", listPrice: 0, priceSource: "Fluent Bit is open source (Apache 2.0); part of the HELIOS service plan",
  },
  {
    key: "helios_siem", name: "HELIOS built-in detection", vendor: "HELIOS", category: "siem",
    description: "This platform's own detection engine and telemetry store.",
    controls: ["siem"], actions: [],
    ingest: "generic", platforms: ["Any"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "gb", listPrice: 0, priceSource: "Part of the HELIOS service plan",
  },
  {
    key: "aws_cloudtrail", name: "CloudTrail", vendor: "AWS", category: "cloud",
    description: "AWS account activity: console sign-ins and every management API call, collected from the trail's S3 bucket through an SQS queue.",
    controls: ["cspm"], actions: [],
    ingest: "cloudtrail", platforms: ["AWS"], deployment: "cloud", offlineCapable: false,
    priceUnit: "flat", listPrice: 0, priceSource: "The first copy of management events is free; data events and extra trails are billed by AWS",
  },
  {
    key: "azure_activity", name: "Azure Activity Log", vendor: "Microsoft", category: "cloud",
    description: "Control-plane activity across Azure subscriptions: who created, changed or deleted which resource.",
    controls: ["cspm"], actions: [],
    ingest: "azure_activity", platforms: ["Azure"], deployment: "cloud", offlineCapable: false,
    priceUnit: "flat", listPrice: 0, priceSource: "Included with every Azure subscription (90 days)",
  },
  {
    key: "gcp_audit_logs", name: "Cloud Audit Logs", vendor: "Google", category: "cloud",
    description: "Google Cloud admin activity audit logs, routed to a Pub/Sub topic for HELIOS to pull.",
    controls: ["cspm"], actions: [],
    ingest: "gcp_audit", platforms: ["Google Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "flat", listPrice: 0, priceSource: "Admin Activity logs are free; Pub/Sub usage is billed by Google",
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
    controls: ["soar"], actions: ["ISOLATE_HOST", "RELEASE_HOST", "BLOCK_IP", "UNBLOCK_IP", "DISABLE_USER", "ENABLE_USER", "KILL_PROCESS", "QUARANTINE_FILE", "BLOCK_SENDER", "CREATE_TICKET"],
    ingest: "generic", platforms: ["Any"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "flat", listPrice: null, priceSource: null,
  },
  // --- Mobile threat defense
  {
    key: "lookout_mes", name: "Mobile Endpoint Security", vendor: "Lookout", category: "mtd",
    description: "Mobile threat defense for iOS and Android: phishing, malicious apps, device and network threats, with risk signals for conditional access.",
    controls: ["mtd"], actions: [],
    ingest: "generic", platforms: ["iOS", "Android"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "zimperium_mtd", name: "Mobile Threat Defense", vendor: "Zimperium", category: "mtd",
    description: "On-device detection of mobile malware, phishing and network attacks for corporate and BYOD phones and tablets.",
    controls: ["mtd"], actions: [],
    ingest: "generic", platforms: ["iOS", "Android"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: null, priceSource: QUOTE_ONLY,
  },
  // --- Cloud security (CSPM / CWPP / SaaS)
  {
    key: "wiz", name: "Wiz Cloud", vendor: "Wiz", category: "cloud",
    description: "Agentless CNAPP: posture, permissions, vulnerabilities and attack paths across AWS, Azure, Google Cloud and Kubernetes.",
    controls: ["cspm", "cwpp"], actions: [],
    ingest: "generic", platforms: ["AWS", "Azure", "Google Cloud", "Kubernetes"], deployment: "cloud", offlineCapable: false,
    priceUnit: "workload", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "defender_cloud", name: "Defender for Cloud", vendor: "Microsoft", category: "cloud",
    description: "Posture management (Defender CSPM) and workload protection (Defender for Servers, Containers) for Azure, AWS and Google Cloud.",
    controls: ["cspm", "cwpp"], actions: [],
    ingest: "defender", platforms: ["Azure", "AWS", "Google Cloud", "Kubernetes"], deployment: "cloud", offlineCapable: false,
    priceUnit: "workload", listPrice: null, priceSource: "Usage-based per protected resource on Azure — azure.microsoft.com/pricing/details/defender-for-cloud",
  },
  {
    key: "prisma_cloud", name: "Prisma Cloud", vendor: "Palo Alto Networks", category: "cloud",
    description: "CNAPP covering cloud posture, workload and container runtime protection, and infrastructure-as-code scanning.",
    controls: ["cspm", "cwpp"], actions: [],
    ingest: "generic", platforms: ["AWS", "Azure", "Google Cloud", "Kubernetes"], deployment: "cloud", offlineCapable: false,
    priceUnit: "workload", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "aws_security_hub", name: "AWS Security Hub", vendor: "Amazon Web Services", category: "cloud",
    description: "Posture checks against AWS best practices and aggregated findings from GuardDuty, Inspector and partner tools.",
    controls: ["cspm"], actions: [],
    ingest: "generic", platforms: ["AWS"], deployment: "cloud", offlineCapable: false,
    priceUnit: "account", listPrice: null, priceSource: "Usage-based per security check and finding — aws.amazon.com/security-hub/pricing",
  },
  {
    key: "prowler", name: "Prowler", vendor: "Open source", category: "cloud",
    description: "Open-source security and compliance checks for AWS, Azure, Google Cloud, Kubernetes and Microsoft 365.",
    controls: ["cspm", "sspm"], actions: [],
    ingest: "generic", platforms: ["AWS", "Azure", "Google Cloud", "Kubernetes", "Microsoft 365"], deployment: "self-hosted", offlineCapable: false,
    priceUnit: "account", listPrice: 0, priceSource: `${OPEN_SOURCE} — budget hosting and engineering time`,
  },
  {
    key: "defender_cloud_apps", name: "Defender for Cloud Apps", vendor: "Microsoft", category: "cloud",
    description: "CASB and SaaS security posture: risky settings, OAuth apps and data sharing across Microsoft 365 and connected SaaS.",
    controls: ["sspm"], actions: ["DISABLE_USER"],
    ingest: "defender", platforms: ["Microsoft 365", "Google Workspace", "Salesforce"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: null, priceSource: "Included in Microsoft 365 E5; otherwise through Microsoft partners",
  },
  // --- Network detection & IDS
  {
    key: "suricata", name: "Suricata", vendor: "Open source", category: "ndr",
    description: "Open-source IDS/IPS and network security monitoring from the OISF; EVE JSON alerts stream to the SOC.",
    controls: ["ndr"], actions: [],
    ingest: "generic", platforms: ["Network sensor"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "flat", listPrice: 0, priceSource: `${OPEN_SOURCE} — budget sensor hardware and tuning`,
  },
  {
    key: "zeek", name: "Zeek", vendor: "Open source", category: "ndr",
    description: "Open-source network analysis: connection, DNS, HTTP and TLS logs for hunting and detection.",
    controls: ["ndr"], actions: [],
    ingest: "generic", platforms: ["Network sensor"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "flat", listPrice: 0, priceSource: `${OPEN_SOURCE} — budget sensor hardware`,
  },
  {
    key: "darktrace_network", name: "Darktrace / NETWORK", vendor: "Darktrace", category: "ndr",
    description: "Self-learning network detection and autonomous response across on-premises and cloud traffic.",
    controls: ["ndr"], actions: [],
    ingest: "generic", platforms: ["Network sensor", "Cloud"], deployment: "hybrid", offlineCapable: false,
    priceUnit: "flat", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "vectra_ai", name: "Vectra AI Platform", vendor: "Vectra AI", category: "ndr",
    description: "Attack-signal detection across network, identity and cloud, prioritized by entity.",
    controls: ["ndr"], actions: [],
    ingest: "generic", platforms: ["Network sensor", "Cloud"], deployment: "hybrid", offlineCapable: false,
    priceUnit: "flat", listPrice: null, priceSource: QUOTE_ONLY,
  },
  // --- Privileged access (PAM) and identity threat detection
  {
    key: "cyberark_privilege_cloud", name: "Privilege Cloud", vendor: "CyberArk", category: "pam",
    description: "SaaS privileged access management: credential vaulting, rotation and recorded privileged sessions.",
    controls: ["pam"], actions: [],
    ingest: "generic", platforms: ["Windows", "Linux", "Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "admin", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "delinea_secret_server", name: "Secret Server", vendor: "Delinea", category: "pam",
    description: "Privileged password vault with discovery, rotation and session recording; on-premises or cloud.",
    controls: ["pam"], actions: [],
    ingest: "generic", platforms: ["Windows", "Linux", "Cloud"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "admin", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "beyondtrust_password_safe", name: "Password Safe", vendor: "BeyondTrust", category: "pam",
    description: "Privileged credential and session management with just-in-time access.",
    controls: ["pam"], actions: [],
    ingest: "generic", platforms: ["Windows", "Linux", "Cloud"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "admin", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "defender_identity", name: "Defender for Identity", vendor: "Microsoft", category: "identity",
    description: "Identity threat detection for Active Directory and Entra ID: reconnaissance, Kerberoasting, DCSync, lateral movement.",
    controls: ["itdr"], actions: ["DISABLE_USER", "ENABLE_USER"],
    ingest: "defender", platforms: ["Windows", "Cloud"], deployment: "hybrid", offlineCapable: false,
    priceUnit: "user", listPrice: null, priceSource: "Included in Microsoft 365 E5 and E5 Security; otherwise through Microsoft partners",
  },
  // --- IoT / OT security
  {
    key: "nozomi_guardian", name: "Guardian", vendor: "Nozomi Networks", category: "ot",
    description: "Passive OT and IoT asset discovery, vulnerability assessment and threat detection on industrial networks.",
    controls: ["ot_monitoring", "ndr"], actions: [],
    ingest: "generic", platforms: ["OT network", "IoT"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "asset", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "claroty_xdome", name: "xDome", vendor: "Claroty", category: "ot",
    description: "Cyber-physical systems protection for industrial, medical and building devices.",
    controls: ["ot_monitoring"], actions: [],
    ingest: "generic", platforms: ["OT network", "IoT"], deployment: "cloud", offlineCapable: false,
    priceUnit: "asset", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "defender_iot", name: "Defender for IoT (OT)", vendor: "Microsoft", category: "ot",
    description: "Agentless OT network sensors: asset inventory, vulnerabilities and threat detection; sensors can run air-gapped.",
    controls: ["ot_monitoring", "ndr"], actions: [],
    ingest: "defender", platforms: ["OT network", "IoT"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "asset", listPrice: null, priceSource: "Licensed per site through Microsoft; see azure.microsoft.com/pricing/details/iot-defender",
  },
  {
    key: "armis_centrix", name: "Centrix", vendor: "Armis", category: "ot",
    description: "Agentless asset intelligence for every connected device: IT, IoT, OT and medical.",
    controls: ["ot_monitoring"], actions: [],
    ingest: "generic", platforms: ["OT network", "IoT"], deployment: "cloud", offlineCapable: false,
    priceUnit: "asset", listPrice: null, priceSource: QUOTE_ONLY,
  },
  // --- Web application & API protection, code & secrets security
  {
    key: "cloudflare_pro", name: "Pro plan (WAF)", vendor: "Cloudflare", category: "webapp",
    description: "Managed web application firewall, DDoS protection and CDN for a website or portal.",
    controls: ["waf"], actions: ["BLOCK_IP"],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "app", listPrice: 20, priceSource: "$20 per domain per month billed annually ($25 monthly) — cloudflare.com/plans",
  },
  {
    key: "cloudflare_business", name: "Business plan (WAF)", vendor: "Cloudflare", category: "webapp",
    description: "WAF with more custom rules, a 100% uptime SLA and priority support for business-critical sites.",
    controls: ["waf"], actions: ["BLOCK_IP"],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "app", listPrice: 200, priceSource: "$200 per domain per month billed annually ($250 monthly) — cloudflare.com/plans",
  },
  {
    key: "aws_waf", name: "AWS WAF", vendor: "Amazon Web Services", category: "webapp",
    description: "Web application firewall for CloudFront, load balancers and API Gateway.",
    controls: ["waf"], actions: ["BLOCK_IP"],
    ingest: "generic", platforms: ["AWS"], deployment: "cloud", offlineCapable: false,
    priceUnit: "app", listPrice: null, priceSource: "Usage-based per web ACL, rule and million requests — aws.amazon.com/waf/pricing",
  },
  {
    key: "salt_security", name: "API Protection Platform", vendor: "Salt Security", category: "webapp",
    description: "API discovery, posture and runtime detection of API abuse.",
    controls: ["api_security"], actions: [],
    ingest: "generic", platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "app", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "github_secret_protection", name: "Secret Protection", vendor: "GitHub", category: "code",
    description: "Secret scanning and push protection that stop credentials reaching repositories.",
    controls: ["code_security"], actions: [],
    ingest: "generic", platforms: ["GitHub"], deployment: "cloud", offlineCapable: false,
    priceUnit: "developer", listPrice: 19, priceSource: "$19 per active committer per month — github.blog/changelog/2025-03-04-introducing-github-secret-protection-and-github-code-security",
  },
  {
    key: "github_code_security", name: "Code Security", vendor: "GitHub", category: "code",
    description: "Code scanning (CodeQL), dependency review and Copilot Autofix in pull requests.",
    controls: ["code_security"], actions: [],
    ingest: "generic", platforms: ["GitHub"], deployment: "cloud", offlineCapable: false,
    priceUnit: "developer", listPrice: 30, priceSource: "$30 per active committer per month — github.blog/changelog/2025-03-04-introducing-github-secret-protection-and-github-code-security",
  },
  {
    key: "snyk_team", name: "Snyk Team", vendor: "Snyk", category: "code",
    description: "Dependency, code and container scanning in the IDE, pull requests and CI/CD.",
    controls: ["code_security"], actions: [],
    ingest: "generic", platforms: ["GitHub", "GitLab", "Bitbucket", "Azure DevOps"], deployment: "cloud", offlineCapable: false,
    priceUnit: "developer", listPrice: 25, priceSource: "From $25 per contributing developer per month (Team plan) — snyk.io/plans",
  },
  {
    key: "gitleaks", name: "Gitleaks", vendor: "Open source", category: "code",
    description: "Open-source secrets scanner for repositories and CI pipelines.",
    controls: ["code_security"], actions: [],
    ingest: "generic", platforms: ["Any"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "flat", listPrice: 0, priceSource: OPEN_SOURCE,
  },
  {
    key: "zap", name: "ZAP DAST scanner", vendor: "Open source", category: "code",
    description: "Open-source dynamic application security testing for web apps and APIs, runnable in CI.",
    controls: ["code_security"], actions: [],
    ingest: "generic", platforms: ["Any"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "flat", listPrice: 0, priceSource: OPEN_SOURCE,
  },
  // --- More email, SIEM, network, vulnerability and awareness options
  {
    key: "mimecast_email", name: "Email Security", vendor: "Mimecast", category: "email",
    description: "Secure email gateway with URL and attachment protection, impersonation defense and continuity.",
    controls: ["email_security"], actions: ["BLOCK_SENDER"],
    ingest: "generic", platforms: ["Microsoft 365", "Google Workspace", "Exchange"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "elastic_security", name: "Elastic Security (self-managed)", vendor: "Elastic", category: "siem",
    description: "SIEM on the Elastic Stack; the free self-managed tier covers log collection, detection rules and timelines.",
    controls: ["siem"], actions: [],
    ingest: "generic", platforms: ["Any"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "gb", listPrice: 0, priceSource: "Free self-managed tier — budget hosting; paid subscriptions by quote",
  },
  {
    key: "zscaler_zia", name: "Internet Access", vendor: "Zscaler", category: "network",
    description: "Cloud secure web gateway: URL filtering, TLS inspection, sandboxing and cloud firewall for every user.",
    controls: ["web_filtering"], actions: [],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux", "iOS", "Android"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "palo_alto_ngfw", name: "Next-Generation Firewall", vendor: "Palo Alto Networks", category: "network",
    description: "Firewall with intrusion prevention, URL filtering and DNS security; dynamic block lists from the SOC.",
    controls: ["web_filtering", "ndr"], actions: ["BLOCK_IP", "UNBLOCK_IP"],
    ingest: "generic", platforms: ["Appliance"], deployment: "hybrid", offlineCapable: true,
    priceUnit: "flat", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "oxidized", name: "Oxidized", vendor: "Open source", category: "netmgmt",
    description: "Open-source configuration backup and change tracking for routers, switches and firewalls.",
    controls: ["net_config"], actions: [],
    ingest: null, platforms: ["Appliance"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "flat", listPrice: 0, priceSource: OPEN_SOURCE,
  },
  {
    key: "auvik", name: "Network Management", vendor: "Auvik", category: "netmgmt",
    description: "Network discovery, configuration backup and change alerts, and firmware tracking for network devices.",
    controls: ["net_config"], actions: [],
    ingest: "generic", platforms: ["Appliance"], deployment: "cloud", offlineCapable: false,
    priceUnit: "device", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "qualys_vmdr", name: "VMDR", vendor: "Qualys", category: "vuln",
    description: "Vulnerability management, detection and response across endpoints, servers, cloud and network devices.",
    controls: ["vuln_scan"], actions: [],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux", "Network"], deployment: "cloud", offlineCapable: false,
    priceUnit: "endpoint", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "rapid7_insightvm", name: "InsightVM", vendor: "Rapid7", category: "vuln",
    description: "Vulnerability risk management with live dashboards and remediation projects.",
    controls: ["vuln_scan"], actions: [],
    ingest: "generic", platforms: ["Windows", "macOS", "Linux", "Network"], deployment: "hybrid", offlineCapable: false,
    priceUnit: "endpoint", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "knowbe4_kmsat", name: "Security Awareness Training", vendor: "KnowBe4", category: "awareness",
    description: "Phishing simulation and security awareness training for every employee.",
    controls: [], actions: [],
    ingest: null, platforms: ["Cloud"], deployment: "cloud", offlineCapable: false,
    priceUnit: "user", listPrice: null, priceSource: QUOTE_ONLY,
  },
  {
    key: "shuffle_soar", name: "Shuffle", vendor: "Open source", category: "automation",
    description: "Open-source SOAR: workflows that carry out the response actions HELIOS sends.",
    controls: ["soar"], actions: [],
    ingest: "generic", platforms: ["Any"], deployment: "self-hosted", offlineCapable: true,
    priceUnit: "flat", listPrice: 0, priceSource: OPEN_SOURCE,
  },
];
