// MITRE ATT&CK (Enterprise) reference subset — every technique any HELIOS
// module can map to (signal-fusion's detectors and attack scenarios, desas's
// forensic signals, asip's RCA output, governance scenarios) plus the common
// neighbours an analyst would expect in a coverage matrix. Seeded into
// mitre_tactics / mitre_techniques so all modules share one reference set.
//
// ATT&CK lists some techniques under several tactics; the schema stores one,
// so `tactic` is the primary tactic each technique is filed under here.

export interface TacticRef {
  id: string;
  name: string;
  order: number;
}

export interface TechniqueRef {
  id: string;
  name: string;
  tactic: string;
}

export const TACTICS: TacticRef[] = [
  { id: "TA0043", name: "Reconnaissance", order: 1 },
  { id: "TA0042", name: "Resource Development", order: 2 },
  { id: "TA0001", name: "Initial Access", order: 3 },
  { id: "TA0002", name: "Execution", order: 4 },
  { id: "TA0003", name: "Persistence", order: 5 },
  { id: "TA0004", name: "Privilege Escalation", order: 6 },
  { id: "TA0005", name: "Defense Evasion", order: 7 },
  { id: "TA0006", name: "Credential Access", order: 8 },
  { id: "TA0007", name: "Discovery", order: 9 },
  { id: "TA0008", name: "Lateral Movement", order: 10 },
  { id: "TA0009", name: "Collection", order: 11 },
  { id: "TA0011", name: "Command and Control", order: 12 },
  { id: "TA0010", name: "Exfiltration", order: 13 },
  { id: "TA0040", name: "Impact", order: 14 },
];

export const TECHNIQUES: TechniqueRef[] = [
  // Reconnaissance
  { id: "T1595", name: "Active Scanning", tactic: "TA0043" },
  { id: "T1590", name: "Gather Victim Network Information", tactic: "TA0043" },
  { id: "T1589", name: "Gather Victim Identity Information", tactic: "TA0043" },
  { id: "T1593", name: "Search Open Websites/Domains", tactic: "TA0043" },
  { id: "T1598", name: "Phishing for Information", tactic: "TA0043" },

  // Resource Development
  { id: "T1583", name: "Acquire Infrastructure", tactic: "TA0042" },
  { id: "T1584", name: "Compromise Infrastructure", tactic: "TA0042" },
  { id: "T1587", name: "Develop Capabilities", tactic: "TA0042" },
  { id: "T1608", name: "Stage Capabilities", tactic: "TA0042" },

  // Initial Access
  { id: "T1566", name: "Phishing", tactic: "TA0001" },
  { id: "T1566.001", name: "Spearphishing Attachment", tactic: "TA0001" },
  { id: "T1566.002", name: "Spearphishing Link", tactic: "TA0001" },
  { id: "T1566.003", name: "Spearphishing via Service", tactic: "TA0001" },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "TA0001" },
  { id: "T1078", name: "Valid Accounts", tactic: "TA0001" },
  { id: "T1195", name: "Supply Chain Compromise", tactic: "TA0001" },
  { id: "T1189", name: "Drive-by Compromise", tactic: "TA0001" },
  { id: "T1133", name: "External Remote Services", tactic: "TA0001" },
  { id: "T1199", name: "Trusted Relationship", tactic: "TA0001" },

  // Execution
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "TA0002" },
  { id: "T1059.001", name: "PowerShell", tactic: "TA0002" },
  { id: "T1059.003", name: "Windows Command Shell", tactic: "TA0002" },
  { id: "T1059.004", name: "Unix Shell", tactic: "TA0002" },
  { id: "T1059.005", name: "Visual Basic", tactic: "TA0002" },
  { id: "T1059.007", name: "JavaScript", tactic: "TA0002" },
  { id: "T1204", name: "User Execution", tactic: "TA0002" },
  { id: "T1204.001", name: "Malicious Link", tactic: "TA0002" },
  { id: "T1204.002", name: "Malicious File", tactic: "TA0002" },
  { id: "T1047", name: "Windows Management Instrumentation", tactic: "TA0002" },
  { id: "T1569", name: "System Services", tactic: "TA0002" },
  { id: "T1569.002", name: "Service Execution", tactic: "TA0002" },
  { id: "T1203", name: "Exploitation for Client Execution", tactic: "TA0002" },
  { id: "T1106", name: "Native API", tactic: "TA0002" },

  // Persistence
  { id: "T1053", name: "Scheduled Task/Job", tactic: "TA0003" },
  { id: "T1053.005", name: "Scheduled Task", tactic: "TA0003" },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "TA0003" },
  { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "TA0003" },
  { id: "T1543", name: "Create or Modify System Process", tactic: "TA0003" },
  { id: "T1543.003", name: "Windows Service", tactic: "TA0003" },
  { id: "T1136", name: "Create Account", tactic: "TA0003" },
  { id: "T1098", name: "Account Manipulation", tactic: "TA0003" },
  { id: "T1505", name: "Server Software Component", tactic: "TA0003" },
  { id: "T1505.003", name: "Web Shell", tactic: "TA0003" },
  { id: "T1546", name: "Event Triggered Execution", tactic: "TA0003" },

  // Privilege Escalation
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "TA0004" },
  { id: "T1548.002", name: "Bypass User Account Control", tactic: "TA0004" },
  { id: "T1548.003", name: "Sudo and Sudo Caching", tactic: "TA0004" },
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "TA0004" },
  { id: "T1134", name: "Access Token Manipulation", tactic: "TA0004" },
  { id: "T1055", name: "Process Injection", tactic: "TA0004" },

  // Defense Evasion
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "TA0005" },
  { id: "T1027.001", name: "Binary Padding", tactic: "TA0005" },
  { id: "T1036", name: "Masquerading", tactic: "TA0005" },
  { id: "T1036.007", name: "Double File Extension", tactic: "TA0005" },
  { id: "T1070", name: "Indicator Removal", tactic: "TA0005" },
  { id: "T1070.001", name: "Clear Windows Event Logs", tactic: "TA0005" },
  { id: "T1070.004", name: "File Deletion", tactic: "TA0005" },
  { id: "T1562", name: "Impair Defenses", tactic: "TA0005" },
  { id: "T1562.001", name: "Disable or Modify Tools", tactic: "TA0005" },
  { id: "T1497", name: "Virtualization/Sandbox Evasion", tactic: "TA0005" },
  { id: "T1218", name: "System Binary Proxy Execution", tactic: "TA0005" },
  { id: "T1140", name: "Deobfuscate/Decode Files or Information", tactic: "TA0005" },
  { id: "T1112", name: "Modify Registry", tactic: "TA0005" },

  // Credential Access
  { id: "T1003", name: "OS Credential Dumping", tactic: "TA0006" },
  { id: "T1003.001", name: "LSASS Memory", tactic: "TA0006" },
  { id: "T1110", name: "Brute Force", tactic: "TA0006" },
  { id: "T1110.001", name: "Password Guessing", tactic: "TA0006" },
  { id: "T1110.003", name: "Password Spraying", tactic: "TA0006" },
  { id: "T1056", name: "Input Capture", tactic: "TA0006" },
  { id: "T1056.001", name: "Keylogging", tactic: "TA0006" },
  { id: "T1558", name: "Steal or Forge Kerberos Tickets", tactic: "TA0006" },
  { id: "T1558.003", name: "Kerberoasting", tactic: "TA0006" },
  { id: "T1552", name: "Unsecured Credentials", tactic: "TA0006" },
  { id: "T1555", name: "Credentials from Password Stores", tactic: "TA0006" },
  { id: "T1539", name: "Steal Web Session Cookie", tactic: "TA0006" },
  { id: "T1556", name: "Modify Authentication Process", tactic: "TA0006" },

  // Discovery
  { id: "T1087", name: "Account Discovery", tactic: "TA0007" },
  { id: "T1082", name: "System Information Discovery", tactic: "TA0007" },
  { id: "T1018", name: "Remote System Discovery", tactic: "TA0007" },
  { id: "T1046", name: "Network Service Discovery", tactic: "TA0007" },
  { id: "T1057", name: "Process Discovery", tactic: "TA0007" },
  { id: "T1083", name: "File and Directory Discovery", tactic: "TA0007" },
  { id: "T1016", name: "System Network Configuration Discovery", tactic: "TA0007" },
  { id: "T1033", name: "System Owner/User Discovery", tactic: "TA0007" },
  { id: "T1069", name: "Permission Groups Discovery", tactic: "TA0007" },
  { id: "T1135", name: "Network Share Discovery", tactic: "TA0007" },

  // Lateral Movement
  { id: "T1021", name: "Remote Services", tactic: "TA0008" },
  { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "TA0008" },
  { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "TA0008" },
  { id: "T1021.004", name: "SSH", tactic: "TA0008" },
  { id: "T1021.006", name: "Windows Remote Management", tactic: "TA0008" },
  { id: "T1550", name: "Use Alternate Authentication Material", tactic: "TA0008" },
  { id: "T1550.002", name: "Pass the Hash", tactic: "TA0008" },
  { id: "T1570", name: "Lateral Tool Transfer", tactic: "TA0008" },
  { id: "T1210", name: "Exploitation of Remote Services", tactic: "TA0008" },

  // Collection
  { id: "T1005", name: "Data from Local System", tactic: "TA0009" },
  { id: "T1113", name: "Screen Capture", tactic: "TA0009" },
  { id: "T1115", name: "Clipboard Data", tactic: "TA0009" },
  { id: "T1114", name: "Email Collection", tactic: "TA0009" },
  { id: "T1119", name: "Automated Collection", tactic: "TA0009" },
  { id: "T1560", name: "Archive Collected Data", tactic: "TA0009" },
  { id: "T1039", name: "Data from Network Shared Drive", tactic: "TA0009" },
  { id: "T1530", name: "Data from Cloud Storage", tactic: "TA0009" },

  // Command and Control
  { id: "T1071", name: "Application Layer Protocol", tactic: "TA0011" },
  { id: "T1071.001", name: "Web Protocols", tactic: "TA0011" },
  { id: "T1071.004", name: "DNS", tactic: "TA0011" },
  { id: "T1571", name: "Non-Standard Port", tactic: "TA0011" },
  { id: "T1573", name: "Encrypted Channel", tactic: "TA0011" },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "TA0011" },
  { id: "T1090", name: "Proxy", tactic: "TA0011" },
  { id: "T1095", name: "Non-Application Layer Protocol", tactic: "TA0011" },
  { id: "T1572", name: "Protocol Tunneling", tactic: "TA0011" },
  { id: "T1568", name: "Dynamic Resolution", tactic: "TA0011" },

  // Exfiltration
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "TA0010" },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "TA0010" },
  { id: "T1048.003", name: "Exfiltration Over Unencrypted Non-C2 Protocol", tactic: "TA0010" },
  { id: "T1567", name: "Exfiltration Over Web Service", tactic: "TA0010" },
  { id: "T1567.002", name: "Exfiltration to Cloud Storage", tactic: "TA0010" },
  { id: "T1020", name: "Automated Exfiltration", tactic: "TA0010" },
  { id: "T1030", name: "Data Transfer Size Limits", tactic: "TA0010" },
  { id: "T1537", name: "Transfer Data to Cloud Account", tactic: "TA0010" },

  // Impact
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "TA0040" },
  { id: "T1485", name: "Data Destruction", tactic: "TA0040" },
  { id: "T1489", name: "Service Stop", tactic: "TA0040" },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "TA0040" },
  { id: "T1491", name: "Defacement", tactic: "TA0040" },
  { id: "T1498", name: "Network Denial of Service", tactic: "TA0040" },
  { id: "T1499", name: "Endpoint Denial of Service", tactic: "TA0040" },
  { id: "T1531", name: "Account Access Removal", tactic: "TA0040" },
  { id: "T1561", name: "Disk Wipe", tactic: "TA0040" },
  { id: "T1565", name: "Data Manipulation", tactic: "TA0040" },
];

const TECHNIQUE_BY_ID = new Map(TECHNIQUES.map((t) => [t.id, t]));
const TACTIC_BY_ID = new Map(TACTICS.map((t) => [t.id, t]));

export function getTechnique(id: string): TechniqueRef | undefined {
  return TECHNIQUE_BY_ID.get(id);
}

export function getTactic(id: string): TacticRef | undefined {
  return TACTIC_BY_ID.get(id);
}

export function parentTechniqueId(id: string): string | null {
  const dot = id.indexOf(".");
  return dot === -1 ? null : id.slice(0, dot);
}

const TECHNIQUE_ID_RE = /\bT\d{4}(?:\.\d{3})?\b/;

// Detectors and LLM output reference techniques as free text
// ("T1003 - OS Credential Dumping", "Execution (TA0002) / T1059.001").
export function extractTechniqueId(text: string): string | null {
  return text.match(TECHNIQUE_ID_RE)?.[0] ?? null;
}

// Resolves a free-text reference to a catalog technique, falling back to the
// parent technique when only an unlisted sub-technique was cited.
export function resolveTechnique(text: string): TechniqueRef | undefined {
  const id = extractTechniqueId(text);
  if (!id) return undefined;
  const direct = getTechnique(id);
  if (direct) return direct;
  const parent = parentTechniqueId(id);
  return parent ? getTechnique(parent) : undefined;
}
