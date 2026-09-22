import { PrismaClient } from "@prisma/client";

// Seeds the shared MITRE ATT&CK reference set every detection source
// (aegis governance, asip investigations, desas forensics, signal-fusion
// detectors) maps into — one table instead of four copies. Covers the 14
// enterprise tactics and every technique ID actually referenced by the
// detectors/scenarios ported into this app so far.

const db = new PrismaClient();

const TACTICS: { id: string; name: string }[] = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
];

const TECHNIQUES: { id: string; name: string; tacticId: string }[] = [
  { id: "T1595", name: "Active Scanning", tacticId: "TA0043" },
  { id: "T1590", name: "Gather Victim Network Information", tacticId: "TA0043" },
  { id: "T1593", name: "Search Open Websites/Domains", tacticId: "TA0043" },
  { id: "T1078", name: "Valid Accounts", tacticId: "TA0001" },
  { id: "T1190", name: "Exploit Public-Facing Application", tacticId: "TA0001" },
  { id: "T1566.001", name: "Phishing: Spearphishing Attachment", tacticId: "TA0001" },
  { id: "T1059", name: "Command and Scripting Interpreter", tacticId: "TA0002" },
  { id: "T1059.005", name: "Command and Scripting Interpreter: Visual Basic", tacticId: "TA0002" },
  { id: "T1059.007", name: "Command and Scripting Interpreter: JavaScript", tacticId: "TA0002" },
  { id: "T1204.002", name: "User Execution: Malicious File", tacticId: "TA0002" },
  { id: "T1569.002", name: "System Services: Service Execution", tacticId: "TA0002" },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tacticId: "TA0003" },
  { id: "T1053", name: "Scheduled Task/Job", tacticId: "TA0003" },
  { id: "T1543", name: "Create or Modify System Process", tacticId: "TA0003" },
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tacticId: "TA0004" },
  { id: "T1070.001", name: "Indicator Removal: Clear Windows Event Logs", tacticId: "TA0005" },
  { id: "T1562", name: "Impair Defenses", tacticId: "TA0005" },
  { id: "T1027", name: "Obfuscated Files or Information", tacticId: "TA0005" },
  { id: "T1027.001", name: "Obfuscated Files or Information: Binary Padding", tacticId: "TA0005" },
  { id: "T1036.007", name: "Masquerading: Double File Extension", tacticId: "TA0005" },
  { id: "T1497", name: "Virtualization/Sandbox Evasion", tacticId: "TA0005" },
  { id: "T1003", name: "OS Credential Dumping", tacticId: "TA0006" },
  { id: "T1110.003", name: "Brute Force: Password Spraying", tacticId: "TA0006" },
  { id: "T1056", name: "Input Capture", tacticId: "TA0006" },
  { id: "T1558", name: "Steal or Forge Kerberos Tickets", tacticId: "TA0006" },
  { id: "T1552", name: "Unsecured Credentials", tacticId: "TA0006" },
  { id: "T1082", name: "System Information Discovery", tacticId: "TA0007" },
  { id: "T1087", name: "Account Discovery", tacticId: "TA0007" },
  { id: "T1021.001", name: "Remote Services: Remote Desktop Protocol", tacticId: "TA0008" },
  { id: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares", tacticId: "TA0008" },
  { id: "T1047", name: "Windows Management Instrumentation", tacticId: "TA0008" },
  { id: "T1550.002", name: "Use Alternate Authentication Material: Pass the Hash", tacticId: "TA0008" },
  { id: "T1071", name: "Application Layer Protocol", tacticId: "TA0011" },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tacticId: "TA0010" },
  { id: "T1048.003", name: "Exfiltration Over Alternative Protocol: Non-C2 Protocol", tacticId: "TA0010" },
  { id: "T1567", name: "Exfiltration Over Web Service", tacticId: "TA0010" },
  { id: "T1020", name: "Automated Exfiltration", tacticId: "TA0010" },
  { id: "T1486", name: "Data Encrypted for Impact", tacticId: "TA0040" },
  { id: "T1485", name: "Data Destruction", tacticId: "TA0040" },
  { id: "T1489", name: "Service Stop", tacticId: "TA0040" },
];

async function main() {
  for (const tactic of TACTICS) {
    await db.mitreTactic.upsert({
      where: { id: tactic.id },
      update: { name: tactic.name },
      create: tactic,
    });
  }

  for (const tech of TECHNIQUES) {
    const isSub = tech.id.includes(".");
    await db.mitreTechnique.upsert({
      where: { id: tech.id },
      update: { name: tech.name, tacticId: tech.tacticId },
      create: {
        id: tech.id,
        name: tech.name,
        tacticId: tech.tacticId,
        isSubtechnique: isSub,
        parentId: isSub ? tech.id.split(".")[0] : null,
      },
    });
  }

  console.log(`Seeded ${TACTICS.length} tactics and ${TECHNIQUES.length} techniques.`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => db.$disconnect());
