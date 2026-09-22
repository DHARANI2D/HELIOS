import { db } from "@/lib/db";
import { ingestRawLog, type RawLog } from "./ingestion";
import { runDetections } from "./engine";
import { toNormalizedEvent } from "./types";
import type { EventSource, CaseSeverity } from "@prisma/client";

// Curated attack-log fixtures spanning all 12 MITRE tactics the detectors
// cover, condensed from signal-fusion's 48-scenario/12-file library
// (simulation/scenarios/*.ts) into one file — each entry here is built to
// trip a specific detector's exact matching logic rather than reproduced
// verbatim from the original fixtures.

interface ScenarioLog {
  source: EventSource;
  data: RawLog;
}

interface Scenario {
  id: string;
  name: string;
  description: string;
  mitreTactic: string;
  severity: CaseSeverity;
  logs: ScenarioLog[];
}

const now = () => new Date().toISOString();
const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

export const SCENARIOS: Scenario[] = [
  {
    id: "geo-velocity",
    name: "Impossible Travel",
    description: "Same user logs in from two continents within minutes",
    mitreTactic: "Initial Access",
    severity: "HIGH",
    logs: [
      { source: "AUTH", data: { timestamp: minutesAgo(30), user: "j.doe", result: "SUCCESS", source_ip: "8.8.8.8", geo_location: "US" } },
      { source: "AUTH", data: { timestamp: minutesAgo(5), user: "j.doe", result: "SUCCESS", source_ip: "45.33.22.11", geo_location: "RU" } },
    ],
  },
  {
    id: "account-takeover-chain",
    name: "Account Takeover Chain",
    description: "Failed login, then success, then a sensitive cloud action",
    mitreTactic: "Persistence",
    severity: "HIGH",
    logs: [
      { source: "AUTH", data: { timestamp: minutesAgo(10), user: "svc-billing", result: "FAILED", source_ip: "103.22.11.55" } },
      { source: "AUTH", data: { timestamp: minutesAgo(9), user: "svc-billing", result: "SUCCESS", source_ip: "103.22.11.55" } },
      { source: "CLOUD", data: { timestamp: minutesAgo(8), user: "svc-billing", action: "IAM_POLICY_UPDATE", resource: "billing-role", status: "SUCCESS" } },
    ],
  },
  {
    id: "discovery-then-powershell",
    name: "Discovery Followed by PowerShell",
    description: "whoami / net user followed by an obfuscated PowerShell command",
    mitreTactic: "Discovery",
    severity: "MEDIUM",
    logs: [
      { source: "ENDPOINT", data: { timestamp: minutesAgo(4), user: "attacker", process: "whoami /all", hostname: "ws-14" } },
      { source: "ENDPOINT", data: { timestamp: minutesAgo(3), user: "attacker", process: "powershell.exe -enc SGVsbG8=", hostname: "ws-14" } },
    ],
  },
  {
    id: "known-c2-beacon",
    name: "Known C2 Beacon",
    description: "Outbound connection to a known-malicious IP",
    mitreTactic: "Command and Control",
    severity: "CRITICAL",
    logs: [
      { source: "NETWORK", data: { timestamp: now(), source_ip: "10.0.4.22", dest_ip: "99.88.77.66", type: "HTTPS", port: 443 } },
    ],
  },
  {
    id: "credential-dumping",
    name: "Credential Dumping - Mimikatz",
    description: "mimikatz.exe run against LSASS",
    mitreTactic: "Credential Access",
    severity: "CRITICAL",
    logs: [
      { source: "ENDPOINT", data: { timestamp: now(), user: "admin", process: "mimikatz.exe privilege::debug sekurlsa::logonpasswords", parent_process: "powershell.exe", hostname: "dc-01" } },
    ],
  },
  {
    id: "password-spraying",
    name: "Password Spraying",
    description: "One source IP tries five different accounts, mostly failing",
    mitreTactic: "Credential Access",
    severity: "MEDIUM",
    logs: ["alice", "bob", "carol", "dave", "erin"].map((user, i) => ({
      source: "AUTH" as const,
      data: {
        timestamp: minutesAgo(10 - i),
        user,
        source_ip: "45.33.22.11",
        result: i === 4 ? "SUCCESS" : "FAILED",
      },
    })),
  },
  {
    id: "port-scan",
    name: "Internal Port Scan",
    description: "One host probes ten+ distinct ports on a target",
    mitreTactic: "Reconnaissance",
    severity: "MEDIUM",
    logs: Array.from({ length: 12 }, (_, i) => ({
      source: "NETWORK" as const,
      data: {
        timestamp: minutesAgo(2),
        source_ip: "192.168.1.77",
        dest_ip: "192.168.1.10",
        port: 1000 + i,
        protocol: "TCP",
      },
    })),
  },
  {
    id: "osint-recon",
    name: "OSINT Reconnaissance",
    description: "Browsing OSINT platforms ahead of a targeted attack",
    mitreTactic: "Reconnaissance",
    severity: "LOW",
    logs: [
      { source: "NETWORK", data: { timestamp: now(), source_ip: "10.0.1.5", dest_ip: "140.82.121.4", url: "https://github.com/target-org", type: "HTTPS" } },
    ],
  },
  {
    id: "rdp-lateral-movement",
    name: "Internal RDP Lateral Movement",
    description: "RDP hop between two internal hosts",
    mitreTactic: "Lateral Movement",
    severity: "MEDIUM",
    logs: [
      { source: "NETWORK", data: { timestamp: now(), source_ip: "10.0.2.15", dest_ip: "10.0.2.40", service: "RDP" } },
    ],
  },
  {
    id: "psexec-lateral-movement",
    name: "PsExec Remote Execution",
    description: "PsExec used to run a command on a remote host",
    mitreTactic: "Lateral Movement",
    severity: "HIGH",
    logs: [
      { source: "ENDPOINT", data: { timestamp: now(), user: "admin", process: "psexec.exe \\\\FILESRV01 cmd.exe", hostname: "ws-02" } },
    ],
  },
  {
    id: "cloud-exfiltration",
    name: "Large Cloud Upload",
    description: "A 50MB object uploaded to an external bucket",
    mitreTactic: "Exfiltration",
    severity: "HIGH",
    logs: [
      { source: "CLOUD", data: { timestamp: now(), user: "j.doe", action: "S3_OBJECT_UPLOAD", resource: "external-bucket/dump.zip", size: 50 * 1024 * 1024 } },
    ],
  },
  {
    id: "dns-tunneling",
    name: "DNS Tunneling",
    description: "Many unusually long DNS queries from one host",
    mitreTactic: "Exfiltration",
    severity: "HIGH",
    logs: Array.from({ length: 12 }, (_, i) => ({
      source: "NETWORK" as const,
      data: {
        timestamp: minutesAgo(1),
        source_ip: "10.0.3.9",
        type: "DNS",
        query: `${"a".repeat(60)}${i}.exfil.example.net`,
      },
    })),
  },
  {
    id: "registry-persistence",
    name: "Registry Run Key Persistence",
    description: "A run key added under CurrentVersion\\Run",
    mitreTactic: "Persistence",
    severity: "HIGH",
    logs: [
      { source: "ENDPOINT", data: { timestamp: now(), user: "system", process: "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\payload.exe", hostname: "ws-09" } },
    ],
  },
  {
    id: "log-clearing",
    name: "Windows Event Log Clearing",
    description: "wevtutil used to clear the System log",
    mitreTactic: "Defense Evasion",
    severity: "CRITICAL",
    logs: [
      { source: "ENDPOINT", data: { timestamp: now(), user: "admin", process: "wevtutil cl System", hostname: "dc-01" } },
    ],
  },
  {
    id: "disable-av",
    name: "Antivirus Disabled",
    description: "Windows Defender real-time monitoring disabled via PowerShell",
    mitreTactic: "Defense Evasion",
    severity: "CRITICAL",
    logs: [
      { source: "ENDPOINT", data: { timestamp: now(), user: "admin", process: "Set-MpPreference -DisableRealtimeMonitoring $true", hostname: "ws-03" } },
    ],
  },
  {
    id: "ransomware",
    name: "Ransomware Mass Encryption",
    description: "A process modifies thousands of files in a short window",
    mitreTactic: "Impact",
    severity: "CRITICAL",
    logs: [
      { source: "ENDPOINT", data: { timestamp: now(), user: "svc-backup", process: "svchost.exe", files_modified: 4200, hostname: "fileserver-02" } },
    ],
  },
];

export async function runSimulation(count = 6): Promise<{
  scenariosRun: string[];
  ingestedCount: number;
  caseIds: string[];
  detectionCount: number;
}> {
  const pool = [...SCENARIOS].sort(() => Math.random() - 0.5);
  const selected = pool.slice(0, Math.min(count, pool.length));

  let ingestedCount = 0;
  for (const scenario of selected) {
    for (const log of scenario.logs) {
      await ingestRawLog(log.source, log.data);
      ingestedCount++;
    }
  }

  const uncasedEvents = await db.ingestedEvent.findMany({
    where: { caseId: null },
    orderBy: { timestamp: "asc" },
  });

  const { caseIds, detectionCount } = await runDetections(uncasedEvents.map(toNormalizedEvent));

  return {
    scenariosRun: selected.map((s) => s.name),
    ingestedCount,
    caseIds,
    detectionCount,
  };
}
