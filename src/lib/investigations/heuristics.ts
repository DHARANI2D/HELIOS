import type { CaseSeverity, DetectionSource } from "@prisma/client";

import type { UesEvent } from "@/lib/investigations/normalize";
import { ancestry, type EntityGraph } from "@/lib/investigations/graph";
import { getTactic, getTechnique, resolveTechnique } from "@/lib/mitre/catalog";
import { isPrivateIp } from "@/lib/threat-intel/indicators";
import { EMPTY_INTEL, localVerdict, type IntelSnapshot } from "@/lib/threat-intel/local-intel";
import { maxSeverity, severityRank } from "@/lib/severity";

// Deterministic forensic rules over normalized telemetry. They do two jobs:
// 1. ground the LLM swarm (findings are passed to every agent as evidence),
// 2. stand in for it when no ANTHROPIC_API_KEY is configured — replacing
//    asip's _get_mock_agent_response, which returned the same canned
//    "invoice.docx → powershell → 185.220.101.5" story for every input.

export interface Finding {
  ruleId: string;
  title: string;
  description: string;
  severity: CaseSeverity;
  detectionSource: DetectionSource;
  techniques: string[];
  confidence: number;
  events: UesEvent[];
}

const lower = (s?: string) => (s ?? "").toLowerCase();
const cmd = (e: UesEvent) => lower(e.commandLine ?? e.processName);
const proc = (e: UesEvent) => lower(e.processName);

const OFFICE = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe"];
const SHELLS = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bash", "sh"];
const SCRIPTING = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget"];
const WEB_SERVERS = ["w3wp.exe", "httpd", "httpd.exe", "nginx", "nginx.exe", "apache2", "tomcat", "java.exe", "php-cgi.exe", "node.exe"];
const DISCOVERY = ["whoami", "net user", "net group", "net localgroup", "ipconfig", "systeminfo", "nltest", "tasklist", "quser", "arp -a", "netstat", "hostname"];
const STAGING_DIRS = ["\\appdata\\", "\\temp\\", "\\tmp\\", "\\programdata\\", "\\users\\public\\", "/tmp/", "/dev/shm/"];
const EXECUTABLE_EXT = /\.(exe|dll|scr|ps1|vbs|vbe|js|jse|hta|bat|cmd|lnk|jar)$/i;
const STANDARD_PORTS = new Set([80, 443, 53, 8080, 8443]);
const PRIVILEGED_GROUPS = ["administrators", "domain admins", "enterprise admins", "schema admins", "backup operators", "account operators", "server operators", "dnsadmins", "group policy creator owners", "remote desktop users"];
// Microsoft's own drivers and accounts that Windows creates on its own.
const TRUSTED_SERVICE_PATHS = /\\programdata\\microsoft\\windows defender\\/i;
const BUILTIN_ACCOUNTS = ["wdagutilityaccount", "defaultaccount", "guest", "defaultuser0", "defaultuser100000"];
const SUSPICIOUS_SERVICE = /cmd(\.exe)?\s+\/c|powershell|pwsh|%comspec%|\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\|rundll32|mshta|regsvr32|\\admin\$|\\\\127\.0\.0\.1\\/i;

function finding(partial: Omit<Finding, "confidence"> & { confidence?: number }): Finding {
  return { confidence: 0.75, ...partial };
}

export function runForensicRules(events: UesEvent[], intel: IntelSnapshot = EMPTY_INTEL): Finding[] {
  const out: Finding[] = [];
  const byRule = new Map<string, Finding>();
  // One finding per rule, accumulating every matching event — reads better
  // in an RCA than twenty copies of "encoded PowerShell".
  const add = (f: Finding, event: UesEvent) => {
    const existing = byRule.get(f.ruleId);
    if (existing) {
      if (!existing.events.includes(event)) existing.events.push(event);
      existing.severity = maxSeverity(existing.severity, f.severity);
      for (const t of f.techniques) if (!existing.techniques.includes(t)) existing.techniques.push(t);
      return;
    }
    const created = { ...f, events: [event] };
    byRule.set(f.ruleId, created);
    out.push(created);
  };

  for (const e of events) {
    const c = cmd(e);
    const p = proc(e);
    const parent = lower(e.parentProcessName);

    // PowerShell script blocks (4104) carry the decoded script, so the
    // command-line rules apply to them too.
    if (e.eventType === "process_create" || e.eventType === "script_block") {
      if (OFFICE.includes(parent) && SHELLS.includes(p)) {
        add(finding({
          ruleId: "office_child_shell",
          title: "Office application spawned a shell",
          description: `${e.parentProcessName} launched ${e.processName} — typical of a malicious macro or embedded object in a phishing attachment.`,
          severity: "HIGH",
          detectionSource: "ANOMALOUS_ACTION",
          techniques: ["T1566.001", "T1204.002"],
          confidence: 0.85,
          events: [],
        }), e);
      }
      if (WEB_SERVERS.includes(parent) && SHELLS.includes(p)) {
        add(finding({
          ruleId: "webserver_child_shell",
          title: "Web server process spawned a shell",
          description: `${e.parentProcessName} launched ${e.processName} — consistent with a web shell or exploited public-facing application.`,
          severity: "HIGH",
          detectionSource: "ANOMALOUS_ACTION",
          techniques: ["T1190", "T1505.003"],
          confidence: 0.85,
          events: [],
        }), e);
      }
      if ((p.includes("powershell") || p.includes("pwsh")) && /\s-(e|en|enc|enco|encodedcommand)\s+[a-z0-9+/=]{16,}/i.test(c)) {
        add(finding({
          ruleId: "encoded_powershell",
          title: "Encoded PowerShell command",
          description: "PowerShell executed a base64-encoded command line, hiding its intent from casual inspection.",
          severity: "HIGH",
          detectionSource: "DEFENSE_EVASION",
          techniques: ["T1059.001", "T1027"],
          events: [],
        }), e);
      }
      if (/downloadstring|downloadfile|invoke-webrequest|iwr |net\.webclient|start-bitstransfer|invoke-expression|\biex\b/.test(c)) {
        add(finding({
          ruleId: "download_cradle",
          title: "Script download cradle",
          description: "A script interpreter fetched and/or executed remote content (download cradle).",
          severity: "HIGH",
          detectionSource: "ANOMALOUS_ACTION",
          techniques: ["T1059.001", "T1105"],
          events: [],
        }), e);
      }
      if ((p === "certutil.exe" && /-urlcache|-decode|-split/.test(c)) || (p === "bitsadmin.exe" && c.includes("/transfer"))) {
        add(finding({
          ruleId: "lolbin_transfer",
          title: "Living-off-the-land binary used for transfer/decoding",
          description: `${e.processName} was used to download or decode a payload.`,
          severity: "MEDIUM",
          detectionSource: "DEFENSE_EVASION",
          techniques: ["T1105", "T1140"],
          events: [],
        }), e);
      }
      if ((p === "rundll32.exe" || p === "regsvr32.exe" || p === "mshta.exe") && /https?:|\\appdata\\|\\temp\\|javascript:|scrobj/.test(c)) {
        add(finding({
          ruleId: "signed_binary_proxy",
          title: "Signed binary proxy execution",
          description: `${e.processName} executed content from a remote or user-writable location.`,
          severity: "HIGH",
          detectionSource: "DEFENSE_EVASION",
          techniques: ["T1218"],
          events: [],
        }), e);
      }
      if (/mimikatz|sekurlsa|lsadump|procdump.*lsass|\s-ma\s+lsass|comsvcs\.dll.*minidump|lsass\.dmp/.test(c)) {
        add(finding({
          ruleId: "credential_dumping",
          title: "LSASS credential dumping",
          description: "A process accessed or dumped LSASS memory to harvest credentials.",
          severity: "CRITICAL",
          detectionSource: "CREDENTIAL_HARVESTING",
          techniques: ["T1003.001"],
          confidence: 0.95,
          events: [],
        }), e);
      }
      if (/reg(\.exe)?\s+add\s+.*\\currentversion\\run/.test(c)) {
        add(finding({
          ruleId: "run_key_persistence",
          title: "Registry Run-key persistence",
          description: "An autostart Run key was added so the payload survives reboot.",
          severity: "HIGH",
          detectionSource: "PERSISTENCE",
          techniques: ["T1547.001"],
          events: [],
        }), e);
      }
      if (/schtasks(\.exe)?\s+\/create/.test(c)) {
        add(finding({
          ruleId: "scheduled_task_persistence",
          title: "Scheduled task created",
          description: "A scheduled task was registered, commonly used for persistence or delayed execution.",
          severity: "MEDIUM",
          detectionSource: "PERSISTENCE",
          techniques: ["T1053.005"],
          events: [],
        }), e);
      }
      if (/\bsc(\.exe)?\s+create\b|new-service/.test(c)) {
        add(finding({
          ruleId: "service_persistence",
          title: "New service installed",
          description: "A Windows service was created — a persistence and privilege mechanism.",
          severity: "HIGH",
          detectionSource: "PERSISTENCE",
          techniques: ["T1543.003"],
          events: [],
        }), e);
      }
      if (/wevtutil(\.exe)?\s+(cl|clear-log)|clear-eventlog/.test(c)) {
        add(finding({
          ruleId: "log_clearing",
          title: "Event logs cleared",
          description: "Windows event logs were cleared to destroy forensic evidence.",
          severity: "HIGH",
          detectionSource: "DEFENSE_EVASION",
          techniques: ["T1070.001"],
          confidence: 0.9,
          events: [],
        }), e);
      }
      if (/set-mppreference.*disable|disablerealtimemonitoring|sc(\.exe)?\s+stop\s+windefend/.test(c)) {
        add(finding({
          ruleId: "defender_tampering",
          title: "Security tooling disabled",
          description: "Microsoft Defender protections were disabled.",
          severity: "HIGH",
          detectionSource: "DEFENSE_EVASION",
          techniques: ["T1562.001"],
          confidence: 0.9,
          events: [],
        }), e);
      }
      if (/vssadmin(\.exe)?\s+delete\s+shadows|wbadmin(\.exe)?\s+delete\s+catalog|bcdedit.*recoveryenabled\s+no|wmic\s+shadowcopy\s+delete/.test(c)) {
        add(finding({
          ruleId: "inhibit_recovery",
          title: "System recovery inhibited",
          description: "Shadow copies / backup catalog were deleted — a strong ransomware precursor.",
          severity: "CRITICAL",
          detectionSource: "IMPACT",
          techniques: ["T1490"],
          confidence: 0.95,
          events: [],
        }), e);
      }
      if (/psexec|paexec|wmic\s+\/node:|winrs\s|enter-pssession|invoke-command\s+-computername/.test(c)) {
        add(finding({
          ruleId: "remote_execution",
          title: "Remote execution on another host",
          description: "A remote-execution tool was used against another system (lateral movement).",
          severity: "HIGH",
          detectionSource: "LATERAL_MOVEMENT",
          techniques: [c.includes("wmic") ? "T1047" : c.includes("psexec") || c.includes("paexec") ? "T1569.002" : "T1021.006"],
          events: [],
        }), e);
      }
      if (/rclone|megacmd|curl.*(-t|--upload-file)\s|scp\s+.*@/.test(c)) {
        add(finding({
          ruleId: "exfil_tool",
          title: "Data exfiltration tooling",
          description: "A tool commonly used to move data off-host was executed.",
          severity: "HIGH",
          detectionSource: "DATA_EXFILTRATION",
          techniques: ["T1567"],
          events: [],
        }), e);
      }
    }

    if (e.eventType === "process_access" && /lsass/.test(lower(String(e.raw.TargetImage ?? "")))) {
      add(finding({
        ruleId: "credential_dumping",
        title: "LSASS credential dumping",
        description: "A process opened a handle to LSASS — credential theft.",
        severity: "CRITICAL",
        detectionSource: "CREDENTIAL_HARVESTING",
        techniques: ["T1003.001"],
        confidence: 0.9,
        events: [],
      }), e);
    }

    if (e.eventType.startsWith("registry") && /\\currentversion\\run(once)?\\/.test(lower(e.filePath))) {
      add(finding({
        ruleId: "run_key_persistence",
        title: "Registry Run-key persistence",
        description: "An autostart Run key value was written.",
        severity: "HIGH",
        detectionSource: "PERSISTENCE",
        techniques: ["T1547.001"],
        events: [],
      }), e);
    }

    if (e.eventType === "file_create" && e.filePath && EXECUTABLE_EXT.test(e.filePath) && STAGING_DIRS.some((d) => lower(e.filePath).includes(d))) {
      add(finding({
        ruleId: "staged_payload",
        title: "Executable dropped in a user-writable staging directory",
        description: "An executable or script was written to a temp/AppData-style path, typical of a dropper stage.",
        severity: "MEDIUM",
        detectionSource: "ANOMALOUS_ACTION",
        techniques: ["T1105"],
        events: [],
      }), e);
    }

    if (e.dstIp && !isPrivateIp(e.dstIp)) {
      const verdict = localVerdict("IP", e.dstIp, intel);
      if (verdict.score >= 0.7) {
        add(finding({
          ruleId: "known_bad_destination",
          title: "Connection to known-malicious infrastructure",
          description: `Outbound connection to ${e.dstIp} (${verdict.reasons.join("; ")}).`,
          severity: "CRITICAL",
          detectionSource: "THREAT_INTEL_MATCH",
          techniques: ["T1071"],
          confidence: 0.9,
          events: [],
        }), e);
      }
      if (SCRIPTING.includes(p)) {
        add(finding({
          ruleId: "script_outbound",
          title: "Scripting engine made an outbound connection",
          description: `${e.processName} connected to external host ${e.dstIp}${e.dstPort ? `:${e.dstPort}` : ""} — likely payload retrieval or C2.`,
          severity: "HIGH",
          detectionSource: "ANOMALOUS_ACTION",
          techniques: ["T1071.001"],
          events: [],
        }), e);
      }
      if (e.dstPort !== undefined && !STANDARD_PORTS.has(e.dstPort) && (SCRIPTING.includes(p) || e.dstPort === 4444)) {
        add(finding({
          ruleId: "non_standard_port",
          title: "C2 over a non-standard port",
          description: `Connection to ${e.dstIp}:${e.dstPort} uses a port associated with reverse shells / C2 frameworks.`,
          severity: "HIGH",
          detectionSource: "ANOMALOUS_ACTION",
          techniques: ["T1571"],
          events: [],
        }), e);
      }
    }

    // --- Windows Security / System / Task Scheduler events
    if (e.eventType === "log_cleared") {
      add(finding({
        ruleId: "log_clearing",
        title: "Event logs cleared",
        description: `The ${String(e.raw.Channel ?? "event")} log was cleared${e.userName ? ` by ${e.userName}` : ""} — evidence destruction.`,
        severity: "HIGH",
        detectionSource: "DEFENSE_EVASION",
        techniques: ["T1070.001"],
        confidence: 0.9,
        events: [],
      }), e);
    }
    const serviceCommand = `${e.commandLine ?? ""} ${e.filePath ?? ""}`;
    if (e.eventType === "service_install" && SUSPICIOUS_SERVICE.test(serviceCommand) && !TRUSTED_SERVICE_PATHS.test(serviceCommand)) {
      add(finding({
        ruleId: "service_persistence",
        title: "Suspicious service installed",
        description: `Service ${String(e.raw.ServiceName ?? "")} runs ${e.commandLine ?? e.filePath} — a shell or a user-writable path, typical of remote execution tools and persistence.`,
        severity: "HIGH",
        detectionSource: "PERSISTENCE",
        techniques: ["T1543.003", "T1569.002"],
        confidence: 0.85,
        events: [],
      }), e);
    }
    if (e.eventType === "scheduled_task_create") {
      add(finding({
        ruleId: "scheduled_task_persistence",
        title: "Scheduled task created",
        description: `Task ${String(e.raw.TaskName ?? "")} was registered${e.commandLine ? ` to run ${e.commandLine}` : ""} — commonly used for persistence or delayed execution.`,
        severity: SUSPICIOUS_SERVICE.test(e.commandLine ?? "") ? "HIGH" : "MEDIUM",
        detectionSource: "PERSISTENCE",
        techniques: ["T1053.005"],
        events: [],
      }), e);
    }
    if (e.eventType === "account_created" && !BUILTIN_ACCOUNTS.includes(lower(e.userName))) {
      add(finding({
        ruleId: "account_created",
        title: "Local or domain account created",
        description: `Account ${e.userName ?? ""} was created by ${String(e.raw.SubjectUserName ?? "an unknown user")} — attackers add accounts to keep access.`,
        severity: "MEDIUM",
        detectionSource: "PERSISTENCE",
        techniques: ["T1136.001"],
        events: [],
      }), e);
    }
    if (e.eventType === "group_member_added" && PRIVILEGED_GROUPS.includes(lower(String(e.raw.TargetUserName ?? "")))) {
      add(finding({
        ruleId: "privileged_group_add",
        title: "Member added to a privileged group",
        description: `${[e.raw.MemberName, e.raw.MemberSid].map((v) => String(v ?? "")).find((v) => v && v !== "-") ?? "An account"} was added to ${String(e.raw.TargetUserName)} by ${String(e.raw.SubjectUserName ?? "an unknown user")}.`,
        severity: "HIGH",
        detectionSource: "ANOMALOUS_ACTION",
        techniques: ["T1098"],
        confidence: 0.8,
        events: [],
      }), e);
    }
    if (e.eventType === "auth" && String(e.raw.LogonType ?? "") === "10" && e.hostIp && /^\d{1,3}(\.\d{1,3}){3}$/.test(e.hostIp) && !isPrivateIp(e.hostIp)) {
      add(finding({
        ruleId: "external_rdp_logon",
        title: "Remote Desktop logon from the internet",
        description: `${e.userName ?? "An account"} logged on over RDP from public address ${e.hostIp}.`,
        severity: "MEDIUM",
        detectionSource: "ANOMALOUS_ACTION",
        techniques: ["T1021.001", "T1133"],
        events: [],
      }), e);
    }

    if (e.eventType === "dns_query" && e.query && e.query.split(".")[0].length > 40) {
      add(finding({
        ruleId: "dns_tunneling",
        title: "Possible DNS tunneling",
        description: `Abnormally long DNS label queried (${e.query.slice(0, 60)}…).`,
        severity: "MEDIUM",
        detectionSource: "DATA_EXFILTRATION",
        techniques: ["T1071.004", "T1048.003"],
        events: [],
      }), e);
    }
  }

  out.push(...credentialAttacks(events));

  // Discovery burst: several distinct recon commands from one host within 10 min.
  const discovery = events.filter((e) => e.eventType === "process_create" && DISCOVERY.some((d) => cmd(e).includes(d)));
  const byHost = new Map<string, UesEvent[]>();
  for (const e of discovery) byHost.set(e.hostName ?? "?", [...(byHost.get(e.hostName ?? "?") ?? []), e]);
  for (const [host, list] of byHost) {
    list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    const distinct = new Set(list.map((e) => DISCOVERY.find((d) => cmd(e).includes(d))));
    const spanMin = (list[list.length - 1].timestamp.getTime() - list[0].timestamp.getTime()) / 60_000;
    if (distinct.size >= 3 && spanMin <= 10) {
      out.push({
        ruleId: "discovery_burst",
        title: "Burst of host and account discovery",
        description: `${distinct.size} distinct discovery commands on ${host} within ${Math.max(1, Math.round(spanMin))} min (${[...distinct].join(", ")}).`,
        severity: "MEDIUM",
        detectionSource: "RECONNAISSANCE",
        techniques: ["T1087", "T1082", "T1016"],
        confidence: 0.7,
        events: list,
      });
    }
  }

  for (const f of out) f.events.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  return out.sort((a, b) => a.events[0].timestamp.getTime() - b.events[0].timestamp.getTime());
}

// Techniques the deterministic rules can emit — feeds the coverage matrix.
// Failed-logon patterns from Windows Security logs: many failures against one
// account (guessing), or one source failing across many accounts (spraying).
// A success for the same account or source afterwards makes it critical.
const BRUTE_WINDOW_MS = 15 * 60_000;
const BRUTE_MIN_FAILURES = 10;
const SPRAY_MIN_ACCOUNTS = 5;

function credentialAttacks(events: UesEvent[]): Finding[] {
  const failures = events.filter((e) => e.eventType === "auth_failure").sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  const successes = events.filter((e) => e.eventType === "auth");
  const out: Finding[] = [];
  const burst = (list: UesEvent[]) => {
    for (let i = 0; i < list.length; i++) {
      let j = i;
      while (j + 1 < list.length && list[j + 1].timestamp.getTime() - list[i].timestamp.getTime() <= BRUTE_WINDOW_MS) j++;
      if (j - i + 1 >= BRUTE_MIN_FAILURES || new Set(list.slice(i, j + 1).map((e) => lower(e.userName))).size >= SPRAY_MIN_ACCOUNTS) return list.slice(i, j + 1);
    }
    return null;
  };
  const after = (window: UesEvent[], match: (s: UesEvent) => boolean) => {
    const start = window[0].timestamp.getTime();
    return successes.find((s) => match(s) && s.timestamp.getTime() >= start && s.timestamp.getTime() - window[window.length - 1].timestamp.getTime() <= 30 * 60_000);
  };

  const byUser = new Map<string, UesEvent[]>();
  for (const e of failures) if (e.userName) byUser.set(lower(e.userName), [...(byUser.get(lower(e.userName)) ?? []), e]);
  for (const [user, list] of byUser) {
    const window = list.length >= BRUTE_MIN_FAILURES ? burst(list) : null;
    if (!window || window.length < BRUTE_MIN_FAILURES) continue;
    const success = after(window, (s) => lower(s.userName) === user);
    out.push({
      ruleId: "brute_force",
      title: success ? "Password guessing followed by a successful logon" : "Password guessing against one account",
      description: `${window.length} failed logons for ${window[0].userName} within ${Math.max(1, Math.round((window[window.length - 1].timestamp.getTime() - window[0].timestamp.getTime()) / 60_000))} min${success ? `, then a successful logon at ${success.timestamp.toISOString().slice(11, 19)} UTC` : ""}.`,
      severity: success ? "CRITICAL" : "HIGH",
      detectionSource: "CREDENTIAL_HARVESTING",
      techniques: ["T1110.001"],
      confidence: success ? 0.9 : 0.75,
      events: success ? [...window, success] : window,
    });
  }

  const bySource = new Map<string, UesEvent[]>();
  for (const e of failures) if (e.hostIp) bySource.set(e.hostIp, [...(bySource.get(e.hostIp) ?? []), e]);
  for (const [source, list] of bySource) {
    const window = burst(list);
    if (!window) continue;
    const accounts = new Set(window.map((e) => lower(e.userName)));
    if (accounts.size < SPRAY_MIN_ACCOUNTS) continue;
    const success = after(window, (s) => s.hostIp === source);
    out.push({
      ruleId: "password_spraying",
      title: success ? "Password spraying followed by a successful logon" : "Password spraying from one source",
      description: `${source} failed to log on to ${accounts.size} different accounts within ${BRUTE_WINDOW_MS / 60_000} min${success ? `, then logged on as ${success.userName}` : ""}.`,
      severity: success ? "CRITICAL" : "HIGH",
      detectionSource: "CREDENTIAL_HARVESTING",
      techniques: ["T1110.003"],
      confidence: success ? 0.9 : 0.8,
      events: success ? [...window, success] : window,
    });
  }
  return out;
}

export const INVESTIGATION_RULE_TECHNIQUES: Array<{ rule: string; techniques: string[] }> = [
  { rule: "office_child_shell", techniques: ["T1566.001", "T1204.002"] },
  { rule: "webserver_child_shell", techniques: ["T1190", "T1505.003"] },
  { rule: "encoded_powershell", techniques: ["T1059.001", "T1027"] },
  { rule: "download_cradle", techniques: ["T1105"] },
  { rule: "lolbin_transfer", techniques: ["T1140"] },
  { rule: "signed_binary_proxy", techniques: ["T1218"] },
  { rule: "credential_dumping", techniques: ["T1003.001"] },
  { rule: "run_key_persistence", techniques: ["T1547.001"] },
  { rule: "scheduled_task_persistence", techniques: ["T1053.005"] },
  { rule: "service_persistence", techniques: ["T1543.003"] },
  { rule: "log_clearing", techniques: ["T1070.001"] },
  { rule: "defender_tampering", techniques: ["T1562.001"] },
  { rule: "inhibit_recovery", techniques: ["T1490"] },
  { rule: "remote_execution", techniques: ["T1047", "T1569.002", "T1021.006"] },
  { rule: "exfil_tool", techniques: ["T1567"] },
  { rule: "known_bad_destination", techniques: ["T1071"] },
  { rule: "script_outbound", techniques: ["T1071.001"] },
  { rule: "non_standard_port", techniques: ["T1571"] },
  { rule: "dns_tunneling", techniques: ["T1071.004", "T1048.003"] },
  { rule: "discovery_burst", techniques: ["T1087", "T1082", "T1016"] },
  { rule: "brute_force", techniques: ["T1110.001"] },
  { rule: "password_spraying", techniques: ["T1110.003"] },
  { rule: "account_created", techniques: ["T1136.001"] },
  { rule: "privileged_group_add", techniques: ["T1098"] },
  { rule: "external_rdp_logon", techniques: ["T1021.001", "T1133"] },
];

// ---------------------------------------------------------------------------
// Agent-shaped outputs (same contract the LLM agents fill)
// ---------------------------------------------------------------------------

export interface TriageResult {
  alert_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  mitre_tactic: string;
  initial_hypothesis: string;
  evidence_required: string[];
}

export interface RcaResult {
  root_cause: string;
  timeline: string[];
  confidence_score: number;
  mitre_techniques: Array<{ id: string; name: string; evidence: string }>;
}

export interface QaResult {
  is_valid: boolean;
  validated_evidence: string[];
  issues: string[];
}

export function hhmmss(d: Date) {
  return d.toISOString().slice(11, 19);
}

export function describeEvent(e: UesEvent): string {
  const pid = e.processPid !== undefined ? ` (PID ${e.processPid})` : "";
  const on = e.hostName ? ` on ${e.hostName}` : "";
  switch (e.eventType) {
    case "process_create":
      return `${e.parentProcessName ? `${e.parentProcessName} spawned ` : ""}${e.processName ?? "process"}${pid}${on}${e.commandLine ? `: ${e.commandLine}` : ""}`;
    case "network_connect":
      return `${e.processName ?? "process"}${pid} connected to ${e.dstIp}${e.dstPort ? `:${e.dstPort}` : ""}`;
    case "dns_query":
      return `${e.processName ?? "process"}${pid} resolved ${e.query}`;
    case "file_create":
      return `${e.processName ?? "process"}${pid} wrote ${e.filePath}`;
    case "image_load":
      return `${e.processName ?? "process"}${pid} loaded ${e.filePath}`;
    case "process_access":
      return `${e.processName ?? "process"}${pid} opened ${String(e.raw.TargetImage ?? "another process")}`;
    default:
      if (e.eventType.startsWith("registry")) return `${e.processName ?? "process"}${pid} modified ${e.filePath ?? "registry"}`;
      return `${e.eventType}${e.processName ? ` by ${e.processName}${pid}` : ""}${on}${e.raw.message ? `: ${String(e.raw.message).slice(0, 160)}` : ""}`;
  }
}

const TACTIC_OF = (id: string) => {
  const t = resolveTechnique(id);
  return t ? t.tactic : undefined;
};

function severityLabel(s: CaseSeverity): TriageResult["severity"] {
  return s.toLowerCase() as TriageResult["severity"];
}

export function heuristicTriage(title: string, findings: Finding[]): TriageResult {
  if (findings.length === 0) {
    return {
      alert_type: "No malicious activity identified",
      severity: "low",
      mitre_tactic: "None",
      initial_hypothesis: `None of the forensic rules matched the supplied telemetry for "${title}". The alert may be a false positive, or the relevant telemetry (process, network, file events) wasn't included.`,
      evidence_required: ["process_create events for the alerting host", "network_connect events around the alert time"],
    };
  }
  const severity = maxSeverity(...findings.map((f) => f.severity));
  const lead = [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))[0];
  const tacticId = lead.techniques.map(TACTIC_OF).find(Boolean);
  const tactic = tacticId ? `${getTactic(tacticId)?.name ?? tacticId} (${tacticId})` : undefined;
  const evidence = new Set<string>();
  for (const f of findings) {
    if (f.events.some((e) => e.eventType === "process_create")) evidence.add("process_create (parent/child lineage)");
    if (f.events.some((e) => e.dstIp)) evidence.add("network_connect to external destinations");
    if (f.events.some((e) => e.eventType === "file_create")) evidence.add("file_create in staging directories");
  }
  return {
    alert_type: lead.title,
    severity: severityLabel(severity),
    mitre_tactic: tactic ?? "Unknown",
    initial_hypothesis:
      findings.slice(0, 3).map((f) => f.description).join(" ") +
      (findings.length > 3 ? ` ${findings.length - 3} further finding(s): ${findings.slice(3).map((f) => f.title.toLowerCase()).join(", ")}.` : ""),
    evidence_required: [...evidence],
  };
}

// Prior cases that share evidence with this one (lib/cases/related), passed to
// the RCA as context — asip fed its Qdrant "similar incidents" the same way.
export interface PriorCase {
  title: string;
  source: string;
  verdict: string | null;
  severity: string;
  openedAt: string;
  sharedEvidence: string[];
  rootCause?: string;
}

function priorCaseSentence(prior: PriorCase[]): string {
  if (prior.length === 0) return "";
  const shown = prior
    .slice(0, 3)
    .map((p) => `"${p.title}" (${p.verdict ?? "no verdict"}; ${p.sharedEvidence.slice(0, 2).join(", ")})`)
    .join("; ");
  return `This activity overlaps ${prior.length} earlier case(s): ${shown}.`;
}

export function heuristicRca(findings: Finding[], graph: EntityGraph, prior: PriorCase[] = []): RcaResult {
  if (findings.length === 0) {
    return {
      root_cause: ["No attack chain could be established from the supplied telemetry.", priorCaseSentence(prior)].filter(Boolean).join(" "),
      timeline: [],
      confidence_score: 0.3,
      mitre_techniques: [],
    };
  }

  const first = findings[0].events[0];
  const node = graph.nodes.find((n) => n.type === "process" && n.pid === first.processPid && n.host === (first.hostName ?? "unknown_host") && n.observed);
  const chain = node ? ancestry(graph, node.id).map((n) => n.label) : [];

  const entry = findings.find((f) => f.ruleId === "office_child_shell")
    ? "a malicious Office document (likely a phishing attachment) whose macro or embedded object launched a shell"
    : findings.find((f) => f.ruleId === "webserver_child_shell")
      ? "exploitation of a public-facing web application, which spawned a shell from the web server process"
      : "an entry point not visible in this telemetry";

  const who = [first.userName && `user ${first.userName}`, first.hostName && `host ${first.hostName}`].filter(Boolean).join(" on ");
  const narrative = [
    `Activity${who ? ` for ${who}` : ""} most likely began with ${entry}.`,
    chain.length > 1 ? `Observed process lineage: ${chain.join(" → ")}.` : "",
    ...findings.map((f) => `${f.title}: ${f.description}`),
    priorCaseSentence(prior),
  ].filter(Boolean);

  const timelineEvents = [...new Set(findings.flatMap((f) => f.events))].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  const techniques = new Map<string, { id: string; name: string; evidence: string }>();
  for (const f of findings) {
    for (const id of f.techniques) {
      const t = resolveTechnique(id);
      if (t && !techniques.has(t.id)) techniques.set(t.id, { id: t.id, name: getTechnique(t.id)!.name, evidence: f.title });
    }
  }
  const categories = new Set(findings.map((f) => f.detectionSource)).size;

  return {
    root_cause: narrative.join(" "),
    timeline: timelineEvents.slice(0, 60).map((e) => `${hhmmss(e.timestamp)} - ${describeEvent(e)}`),
    confidence_score: Math.min(0.95, 0.5 + 0.08 * findings.length + 0.04 * categories),
    mitre_techniques: [...techniques.values()],
  };
}

// The adversarial QA agent's job, done mechanically: every claim must trace
// to a real event, and causality must respect time (a process can't connect
// out before it was created — the exact failure asip's QA prompt calls out).
export function heuristicQa(rca: RcaResult, events: UesEvent[], graph: EntityGraph): QaResult {
  const issues: string[] = [];
  const validated: string[] = [];
  const times = new Set(events.map((e) => hhmmss(e.timestamp)));

  for (const line of rca.timeline) {
    const ts = line.slice(0, 8);
    if (times.has(ts)) validated.push(line);
    else issues.push(`Timeline entry "${line}" does not correspond to any ingested event timestamp.`);
  }

  const created = new Map<string, number>();
  for (const n of graph.nodes) if (n.type === "process" && n.timestamp && n.pid !== undefined) created.set(`${n.host}|${n.pid}`, Date.parse(n.timestamp));
  for (const e of events) {
    if (e.eventType !== "network_connect" || e.processPid === undefined) continue;
    const t = created.get(`${e.hostName ?? "unknown_host"}|${e.processPid}`);
    if (t !== undefined && e.timestamp.getTime() < t) {
      issues.push(`${e.processName} (PID ${e.processPid}) connected to ${e.dstIp} at ${hhmmss(e.timestamp)}, before its observed creation at ${hhmmss(new Date(t))} — PID reuse or clock skew.`);
    }
  }

  return { is_valid: issues.length === 0, validated_evidence: validated, issues };
}

export function heuristicReport(args: {
  title: string;
  triage: TriageResult;
  rca: RcaResult;
  qa: QaResult;
  findings: Finding[];
  events: UesEvent[];
}): string {
  const { title, triage, rca, qa, findings, events } = args;
  const hosts = [...new Set(events.map((e) => e.hostName).filter(Boolean))];
  const users = [...new Set(events.map((e) => e.userName).filter(Boolean))];
  const ips = [...new Set(events.map((e) => e.dstIp).filter((ip): ip is string => !!ip && !isPrivateIp(ip)))];
  const hashes = [...new Set(events.map((e) => e.fileHash).filter(Boolean))];
  const has = (rule: string) => findings.some((f) => f.ruleId === rule);

  const immediate = [
    hosts.length && `Isolate ${hosts.map((h) => `\`${h}\``).join(", ")} at the EDR layer.`,
    ips.length && `Block egress to ${ips.map((ip) => `\`${ip}\``).join(", ")} at the proxy / firewall.`,
    (has("credential_dumping") || users.length) && `Revoke sessions and reset credentials for ${users.length ? users.map((u) => `\`${u}\``).join(", ") : "affected accounts"}.`,
  ].filter(Boolean);
  const shortTerm = [
    hashes.length && `Sweep the fleet for file hashes: ${hashes.slice(0, 5).map((h) => `\`${h}\``).join(", ")}.`,
    (has("run_key_persistence") || has("scheduled_task_persistence") || has("service_persistence")) && "Remove the persistence mechanisms identified above and hunt for the same keys/tasks/services elsewhere.",
    has("office_child_shell") && "Search mail gateways for the originating message and purge it from all mailboxes.",
    has("remote_execution") && "Review authentication logs on every host reached by the remote-execution tooling.",
  ].filter(Boolean);
  const longTerm = [
    has("office_child_shell") && "Enforce ASR rules blocking Office applications from creating child processes; disable macros from the internet.",
    (has("encoded_powershell") || has("download_cradle")) && "Enable PowerShell Constrained Language Mode and script block logging.",
    has("inhibit_recovery") && "Verify offline / immutable backups exist and are restorable.",
    "Feed confirmed IOCs into HELIOS threat intelligence so future telemetry matches automatically.",
  ].filter(Boolean);

  const list = (items: unknown[]) => (items.length ? items.map((i) => `- ${i}`).join("\n") : "- None identified");

  return `# Incident report: ${title}

## Executive summary
**${triage.alert_type}** — assessed severity **${triage.severity}**, confidence **${Math.round(rca.confidence_score * 100)}%**.
${findings.length ? `${findings.length} forensic finding(s) across ${events.length} events from ${hosts.length || "unknown"} host(s).` : `No forensic rule matched across ${events.length} events.`}

## Root cause analysis
${rca.root_cause}

### Timeline
${rca.timeline.length ? rca.timeline.map((t) => `- \`${t.slice(0, 8)}\` ${t.slice(11)}`).join("\n") : "- No timeline could be reconstructed."}

## MITRE ATT&CK mapping
${rca.mitre_techniques.length ? `| Technique | Name | Evidence |\n|---|---|---|\n${rca.mitre_techniques.map((t) => `| ${t.id} | ${t.name} | ${t.evidence} |`).join("\n")}` : "No techniques mapped."}

## Containment & mitigation
### Immediate
${list(immediate)}

### Short-term
${list(shortTerm)}

### Long-term
${list(longTerm)}

## Evidence verification
${qa.is_valid ? `All ${qa.validated_evidence.length} timeline claims trace to ingested events.` : `QA raised ${qa.issues.length} issue(s):\n${qa.issues.map((i) => `- ${i}`).join("\n")}`}
`;
}
