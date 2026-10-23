import type { Detection, Detector, UnifiedEvent } from "@/lib/siem/types";
import { SecurityPolicy } from "@/lib/siem/policy";

// Ported from signal-fusion's seven MITRE-coverage detectors
// (reconnaissance, credentialHarvesting, lateralMovement, dataExfiltration,
// persistence, defenseEvasion, impact). Matching is on the normalized
// command line / metadata, same as the originals, with a few false-positive
// fixes noted inline.

type Hit = Omit<Detection, "detector" | "detectionSource" | "matchedEvents">;

function emit(detector: Detector, events: UnifiedEvent[], hit: Hit): Detection {
  return { detector: detector.name, detectionSource: detector.detectionSource, matchedEvents: events, ...hit };
}

const cmd = (e: UnifiedEvent) => (e.actor.process ?? "").toLowerCase();
const meta = (e: UnifiedEvent, key: string) => e.metadata[key];

function groupBy<K>(events: UnifiedEvent[], key: (e: UnifiedEvent) => K | undefined) {
  const map = new Map<K, UnifiedEvent[]>();
  for (const e of events) {
    const k = key(e);
    if (k === undefined) continue;
    const list = map.get(k) ?? [];
    list.push(e);
    map.set(k, list);
  }
  return map;
}

export const reconnaissanceDetector: Detector = {
  name: "ReconnaissanceDetector",
  detectionSource: "RECONNAISSANCE",
  description: "Port scanning, DNS enumeration, OSINT lookups, and host discovery commands.",
  techniques: ["T1595", "T1590", "T1593", "T1082"],
  run(events) {
    const out: Detection[] = [];
    const { portScanDistinctPorts, dnsEnumerationQueries } = SecurityPolicy.reconnaissance;

    for (const [ip, list] of groupBy(events, (e) => e.network.sourceIp)) {
      const network = list.filter((e) => e.source === "network");
      const ports = new Set(network.map((e) => e.network.destPort ?? meta(e, "port")).filter((p) => p !== undefined));
      // signal-fusion's scan scenario packs the probed ports into one event.
      for (const e of network) {
        const listed = meta(e, "ports");
        if (Array.isArray(listed)) listed.forEach((p) => ports.add(p as number));
      }
      if (ports.size >= portScanDistinctPorts) {
        out.push(emit(this, network.slice(0, 10), {
          ruleId: "port_scan",
          signals: ["port_scanning", "network_reconnaissance"],
          confidence: 0.9,
          mitreTactics: ["Reconnaissance"],
          mitreTechniques: ["T1595 - Active Scanning"],
          reasoning: [`Source IP ${ip} probed ${ports.size} distinct ports`, `Ports: ${[...ports].slice(0, 10).join(", ")}`],
        }));
      }

      const dns = network.filter((e) => meta(e, "type") === "DNS");
      if (dns.length >= dnsEnumerationQueries) {
        out.push(emit(this, dns.slice(0, 20), {
          ruleId: "dns_enumeration",
          signals: ["dns_enumeration", "network_mapping"],
          confidence: 0.85,
          mitreTactics: ["Reconnaissance"],
          mitreTechniques: ["T1590 - Gather Victim Network Information"],
          reasoning: [`Source IP ${ip} issued ${dns.length} DNS queries`, "High-volume DNS suggests subdomain enumeration"],
        }));
      }
    }

    // github.com was on signal-fusion's list; dropped as routine developer traffic.
    const osint = ["linkedin.com", "pastebin.com", "shodan.io", "censys.io"];
    for (const e of events) {
      const url = String(meta(e, "url") ?? "").toLowerCase();
      if (e.source === "network" && url && osint.some((s) => url.includes(s))) {
        out.push(emit(this, [e], {
          ruleId: "osint_lookup",
          signals: ["osint_gathering", "information_collection"],
          confidence: 0.6,
          mitreTactics: ["Reconnaissance"],
          mitreTechniques: ["T1593 - Search Open Websites/Domains"],
          reasoning: [`Access to OSINT platform: ${meta(e, "url")}`],
        }));
      }

      const c = cmd(e);
      if (e.source === "endpoint" && ["systeminfo", "ipconfig", "hostname", "uname -a", "cat /etc/os-release"].some((k) => c.includes(k))) {
        out.push(emit(this, [e], {
          ruleId: "system_info_discovery",
          signals: ["system_enumeration", "host_discovery"],
          confidence: 0.7,
          mitreTactics: ["Discovery"],
          mitreTechniques: ["T1082 - System Information Discovery"],
          reasoning: [`System information command executed: ${e.actor.process}`, `User: ${e.actor.user ?? "unknown"}`],
        }));
      }
    }
    return out;
  },
};

export const credentialHarvestingDetector: Detector = {
  name: "CredentialHarvestingDetector",
  detectionSource: "CREDENTIAL_HARVESTING",
  description: "Credential dumping tools, password spraying, keyloggers, and Kerberos ticket attacks.",
  techniques: ["T1003", "T1110.003", "T1056", "T1558"],
  run(events) {
    const out: Detection[] = [];

    for (const e of events) {
      if (e.source !== "endpoint") continue;
      const c = cmd(e);
      if (["mimikatz", "procdump", "pwdump", "gsecdump", "wce.exe", "lsass"].some((t) => c.includes(t))) {
        out.push(emit(this, [e], {
          ruleId: "credential_dumping",
          signals: ["credential_dumping", "lsass_access", "memory_scraping"],
          confidence: 0.95,
          mitreTactics: ["Credential Access"],
          mitreTechniques: ["T1003 - OS Credential Dumping"],
          reasoning: [`Credential dumping tool detected: ${e.actor.process}`, `User: ${e.actor.user}`, `Host: ${e.actor.host ?? "unknown"}`],
        }));
      }
      if (["keylogger", "keylog", "inputcapture", "cliplogger"].some((k) => c.includes(k))) {
        out.push(emit(this, [e], {
          ruleId: "keylogger",
          signals: ["keylogging", "input_capture"],
          confidence: 0.9,
          mitreTactics: ["Credential Access", "Collection"],
          mitreTechniques: ["T1056 - Input Capture"],
          reasoning: [`Keylogger detected: ${e.actor.process}`],
        }));
      }
      if (["rubeus", "kerberoast", "asreproast", "golden ticket"].some((k) => c.includes(k))) {
        out.push(emit(this, [e], {
          ruleId: "kerberos_attack",
          signals: ["kerberos_attack", "ticket_theft"],
          confidence: 0.95,
          mitreTactics: ["Credential Access"],
          mitreTechniques: ["T1558 - Steal or Forge Kerberos Tickets"],
          reasoning: [`Kerberos attack tool detected: ${e.actor.process}`],
        }));
      }
    }

    const { minDistinctUsers, minFailures } = SecurityPolicy.bruteForce;
    const auth = events.filter((e) => e.source === "auth");
    for (const [ip, list] of groupBy(auth, (e) => e.network.sourceIp)) {
      const users = new Set(list.map((e) => e.actor.user).filter(Boolean));
      const failures = list.filter((e) => e.eventType === "LOGIN_FAIL");
      if (users.size >= minDistinctUsers && failures.length >= minFailures) {
        out.push(emit(this, list.slice(0, 10), {
          ruleId: "password_spraying",
          signals: ["password_spraying", "credential_stuffing"],
          confidence: 0.85,
          mitreTactics: ["Credential Access"],
          mitreTechniques: ["T1110.003 - Password Spraying"],
          reasoning: [`Source IP ${ip} attempted ${users.size} different accounts`, `${failures.length} failed attempts`],
        }));
      }
    }
    return out;
  },
};

const isInternal = (ip?: string) => !!ip && (ip.startsWith("10.") || ip.startsWith("192.168.") || /^172\.(1[6-9]|2\d|3[01])\./.test(ip));

export const lateralMovementDetector: Detector = {
  name: "LateralMovementDetector",
  detectionSource: "LATERAL_MOVEMENT",
  description: "Internal RDP, admin-share access, PsExec, remote WMI, and pass-the-hash.",
  techniques: ["T1021.001", "T1021.002", "T1569.002", "T1047", "T1550.002"],
  run(events) {
    const out: Detection[] = [];
    for (const e of events) {
      const c = cmd(e);
      if (e.source === "network") {
        const service = String(meta(e, "service") ?? meta(e, "type") ?? "").toUpperCase();
        if (service === "RDP" && isInternal(e.network.sourceIp) && isInternal(e.network.destIp)) {
          out.push(emit(this, [e], {
            ruleId: "internal_rdp",
            signals: ["rdp_lateral_movement", "remote_access"],
            confidence: 0.75,
            mitreTactics: ["Lateral Movement"],
            mitreTechniques: ["T1021.001 - Remote Desktop Protocol"],
            reasoning: [`Internal RDP from ${e.network.sourceIp} to ${e.network.destIp}`],
          }));
        }
        const share = String(meta(e, "share") ?? "");
        if (["C$", "ADMIN$", "IPC$"].some((s) => share.toUpperCase().includes(s))) {
          out.push(emit(this, [e], {
            ruleId: "admin_share_access",
            signals: ["admin_share_access", "smb_lateral_movement"],
            confidence: 0.8,
            mitreTactics: ["Lateral Movement"],
            mitreTechniques: ["T1021.002 - SMB/Windows Admin Shares"],
            reasoning: [`Admin share ${share} accessed from ${e.network.sourceIp} to ${e.network.destIp}`],
          }));
        }
      }
      if (e.source === "endpoint") {
        if (c.includes("psexec") || c.includes("paexec")) {
          out.push(emit(this, [e], {
            ruleId: "psexec",
            signals: ["psexec_execution", "remote_execution"],
            confidence: 0.9,
            mitreTactics: ["Lateral Movement", "Execution"],
            mitreTechniques: ["T1021.002 - SMB/Windows Admin Shares", "T1569.002 - Service Execution"],
            reasoning: [`PsExec detected: ${e.actor.process}`],
          }));
        }
        if (c.includes("wmic") && (c.includes("/node:") || c.includes("process call create"))) {
          out.push(emit(this, [e], {
            ruleId: "remote_wmi",
            signals: ["wmi_lateral_movement", "remote_wmi_execution"],
            confidence: 0.85,
            mitreTactics: ["Lateral Movement", "Execution"],
            mitreTechniques: ["T1047 - Windows Management Instrumentation"],
            reasoning: [`WMI remote execution: ${e.actor.process}`],
          }));
        }
      }
      if (e.source === "auth" && meta(e, "auth_method") === "NTLM" && meta(e, "anomaly") === "hash_authentication") {
        out.push(emit(this, [e], {
          ruleId: "pass_the_hash",
          signals: ["pass_the_hash", "ntlm_relay"],
          confidence: 0.9,
          mitreTactics: ["Lateral Movement", "Credential Access"],
          mitreTechniques: ["T1550.002 - Pass the Hash"],
          reasoning: [`NTLM hash authentication for ${e.actor.user} from ${e.network.sourceIp}`],
        }));
      }
    }
    return out;
  },
};

export const dataExfiltrationDetector: Detector = {
  name: "DataExfiltrationDetector",
  detectionSource: "DATA_EXFILTRATION",
  description: "Large transfers, cloud uploads, DNS tunneling, and scheduled exfil scripts.",
  techniques: ["T1048", "T1567", "T1048.003", "T1020"],
  run(events) {
    const out: Detection[] = [];
    const policy = SecurityPolicy.exfiltration;

    for (const e of events) {
      const bytes = Number(meta(e, "bytes_transferred") ?? meta(e, "bytes_sent") ?? 0);
      if (e.source === "network" && bytes > policy.networkBytesThreshold) {
        out.push(emit(this, [e], {
          ruleId: "large_transfer",
          signals: ["large_data_transfer", "potential_exfiltration"],
          confidence: 0.7,
          mitreTactics: ["Exfiltration"],
          mitreTechniques: ["T1048 - Exfiltration Over Alternative Protocol"],
          reasoning: [`${(bytes / 1024 / 1024).toFixed(1)} MB sent from ${e.network.sourceIp} to ${e.network.destIp}`, `Protocol: ${meta(e, "type") ?? "unknown"}`],
        }));
      }

      const action = String(meta(e, "action") ?? "");
      const size = Number(meta(e, "size") ?? 0);
      if (e.source === "cloud" && ["S3_OBJECT_UPLOAD", "BLOB_UPLOAD", "DRIVE_UPLOAD"].includes(action) && size > policy.cloudUploadBytesThreshold) {
        out.push(emit(this, [e], {
          ruleId: "cloud_upload",
          signals: ["cloud_exfiltration", "unauthorized_upload"],
          confidence: 0.75,
          mitreTactics: ["Exfiltration"],
          mitreTechniques: ["T1567 - Exfiltration Over Web Service"],
          reasoning: [`${action} of ${(size / 1024 / 1024).toFixed(1)} MB to ${meta(e, "resource")}`, `User: ${e.actor.user}`],
        }));
      }

      const parent = String(meta(e, "parentProcess") ?? "").toLowerCase();
      const c = cmd(e);
      if (e.source === "endpoint" && (parent.includes("taskeng") || parent.includes("cron")) && ["exfil", "upload", "ftp"].some((k) => c.includes(k))) {
        out.push(emit(this, [e], {
          ruleId: "scheduled_exfil",
          signals: ["automated_exfiltration", "scheduled_upload"],
          confidence: 0.85,
          mitreTactics: ["Exfiltration"],
          mitreTechniques: ["T1020 - Automated Exfiltration"],
          reasoning: [`Scheduled exfiltration script: ${e.actor.process} (parent ${meta(e, "parentProcess")})`],
        }));
      }
    }

    const dns = events.filter((e) => e.source === "network" && meta(e, "type") === "DNS");
    for (const [ip, list] of groupBy(dns, (e) => e.network.sourceIp)) {
      const long = list.filter((e) => String(meta(e, "query") ?? "").length > policy.longDnsQueryLength);
      if (long.length >= policy.longDnsQueryCount) {
        out.push(emit(this, long.slice(0, 10), {
          ruleId: "dns_tunneling",
          signals: ["dns_tunneling", "covert_channel"],
          confidence: 0.8,
          mitreTactics: ["Exfiltration", "Command and Control"],
          mitreTechniques: ["T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol"],
          reasoning: [`${long.length} unusually long DNS queries from ${ip}`],
        }));
      }
    }
    return out;
  },
};

export const persistenceDetector: Detector = {
  name: "PersistenceDetector",
  detectionSource: "PERSISTENCE",
  description: "Registry run keys, scheduled tasks/cron, and new services.",
  techniques: ["T1547", "T1053", "T1543"],
  run(events) {
    const out: Detection[] = [];
    for (const e of events) {
      if (e.source !== "endpoint") continue;
      const c = cmd(e);
      if (c.includes("reg add") && c.includes("\\currentversion\\run")) {
        out.push(emit(this, [e], {
          ruleId: "registry_run_key",
          signals: ["registry_persistence", "autostart_execution"],
          confidence: 0.9,
          mitreTactics: ["Persistence"],
          mitreTechniques: ["T1547 - Boot or Logon Autostart Execution"],
          reasoning: [`Registry run key modification: ${e.actor.process}`],
        }));
      }
      // signal-fusion matched the bare substring "at ", which fires on "cat ",
      // "format " etc. Require the at.exe/at command shape instead.
      if (c.includes("schtasks /create") || /(?:^|[\s\\/])at(?:\.exe)?\s+\d{1,2}:\d{2}/.test(c) || c.includes("crontab")) {
        out.push(emit(this, [e], {
          ruleId: "scheduled_task",
          signals: ["scheduled_task_persistence"],
          confidence: 0.85,
          mitreTactics: ["Persistence", "Execution"],
          mitreTechniques: ["T1053 - Scheduled Task/Job"],
          reasoning: [`Scheduled task creation: ${e.actor.process}`],
        }));
      }
      if (c.includes("sc create") || c.includes("new-service")) {
        out.push(emit(this, [e], {
          ruleId: "service_creation",
          signals: ["service_persistence"],
          confidence: 0.9,
          mitreTactics: ["Persistence"],
          mitreTechniques: ["T1543 - Create or Modify System Process"],
          reasoning: [`Service creation detected: ${e.actor.process}`],
        }));
      }
    }
    return out;
  },
};

export const defenseEvasionDetector: Detector = {
  name: "DefenseEvasionDetector",
  detectionSource: "DEFENSE_EVASION",
  description: "Event-log clearing, disabling Defender, and encoded/obfuscated commands.",
  techniques: ["T1070.001", "T1562", "T1027"],
  run(events) {
    const out: Detection[] = [];
    for (const e of events) {
      if (e.source !== "endpoint") continue;
      const c = cmd(e);
      if (/wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b/.test(c) || c.includes("clear-eventlog")) {
        out.push(emit(this, [e], {
          ruleId: "clear_event_logs",
          signals: ["log_clearing", "anti_forensics"],
          confidence: 0.95,
          mitreTactics: ["Defense Evasion"],
          mitreTechniques: ["T1070.001 - Clear Windows Event Logs"],
          reasoning: [`Event log clearing: ${e.actor.process}`],
        }));
      }
      if (c.includes("set-mppreference") && c.includes("disablerealtimemonitoring")) {
        out.push(emit(this, [e], {
          ruleId: "disable_defender",
          signals: ["disable_av", "impair_defenses"],
          confidence: 0.95,
          mitreTactics: ["Defense Evasion"],
          mitreTechniques: ["T1562 - Impair Defenses"],
          reasoning: [`Antivirus disabled: ${e.actor.process}`],
        }));
      }
      if (/\s-e(?:nc|ncodedcommand)?\s+[a-z0-9+/=]{8,}/i.test(c) || c.includes("base64")) {
        out.push(emit(this, [e], {
          ruleId: "encoded_command",
          signals: ["obfuscation", "encoded_command"],
          confidence: 0.7,
          mitreTactics: ["Defense Evasion"],
          mitreTechniques: ["T1027 - Obfuscated Files or Information"],
          reasoning: [`Obfuscated command: ${e.actor.process}`],
        }));
      }
    }
    return out;
  },
};

export const impactDetector: Detector = {
  name: "ImpactDetector",
  detectionSource: "IMPACT",
  description: "Ransomware-style mass encryption, mass deletion, and service stops.",
  techniques: ["T1486", "T1485", "T1489"],
  run(events) {
    const out: Detection[] = [];
    for (const e of events) {
      if (e.source !== "endpoint") continue;
      const c = cmd(e);
      const filesModified = Number(meta(e, "files_modified") ?? 0);
      if (c.includes("ransomware") || /\bencrypt/.test(c) || filesModified > 1000) {
        out.push(emit(this, [e], {
          ruleId: "mass_encryption",
          signals: ["ransomware", "mass_encryption"],
          confidence: 0.95,
          mitreTactics: ["Impact"],
          mitreTechniques: ["T1486 - Data Encrypted for Impact"],
          reasoning: ["Potential ransomware activity", filesModified ? `${filesModified} files modified` : `Process: ${e.actor.process}`],
        }));
      }
      if (c.includes("del /f /s /q") || c.includes("rm -rf")) {
        out.push(emit(this, [e], {
          ruleId: "mass_deletion",
          signals: ["data_destruction", "mass_deletion"],
          confidence: 0.85,
          mitreTactics: ["Impact"],
          mitreTechniques: ["T1485 - Data Destruction"],
          reasoning: [`Mass file deletion: ${e.actor.process}`],
        }));
      }
      if (c.includes("net stop") || c.includes("sc stop")) {
        out.push(emit(this, [e], {
          ruleId: "service_stop",
          signals: ["service_disruption"],
          confidence: 0.75,
          mitreTactics: ["Impact"],
          mitreTechniques: ["T1489 - Service Stop"],
          reasoning: [`Service stopped: ${e.actor.process}`],
        }));
      }
    }
    return out;
  },
};
