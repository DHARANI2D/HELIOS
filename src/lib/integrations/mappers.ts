import type { CaseSeverity } from "@prisma/client";

import type { IngestFormat } from "@/lib/integrations/catalog";
import type { TelemetrySource } from "@/lib/siem/types";

// Vendor payload → HELIOS. A pushed record is either a vendor *alert* (the
// tool already decided something is bad: filed as a case directly) or raw
// *telemetry* (fed to HELIOS's own detectors). Field paths follow each
// vendor's documented export format; anything unrecognized falls through to
// the generic mapper, so a new tool works on day one with plain JSON.

type Raw = Record<string, unknown>;

export interface VendorAlert {
  externalId?: string;
  title: string;
  severity: CaseSeverity;
  description?: string;
  host?: string;
  user?: string;
  ips: string[];
  hashes: string[];
  process?: string;
  commandLine?: string;
  techniques: string[];
  timestamp: Date;
  raw: Raw;
}

export type Mapped = { kind: "alert"; alert: VendorAlert } | { kind: "telemetry"; source: TelemetrySource; data: Raw };

export interface InventoryRecord {
  hostname: string;
  os?: string;
  ipAddress?: string;
  owner?: string;
  criticality?: string;
  controls?: Record<string, string>;
}

function get(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const key of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Raw)[key];
  }
  return cur;
}

function str(...values: unknown[]): string | undefined {
  for (const v of values) {
    if (typeof v === "string" && v.trim()) return v.trim();
    if (typeof v === "number" && Number.isFinite(v)) return String(v);
  }
  return undefined;
}

function date(...values: unknown[]): Date {
  for (const v of values) {
    if (typeof v === "string" || typeof v === "number") {
      const d = new Date(typeof v === "number" && v < 1e12 ? v * 1000 : v);
      if (!Number.isNaN(d.getTime())) return d;
    }
  }
  return new Date();
}

const TECHNIQUE_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
function techniquesIn(...values: unknown[]): string[] {
  const out = new Set<string>();
  for (const v of values.flat(2)) {
    if (typeof v === "string") for (const m of v.match(TECHNIQUE_RE) ?? []) out.add(m);
  }
  return [...out];
}

const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
function ips(...values: unknown[]): string[] {
  return [...new Set(values.flat().filter((v): v is string => typeof v === "string" && IP_RE.test(v.trim())).map((v) => v.trim()))];
}

function hashes(...values: unknown[]): string[] {
  return [...new Set(values.flat().filter((v): v is string => typeof v === "string" && /^[a-f0-9]{64}$/i.test(v.trim())).map((v) => v.trim().toLowerCase()))];
}

export function severityFromText(value: unknown): CaseSeverity | undefined {
  const s = String(value ?? "").toLowerCase();
  if (!s) return undefined;
  if (/crit/.test(s)) return "CRITICAL";
  if (/high|severe|malicious/.test(s)) return "HIGH";
  if (/med|moderate|suspicious/.test(s)) return "MEDIUM";
  if (/low/.test(s)) return "LOW";
  if (/info/.test(s)) return "INFO";
  return undefined;
}

// 0-100 scales (CrowdStrike alerts API), 1-5 (Falcon detection summaries) and
// 0-15 (Wazuh rule levels) all land on the same five buckets.
export function severityFromNumber(value: unknown, scale: 5 | 15 | 100): CaseSeverity | undefined {
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isFinite(n)) return undefined;
  const pct = scale === 100 ? n : scale === 5 ? (n / 5) * 100 : (n / 15) * 100;
  if (pct >= 85) return "CRITICAL";
  if (pct >= 60) return "HIGH";
  if (pct >= 35) return "MEDIUM";
  if (pct >= 10) return "LOW";
  return "INFO";
}

function crowdstrike(r: Raw): Mapped {
  // Streaming API DetectionSummaryEvent, or the Alerts API v2 entity.
  const e = (r.event && typeof r.event === "object" ? r.event : r) as Raw;
  const title = str(e.DetectName, e.display_name, e.name, e.DetectDescription);
  if (!title) return generic(r, "endpoint");
  return {
    kind: "alert",
    alert: {
      externalId: str(e.DetectId, e.composite_id, e.id),
      title: `CrowdStrike: ${title}`,
      severity: severityFromText(e.SeverityName) ?? severityFromNumber(e.Severity, 5) ?? severityFromNumber(e.severity, 100) ?? "MEDIUM",
      description: str(e.DetectDescription, e.description),
      host: str(e.ComputerName, get(e, "device.hostname")),
      user: str(e.UserName, e.user_name),
      ips: ips(e.LocalIP, get(e, "device.local_ip"), get(e, "device.external_ip")),
      hashes: hashes(e.SHA256String, e.sha256),
      process: str(e.FileName, e.filename),
      commandLine: str(e.CommandLine, e.cmdline),
      techniques: techniquesIn(e.TechniqueId, e.technique_id, e.Technique, e.technique),
      timestamp: date(get(r, "metadata.eventCreationTime"), e.timestamp, e.created_timestamp),
      raw: r,
    },
  };
}

function defender(r: Raw): Mapped {
  // Microsoft Graph security alert (v2).
  const title = str(r.title, r.alertDisplayName);
  if (!title) return generic(r, "endpoint");
  const evidence = Array.isArray(r.evidence) ? (r.evidence as Raw[]) : [];
  const host = evidence.map((ev) => str(ev.deviceDnsName, ev.hostName)).find(Boolean);
  const user = evidence.map((ev) => str(get(ev, "userAccount.accountName"), get(ev, "userAccount.userPrincipalName"))).find(Boolean);
  return {
    kind: "alert",
    alert: {
      externalId: str(r.id, r.providerAlertId),
      title: `Defender: ${title}`,
      severity: severityFromText(r.severity) ?? "MEDIUM",
      description: str(r.description),
      host,
      user,
      ips: ips(...evidence.map((ev) => ev.ipAddress)),
      hashes: hashes(...evidence.map((ev) => get(ev, "fileDetails.sha256"))),
      process: evidence.map((ev) => str(get(ev, "imageFile.fileName"))).find(Boolean),
      commandLine: evidence.map((ev) => str(ev.processCommandLine)).find(Boolean),
      techniques: techniquesIn(r.mitreTechniques),
      timestamp: date(r.createdDateTime, r.firstActivityDateTime),
      raw: r,
    },
  };
}

function sentinelone(r: Raw): Mapped {
  const info = (r.threatInfo ?? {}) as Raw;
  const title = str(info.threatName, info.classification);
  if (!title) return generic(r, "endpoint");
  return {
    kind: "alert",
    alert: {
      externalId: str(info.threatId, r.id),
      title: `SentinelOne: ${title}`,
      severity: severityFromText(info.confidenceLevel) ?? "HIGH",
      description: str(info.classification, info.mitigationStatus),
      host: str(get(r, "agentRealtimeInfo.agentComputerName"), get(r, "agentDetectionInfo.agentComputerName")),
      user: str(info.processUser, get(r, "agentDetectionInfo.agentLastLoggedInUserName")),
      ips: ips(get(r, "agentDetectionInfo.agentIpV4")),
      hashes: hashes(info.sha256),
      process: str(info.originatorProcess, info.fileDisplayName),
      commandLine: str(info.commandLine),
      techniques: techniquesIn(JSON.stringify(r.indicators ?? [])),
      timestamp: date(info.createdAt, info.identifiedAt),
      raw: r,
    },
  };
}

function wazuh(r: Raw): Mapped {
  const description = str(get(r, "rule.description"));
  if (!description) return generic(r, "endpoint");
  const level = Number(get(r, "rule.level") ?? 0);
  const eventdata = (get(r, "data.win.eventdata") ?? {}) as Raw;
  const alert: VendorAlert = {
    externalId: str(r.id),
    title: `Wazuh: ${description}`,
    severity: severityFromNumber(level, 15) ?? "LOW",
    host: str(get(r, "agent.name")),
    user: str(get(r, "data.srcuser"), get(r, "data.dstuser"), eventdata.user, eventdata.targetUserName),
    ips: ips(get(r, "data.srcip"), get(r, "data.dstip"), get(r, "agent.ip")),
    hashes: hashes(get(r, "syscheck.sha256_after"), eventdata.hashes),
    process: str(eventdata.image),
    commandLine: str(eventdata.commandLine),
    techniques: techniquesIn(get(r, "rule.mitre.id")),
    timestamp: date(r.timestamp),
    raw: r,
  };
  // Low-level Wazuh rules are informational noise; keep them as telemetry.
  if (level < 7) {
    return { kind: "telemetry", source: "endpoint", data: { hostname: alert.host, user: alert.user, process: alert.commandLine ?? alert.process, source_ip: alert.ips[0], event_type: description, timestamp: alert.timestamp.toISOString() } };
  }
  return { kind: "alert", alert };
}

function entra(r: Raw): Mapped {
  if (r.riskEventType || r.riskLevel) {
    const level = severityFromText(r.riskLevel) ?? "MEDIUM";
    return {
      kind: "alert",
      alert: {
        externalId: str(r.id),
        title: `Entra ID risk detection: ${str(r.riskEventType) ?? "risky sign-in"}`,
        severity: level,
        user: str(r.userPrincipalName),
        ips: ips(r.ipAddress),
        hashes: [],
        techniques: ["T1078"],
        timestamp: date(r.detectedDateTime, r.activityDateTime),
        raw: r,
      },
    };
  }
  const failed = Number(get(r, "status.errorCode") ?? 0) !== 0;
  return {
    kind: "telemetry",
    source: "auth",
    data: {
      user: str(r.userPrincipalName),
      source_ip: str(r.ipAddress),
      result: failed ? "FAILED" : "SUCCESS",
      geo: str(get(r, "location.countryOrRegion")),
      hostname: str(get(r, "deviceDetail.displayName")),
      timestamp: date(r.createdDateTime).toISOString(),
    },
  };
}

function okta(r: Raw): Mapped {
  const outcome = String(get(r, "outcome.result") ?? "").toUpperCase();
  return {
    kind: "telemetry",
    source: "auth",
    data: {
      user: str(get(r, "actor.alternateId"), get(r, "actor.displayName")),
      source_ip: str(get(r, "client.ipAddress")),
      result: outcome === "FAILURE" || outcome === "DENY" ? "FAILED" : "SUCCESS",
      geo: str(get(r, "client.geographicalContext.country")),
      event_type: str(r.eventType),
      timestamp: date(r.published).toISOString(),
    },
  };
}

// Plain JSON from anything: an object with a title/name and a severity is an
// alert; everything else is telemetry for the tool category's source.
function generic(r: Raw, source: TelemetrySource): Mapped {
  const title = str(r.title, r.alert, r.alert_name, r.rule_name, r.name, get(r, "rule.name"));
  const severity = severityFromText(r.severity ?? r.priority ?? r.level) ?? severityFromNumber(r.severity, 100);
  if (title && severity) {
    return {
      kind: "alert",
      alert: {
        externalId: str(r.id, r.alert_id, r.event_id),
        title,
        severity,
        description: str(r.description, r.message),
        host: str(r.host, r.hostname, r.computer_name, r.device),
        user: str(r.user, r.username, r.user_name),
        ips: ips(r.ip, r.src_ip, r.source_ip, r.dest_ip, r.dst_ip),
        hashes: hashes(r.sha256, r.hash, r.file_hash),
        process: str(r.process, r.process_name),
        commandLine: str(r.command_line, r.commandline, r.cmd),
        techniques: techniquesIn(r.technique, r.techniques, r.mitre, r.mitre_technique),
        timestamp: date(r.timestamp, r["@timestamp"], r.time, r.created_at),
        raw: r,
      },
    };
  }
  return { kind: "telemetry", source, data: r };
}

export function mapRecord(format: IngestFormat, record: Raw, defaultSource: TelemetrySource): Mapped {
  switch (format) {
    case "crowdstrike":
      return crowdstrike(record);
    case "defender":
      return defender(record);
    case "sentinelone":
      return sentinelone(record);
    case "wazuh":
      return wazuh(record);
    case "entra":
      return entra(record);
    case "okta":
      return okta(record);
    default:
      return generic(record, defaultSource);
  }
}

// Accepts an array, { events: [...] }, { data: [...] } (Graph/S1 list
// responses), { value: [...] } (Graph), { resources: [...] } (Falcon), a
// single object, or JSON Lines.
export function recordsFrom(body: unknown): Raw[] {
  if (Array.isArray(body)) return body.filter((r): r is Raw => !!r && typeof r === "object" && !Array.isArray(r));
  if (body && typeof body === "object") {
    const b = body as Raw;
    for (const key of ["events", "alerts", "data", "value", "resources", "records"]) {
      if (Array.isArray(b[key])) return recordsFrom(b[key]);
    }
    return [b];
  }
  return [];
}

export function parseBody(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) return [];
  try {
    return JSON.parse(trimmed);
  } catch {
    return trimmed.split("\n").filter((l) => l.trim()).map((line, i) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error(`Line ${i + 1} is not valid JSON`);
      }
    });
  }
}

export function inventoryFrom(body: unknown): InventoryRecord[] {
  if (!body || typeof body !== "object" || Array.isArray(body)) return [];
  const list = (body as Raw).inventory;
  if (!Array.isArray(list)) return [];
  return list
    .filter((r): r is Raw => !!r && typeof r === "object")
    .map((r) => ({
      hostname: str(r.hostname, r.host, r.name) ?? "",
      os: str(r.os, r.platform),
      ipAddress: str(r.ip, r.ipAddress, r.ip_address),
      owner: str(r.owner, r.user),
      criticality: str(r.criticality),
      controls: r.controls && typeof r.controls === "object" ? (r.controls as Record<string, string>) : undefined,
    }))
    .filter((r) => r.hostname);
}
