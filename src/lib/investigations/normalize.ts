import type { EvtxEvent } from "@/lib/investigations/evtx";

// Port of asip's intake/normalizer.py and parsers/{sysmon,crowdstrike,splunk,
// wazuh,google_secops,generic}.py — every vendor format lands in one
// Universal Event Schema (UES). Windows logs arrive as binary .evtx
// (investigations/evtx.ts), exported XML, or JSON (Winlogbeat, Get-WinEvent
// | ConvertTo-Json); spreadsheets as .xlsx (investigations/xlsx.ts) or CSV.

export interface UesEvent {
  timestamp: Date;
  platform: string;
  eventType: string; // process_create | network_connect | file_create | dns_query | registry_set | auth | log_line | ...
  hostName?: string;
  hostIp?: string;
  userName?: string;
  processName?: string;
  processPid?: number;
  parentProcessName?: string;
  parentProcessPid?: number;
  commandLine?: string;
  filePath?: string;
  fileHash?: string;
  dstIp?: string;
  dstPort?: number;
  query?: string;
  raw: Record<string, unknown>;
}

export interface ParseResult {
  platform: string;
  events: UesEvent[];
}

type Rec = Record<string, unknown>;

// --- helpers ---------------------------------------------------------------

function str(...values: unknown[]): string | undefined {
  for (const v of values) {
    if (typeof v === "string" && v.trim()) return v.trim();
    if (typeof v === "number" && Number.isFinite(v)) return String(v);
  }
  return undefined;
}

function int(...values: unknown[]): number | undefined {
  for (const v of values) {
    const n = typeof v === "number" ? v : typeof v === "string" && v.trim() ? Number(v.trim()) : NaN;
    if (Number.isInteger(n)) return n;
  }
  return undefined;
}

function get(rec: unknown, path: string): unknown {
  let cur: unknown = rec;
  for (const key of path.split(".")) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Rec)[key];
  }
  return cur;
}

export function basename(path: string | undefined): string | undefined {
  if (!path) return undefined;
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

function parseTime(value: unknown): Date | undefined {
  if (value == null || value === "") return undefined;
  if (typeof value === "number") {
    // epoch seconds vs milliseconds
    const d = new Date(value < 1e12 ? value * 1000 : value);
    return Number.isNaN(d.getTime()) ? undefined : d;
  }
  const s = String(value).trim();
  if (/^\d{10}(\.\d+)?$/.test(s)) return new Date(Number(s) * 1000);
  if (/^\d{13}$/.test(s)) return new Date(Number(s));
  // "2024-03-10 08:01:23.456" (Sysmon UtcTime) is UTC without a zone marker.
  const isoish = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(s) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(s) ? `${s.replace(" ", "T")}Z` : s;
  const d = new Date(isoish);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

// Windows renders absent values as "-", and PIDs / logon IDs as hex.
function win(...values: unknown[]): string | undefined {
  for (const v of values) {
    const s = str(v);
    if (s && s !== "-") return s;
  }
  return undefined;
}

function winInt(...values: unknown[]): number | undefined {
  for (const v of values) {
    const s = str(v);
    if (!s) continue;
    const n = /^0x[0-9a-f]+$/i.test(s) ? parseInt(s, 16) : Number(s);
    if (Number.isInteger(n)) return n;
  }
  return undefined;
}

function sha256From(hashes: string | undefined): string | undefined {
  if (!hashes) return undefined;
  const m = hashes.match(/SHA256=([a-fA-F0-9]{64})/);
  if (m) return m[1].toLowerCase();
  return /^[a-fA-F0-9]{64}$/.test(hashes.trim()) ? hashes.trim().toLowerCase() : undefined;
}

function clean(event: UesEvent): UesEvent {
  for (const key of Object.keys(event) as Array<keyof UesEvent>) {
    if (event[key] === "" || event[key] === undefined) delete event[key];
  }
  return event;
}

// --- Sysmon ----------------------------------------------------------------

const SYSMON_EVENT_IDS: Record<number, string> = {
  1: "process_create",
  3: "network_connect",
  5: "process_terminate",
  7: "image_load",
  8: "create_remote_thread",
  10: "process_access",
  11: "file_create",
  12: "registry_add_delete",
  13: "registry_set",
  15: "file_create_stream_hash",
  22: "dns_query",
  23: "file_delete",
};

function fromSysmonData(eventId: number, data: Rec, system: { time?: unknown; computer?: string }): UesEvent {
  return clean({
    timestamp: parseTime(data.UtcTime) ?? parseTime(system.time) ?? new Date(),
    platform: "sysmon",
    eventType: SYSMON_EVENT_IDS[eventId] ?? `windows_event_${eventId}`,
    hostName: str(system.computer, data.Computer),
    hostIp: str(data.SourceIp),
    userName: str(data.User, data.user, data.TargetUserName, data.SubjectUserName),
    processName: basename(str(data.Image)) ?? str(data.ProcessName),
    processPid: int(data.ProcessId),
    parentProcessName: basename(str(data.ParentImage)),
    parentProcessPid: int(data.ParentProcessId),
    commandLine: str(data.CommandLine),
    filePath: str(data.TargetFilename, data.TargetObject, eventId === 1 ? undefined : data.Image),
    fileHash: sha256From(str(data.Hashes)),
    dstIp: str(data.DestinationIp),
    dstPort: int(data.DestinationPort),
    query: str(data.QueryName),
    raw: { EventID: eventId, ...data },
  });
}

// --- Windows event logs beyond Sysmon ----------------------------------------

type WindowsFamily = "sysmon" | "security" | "eventlog" | "scm" | "powershell" | "taskscheduler";

function windowsFamily(provider: string | undefined): WindowsFamily | null {
  const p = (provider ?? "").toLowerCase();
  if (p.includes("sysmon")) return "sysmon";
  if (p.includes("security-auditing")) return "security";
  if (p === "microsoft-windows-eventlog" || p === "eventlog") return "eventlog";
  if (p === "service control manager") return "scm";
  if (p.includes("powershell")) return "powershell";
  if (p.includes("taskscheduler")) return "taskscheduler";
  return null;
}

const WINDOWS_EVENT_TYPES: Record<Exclude<WindowsFamily, "sysmon">, Record<number, string>> = {
  security: {
    4624: "auth",
    4625: "auth_failure",
    4648: "auth_explicit",
    4771: "auth_failure",
    4776: "credential_validation",
    4634: "logoff",
    4672: "privileged_logon",
    4688: "process_create",
    4689: "process_terminate",
    4697: "service_install",
    4698: "scheduled_task_create",
    4702: "scheduled_task_update",
    4720: "account_created",
    4722: "account_enabled",
    4724: "password_reset",
    4726: "account_deleted",
    4728: "group_member_added",
    4732: "group_member_added",
    4756: "group_member_added",
    4740: "account_locked",
    4768: "kerberos_tgt",
    4769: "kerberos_service_ticket",
    5140: "share_access",
    5145: "share_access",
    1102: "log_cleared",
  },
  eventlog: { 1102: "log_cleared", 104: "log_cleared" },
  scm: { 7045: "service_install", 7036: "service_state", 7040: "service_config" },
  powershell: { 4104: "script_block", 4103: "pipeline_execution" },
  taskscheduler: { 106: "scheduled_task_create", 140: "scheduled_task_update", 141: "scheduled_task_delete", 200: "scheduled_task_run" },
};

function taskCommand(xml: string | undefined) {
  if (!xml) return undefined;
  const cmd = xml.match(/<Command>([^<]*)<\/Command>/i)?.[1];
  const args = xml.match(/<Arguments>([^<]*)<\/Arguments>/i)?.[1];
  return cmd ? decodeXml([cmd, args].filter(Boolean).join(" ")) : undefined;
}

export interface WindowsEventInput {
  provider?: string;
  channel?: string;
  eventId: number;
  data: Rec;
  time?: unknown;
  computer?: string;
}

// Any Windows event: Sysmon keeps its own mapping; Security auditing,
// Eventlog, Service Control Manager, PowerShell and Task Scheduler events get
// UES types the forensic rules understand; anything else is kept as
// windows_event_<id> with its data.
export function fromWindowsEvent(input: WindowsEventInput): UesEvent {
  const { eventId, data } = input;
  const family = windowsFamily(input.provider);
  if (family === "sysmon" || (!family && SYSMON_EVENT_IDS[eventId] && (data.UtcTime || data.Image))) {
    return fromSysmonData(eventId, data, { time: input.time, computer: input.computer });
  }
  const type = family ? WINDOWS_EVENT_TYPES[family][eventId] : undefined;
  const processCreate = type === "process_create";
  const scriptBlock = type === "script_block";
  return clean({
    timestamp: parseTime(input.time) ?? new Date(),
    platform: family === "security" ? "windows_security" : family ? `windows_${family}` : "windows",
    eventType: type ?? `windows_event_${eventId}`,
    hostName: str(input.computer),
    hostIp: win(data.IpAddress, data.ClientAddress)?.replace(/^::ffff:/, ""),
    // For a group change the user is the member added; the group stays in raw.
    userName: type === "group_member_added" ? win(data.MemberName, data.MemberSid) : win(data.TargetUserName, data.UserId, data.SubjectUserName, data.AccountName),
    processName: scriptBlock ? "powershell.exe" : basename(win(processCreate ? data.NewProcessName : data.ProcessName)),
    processPid: processCreate ? winInt(data.NewProcessId) : winInt(data.ProcessId),
    parentProcessName: processCreate ? basename(win(data.ParentProcessName)) : undefined,
    parentProcessPid: processCreate ? winInt(data.ProcessId) : undefined,
    commandLine: win(processCreate ? data.CommandLine : undefined, scriptBlock ? str(data.ScriptBlockText)?.slice(0, 8000) : undefined, data.ImagePath, data.ServiceFileName, taskCommand(str(data.TaskContent))),
    filePath: win(data.ImagePath, data.ServiceFileName, data.Path, data.TaskName),
    raw: { EventID: eventId, Provider: input.provider, Channel: input.channel, ...data },
  });
}

export function parseEvtxEvents(events: EvtxEvent[]): ParseResult {
  const out = events.filter((e) => e.eventId !== undefined).map((e) =>
    fromWindowsEvent({ provider: e.provider, channel: e.channel, eventId: e.eventId!, data: { ...e.data }, time: e.timeCreated, computer: e.computer }),
  );
  return { platform: dominantPlatform(out, "windows"), events: out };
}

function dominantPlatform(events: UesEvent[], fallback: string) {
  const counts = new Map<string, number>();
  for (const e of events) counts.set(e.platform, (counts.get(e.platform) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? fallback;
}

function decodeXml(s: string) {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}

export function parseSysmonXml(text: string): UesEvent[] {
  const events: UesEvent[] = [];
  for (const block of text.match(/<Event[\s>][\s\S]*?<\/Event>/g) ?? []) {
    const eventId = int(block.match(/<EventID[^>]*>(\d+)<\/EventID>/)?.[1]);
    if (eventId === undefined) continue;
    const time = block.match(/<TimeCreated[^>]*SystemTime=["']([^"']+)["']/)?.[1];
    const computer = block.match(/<Computer>([^<]*)<\/Computer>/)?.[1];
    const provider = block.match(/<Provider[^>]*\sName=["']([^"']+)["']/)?.[1];
    const channel = block.match(/<Channel>([^<]*)<\/Channel>/)?.[1];
    const data: Rec = {};
    for (const m of block.matchAll(/<Data Name=["']([^"']+)["']\s*(?:\/>|>([\s\S]*?)<\/Data>)/g)) {
      data[m[1]] = decodeXml(m[2] ?? "");
    }
    events.push(fromWindowsEvent({ provider, channel, eventId, data, time, computer }));
  }
  return events;
}

function sysmonFromJson(rec: Rec): UesEvent | null {
  const eventId = int(rec.EventID, rec.EventId, rec.EventCode, rec.event_id, rec.Id, get(rec, "winlog.event_id"), get(rec, "event.code"));
  if (eventId === undefined) return null;
  const nested = (get(rec, "winlog.event_data") ?? rec.EventData ?? rec.event_data) as Rec | undefined;
  const data: Rec = { ...rec, ...(nested && typeof nested === "object" ? nested : {}) };
  return fromWindowsEvent({
    provider: str(get(rec, "winlog.provider_name"), rec.ProviderName, rec.SourceName, get(rec, "Provider.Name"), typeof rec.Provider === "string" ? rec.Provider : undefined),
    channel: str(get(rec, "winlog.channel"), rec.LogName, rec.Channel),
    eventId,
    data,
    time: rec.TimeCreated ?? rec["@timestamp"] ?? rec.timestamp ?? rec._time,
    computer: str(rec.Computer, rec.ComputerName, rec.computer_name, rec.MachineName, rec.host, get(rec, "winlog.computer_name"), get(rec, "host.name")),
  });
}

// --- CrowdStrike Falcon ----------------------------------------------------

const CROWDSTRIKE_TYPES: Record<string, string> = {
  ProcessRollup2: "process_create",
  SyntheticProcessRollup2: "process_create",
  NetworkConnectIP4: "network_connect",
  DnsRequest: "dns_query",
  FileOpenInfo: "file_open",
  NewExecutableWritten: "file_create",
  RegGenericValueUpdate: "registry_set",
  UserLogon: "auth",
  DetectionSummaryEvent: "alert",
};

function crowdstrikeFromJson(rec: Rec): UesEvent {
  const raw = str(rec.event_simpleName, rec.EventType) ?? "unknown";
  return clean({
    timestamp: parseTime(rec.ProcessStartTime) ?? parseTime(rec.timestamp) ?? parseTime(rec.ContextTimeStamp) ?? parseTime(rec.UTCTimestamp) ?? new Date(),
    platform: "crowdstrike",
    eventType: CROWDSTRIKE_TYPES[raw] ?? raw.toLowerCase(),
    hostName: str(rec.ComputerName, rec.aid),
    hostIp: str(rec.LocalAddressIP4, rec.LocalIP),
    userName: str(rec.UserName, rec.UserSid),
    processName: basename(str(rec.FileName, rec.ImageFileName)),
    processPid: int(rec.TargetProcessId, rec.ProcessId),
    parentProcessName: basename(str(rec.ParentBaseFileName, rec.ParentImageFileName)),
    parentProcessPid: int(rec.ParentProcessId),
    commandLine: str(rec.CommandLine),
    filePath: str(rec.FilePath, rec.TargetFilename, rec.TargetFileName),
    fileHash: str(rec.SHA256HashData, rec.sha256)?.toLowerCase(),
    dstIp: str(rec.RemoteAddressIP4, rec.RemoteIP),
    dstPort: int(rec.RemotePort),
    query: str(rec.DomainName),
    raw: rec,
  });
}

// --- Wazuh -----------------------------------------------------------------

function wazuhFromJson(rec: Rec): UesEvent {
  const data = (rec.data ?? {}) as Rec;
  const syscheck = (rec.syscheck ?? {}) as Rec;
  const groups = (get(rec, "rule.groups") as string[] | undefined) ?? [];
  const eventType = syscheck.path
    ? "file_create"
    : groups.includes("authentication_failed") || groups.includes("authentication_success")
      ? "auth"
      : str(get(rec, "data.win.system.eventID")) === "1"
        ? "process_create"
        : "alert";
  return clean({
    timestamp: parseTime(rec.timestamp) ?? parseTime(rec["@timestamp"]) ?? new Date(),
    platform: "wazuh",
    eventType,
    hostName: str(get(rec, "agent.name"), rec.hostname),
    hostIp: str(get(rec, "agent.ip")),
    userName: str(data.dstuser, data.srcuser, get(rec, "data.win.eventdata.user")),
    processName: basename(str(get(data, "process.name"), data.program_name, get(rec, "data.win.eventdata.image"))),
    processPid: int(get(data, "process.pid"), get(rec, "data.win.eventdata.processId")),
    parentProcessName: basename(str(get(rec, "data.win.eventdata.parentImage"))),
    commandLine: str(data.command, get(rec, "data.win.eventdata.commandLine")),
    filePath: str(syscheck.path),
    fileHash: str(syscheck.sha256_after),
    dstIp: str(data.dstip, data.srcip),
    dstPort: int(data.dstport),
    raw: { ...rec, ruleId: get(rec, "rule.id"), ruleDescription: get(rec, "rule.description"), ruleLevel: get(rec, "rule.level") },
  });
}

// --- Google SecOps (Chronicle UDM) -----------------------------------------

const UDM_TYPES: Record<string, string> = {
  PROCESS_LAUNCH: "process_create",
  NETWORK_CONNECTION: "network_connect",
  NETWORK_DNS: "dns_query",
  FILE_CREATION: "file_create",
  REGISTRY_MODIFICATION: "registry_set",
  USER_LOGIN: "auth",
};

function udmFromJson(rec: Rec): UesEvent {
  const type = str(get(rec, "metadata.event_type")) ?? "GENERIC_EVENT";
  return clean({
    timestamp: parseTime(get(rec, "metadata.event_timestamp")) ?? parseTime(rec.timestamp) ?? new Date(),
    platform: "google_secops",
    eventType: UDM_TYPES[type] ?? type.toLowerCase(),
    hostName: str(get(rec, "principal.hostname"), get(rec, "principal.asset.hostname")),
    hostIp: str((get(rec, "principal.ip") as unknown[] | undefined)?.[0], get(rec, "principal.ip")),
    userName: str(get(rec, "principal.user.userid")),
    processName: basename(str(get(rec, "target.process.file.full_path"), get(rec, "principal.process.file.full_path"))),
    processPid: int(get(rec, "target.process.pid"), get(rec, "principal.process.pid")),
    parentProcessName: basename(str(get(rec, "principal.process.file.full_path"))),
    parentProcessPid: int(get(rec, "principal.process.pid")),
    commandLine: str(get(rec, "target.process.command_line"), get(rec, "principal.process.command_line")),
    filePath: str(get(rec, "target.file.full_path")),
    fileHash: str(get(rec, "target.file.sha256"), get(rec, "target.process.file.sha256")),
    dstIp: str((get(rec, "target.ip") as unknown[] | undefined)?.[0], get(rec, "target.ip")),
    dstPort: int(get(rec, "target.port")),
    query: str(get(rec, "network.dns.questions.0.name")),
    raw: rec,
  });
}

// --- Splunk / generic tables & JSON ----------------------------------------

// asip's SplunkParser column aliases, matched case-insensitively.
const COLUMN_ALIASES: Record<string, string[]> = {
  timestamp: ["_time", "timestamp", "time", "@timestamp", "date", "datetime", "utctime"],
  hostName: ["host", "hostname", "computer", "computername", "dvc", "device"],
  hostIp: ["host_ip", "src_ip", "src", "sourceip", "ip"],
  userName: ["user", "username", "user_name", "src_user", "uid", "suser", "duser"],
  processName: ["process", "process_name", "image", "filename", "app", "exe"],
  processPid: ["pid", "process_id", "processid"],
  parentProcessName: ["parent_process", "parent_process_name", "parentimage", "parentbasefilename"],
  parentProcessPid: ["parent_pid", "parent_process_id", "parentprocessid"],
  commandLine: ["commandline", "command_line", "cmdline", "command", "process_exec", "arguments"],
  filePath: ["file_path", "filepath", "targetfilename", "file_name", "path", "object"],
  fileHash: ["sha256", "file_hash", "hash", "sha256hashdata", "hash_sha256"],
  dstIp: ["dst_ip", "dest_ip", "destination_ip", "dst", "destinationip", "remoteaddressip4", "remoteip"],
  dstPort: ["dst_port", "dest_port", "destination_port", "destinationport", "remoteport", "port"],
  query: ["query", "queryname", "domain"],
  eventType: ["event_type", "eventtype", "type", "action", "signature", "category"],
};

function pick(rec: Rec, field: string): unknown {
  const lowered = new Map(Object.keys(rec).map((k) => [k.toLowerCase(), k]));
  for (const alias of COLUMN_ALIASES[field]) {
    const key = lowered.get(alias);
    if (key !== undefined && rec[key] !== "" && rec[key] != null) return rec[key];
  }
  return undefined;
}

function inferEventType(e: Omit<UesEvent, "eventType">, declared?: string): string {
  if (declared) return declared.toLowerCase().replace(/\s+/g, "_");
  if (e.dstIp) return "network_connect";
  if (e.query) return "dns_query";
  if (e.processName || e.commandLine) return "process_create";
  if (e.filePath) return "file_create";
  return "log";
}

function genericFromRecord(rec: Rec, platform: string): UesEvent {
  const base = {
    timestamp: parseTime(pick(rec, "timestamp")) ?? new Date(),
    platform,
    hostName: str(pick(rec, "hostName")),
    hostIp: str(pick(rec, "hostIp")),
    userName: str(pick(rec, "userName")),
    processName: basename(str(pick(rec, "processName"))),
    processPid: int(pick(rec, "processPid")),
    parentProcessName: basename(str(pick(rec, "parentProcessName"))),
    parentProcessPid: int(pick(rec, "parentProcessPid")),
    commandLine: str(pick(rec, "commandLine")),
    filePath: str(pick(rec, "filePath")),
    fileHash: str(pick(rec, "fileHash"))?.toLowerCase(),
    dstIp: str(pick(rec, "dstIp")),
    dstPort: int(pick(rec, "dstPort")),
    query: str(pick(rec, "query")),
    raw: rec,
  };
  return clean({ ...base, eventType: inferEventType(base, str(pick(rec, "eventType"))) });
}

export function parseCsv(text: string): Rec[] {
  const firstLine = text.split(/\r?\n/, 1)[0];
  const delimiter = firstLine.split("\t").length > firstLine.split(",").length ? "\t" : ",";
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      quoted = true;
    } else if (c === delimiter) {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      if (row.some((f) => f !== "")) rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }
  row.push(field);
  if (row.some((f) => f !== "")) rows.push(row);
  if (rows.length < 2) return [];
  const [header, ...body] = rows;
  return body.map((cells) => Object.fromEntries(header.map((h, i) => [h.trim(), cells[i]?.trim() ?? ""])));
}

const TS_IN_LINE = [
  /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/,
  /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/,
];

function rawLine(line: string, filename: string): UesEvent {
  let timestamp: Date | undefined;
  for (const re of TS_IN_LINE) {
    const m = line.match(re)?.[0];
    if (m) {
      timestamp = parseTime(m) ?? parseTime(`${m} ${new Date().getUTCFullYear()}`);
      if (timestamp) break;
    }
  }
  const ips = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [];
  return clean({
    timestamp: timestamp ?? new Date(),
    platform: "generic_text",
    eventType: "log_line",
    hostName: filename || undefined,
    hostIp: ips[0],
    dstIp: ips[1],
    fileHash: line.match(/\b[a-fA-F0-9]{64}\b/)?.[0]?.toLowerCase(),
    raw: { message: line },
  });
}

function recordFormat(rec: Rec): "crowdstrike" | "sysmon" | "wazuh" | "google_secops" | "generic" {
  if ("event_simpleName" in rec || ("EventType" in rec && "aid" in rec)) return "crowdstrike";
  if (get(rec, "rule.level") !== undefined && (rec.agent || rec.decoder)) return "wazuh";
  if (get(rec, "metadata.event_type") !== undefined && (rec.principal || rec.target)) return "google_secops";
  const id = rec.EventID ?? rec.EventId ?? rec.EventCode ?? rec.event_id ?? get(rec, "winlog.event_id");
  if (id !== undefined && (rec.Image || rec.CommandLine || rec.EventData || rec.event_data || get(rec, "winlog.event_data") || rec.DestinationIp || rec.TargetFilename || rec.TargetUserName || rec.ProviderName || get(rec, "winlog.provider_name"))) return "sysmon";
  return "generic";
}

// Rows from a spreadsheet or any other source of flat records.
export function parseRecords(records: Rec[]): ParseResult {
  return fromJsonRecords(records);
}

function fromJsonRecords(records: Rec[]): ParseResult {
  const counts = new Map<string, number>();
  const events: UesEvent[] = [];
  for (const rec of records) {
    if (!rec || typeof rec !== "object" || Array.isArray(rec)) continue;
    const format = recordFormat(rec);
    counts.set(format, (counts.get(format) ?? 0) + 1);
    const event =
      format === "crowdstrike"
        ? crowdstrikeFromJson(rec)
        : format === "wazuh"
          ? wazuhFromJson(rec)
          : format === "google_secops"
            ? udmFromJson(rec)
            : format === "sysmon"
              ? sysmonFromJson(rec)
              : genericFromRecord(rec, "generic");
    if (event) events.push(event);
  }
  const platform = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "generic";
  return { platform, events };
}

function tryJson(text: string): Rec[] | null {
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed as Rec[];
    if (parsed && typeof parsed === "object") {
      // Common wrappers: {"events": [...]}, {"results": [...]}, Splunk {"result": {...}}
      for (const key of ["events", "records", "results", "hits", "data"]) {
        const inner = (parsed as Rec)[key];
        if (Array.isArray(inner)) return inner as Rec[];
      }
      return [parsed as Rec];
    }
  } catch {
    const lines = text.split(/\r?\n/).filter((l) => l.trim());
    const out: Rec[] = [];
    for (const line of lines) {
      try {
        const v = JSON.parse(line);
        if (v && typeof v === "object") out.push((v as Rec).result && typeof (v as Rec).result === "object" ? ((v as Rec).result as Rec) : (v as Rec));
      } catch {
        return out.length ? out : null;
      }
    }
    return out.length ? out : null;
  }
  return null;
}

export function parseTelemetry(text: string, filename = ""): ParseResult {
  const trimmed = text.replace(/^﻿/, "").trim();
  if (!trimmed) return { platform: "empty", events: [] };

  if (/<Event[\s>]/.test(trimmed) && /<EventID/.test(trimmed)) {
    const events = parseSysmonXml(trimmed);
    return { platform: dominantPlatform(events, "sysmon"), events };
  }

  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    const records = tryJson(trimmed);
    if (records) return fromJsonRecords(records);
  }

  const firstLine = trimmed.split(/\r?\n/, 1)[0];
  if ((firstLine.includes(",") || firstLine.includes("\t")) && !TS_IN_LINE.some((re) => re.test(firstLine))) {
    const rows = parseCsv(trimmed);
    if (rows.length && Object.keys(rows[0]).length > 1) {
      return { platform: "splunk_csv", events: rows.map((r) => genericFromRecord(r, "splunk_csv")) };
    }
  }

  return {
    platform: "generic_text",
    events: trimmed.split(/\r?\n/).filter((l) => l.trim()).map((l) => rawLine(l, filename)),
  };
}
