import { ACTIVITY, CLASS, SEVERITY, STATUS, hashesOf, ocsfEvent, type OcsfEvent, type OcsfFields } from "@/lib/ocsf/schema";
import { MappingError, dateOf, isRaw, num, str, type Raw } from "@/lib/ocsf/sources/util";

// Windows events to OCSF, as the HELIOS forwarder (Fluent Bit's winevtlog
// input) sends them: ProviderName, EventID, Level, TimeCreated
// ("YYYY-MM-DD HH:MM:SS +HHMM", local time), EventRecordID, Channel,
// Computer, UserID, Message, and the event data as StringInserts (an array
// in the event template's order) or, with event_data_as_map, EventData (by
// name). Fields are read by name when the map is there, else by position.
//   Security: logons (4624, 4625, 4634, 4647, 4648), process creation (4688),
//     account changes (4720-4726, 4740, 4767), group membership (4728, 4732,
//     4756), scheduled tasks (4698), log cleared (1102);
//   System: service installed (7045);
//   PowerShell/Operational: script blocks (4104);
//   Sysmon/Operational: process (1), network (3), file create (11), DNS (22),
//     read from the rendered Message so Sysmon schema versions don't matter.
// Positions follow each event's published template; check them against a
// lab forwarder's output before relying on a new event id.

const POSITIONS: Record<number, Record<string, number>> = {
  4624: { TargetUserName: 5, TargetDomainName: 6, LogonType: 8, LogonProcessName: 9, AuthenticationPackageName: 10, WorkstationName: 11, ProcessName: 17, IpAddress: 18, IpPort: 19 },
  4625: { TargetUserName: 5, TargetDomainName: 6, Status: 7, FailureReason: 8, SubStatus: 9, LogonType: 10, AuthenticationPackageName: 12, WorkstationName: 13, IpAddress: 19, IpPort: 20 },
  4634: { TargetUserName: 1, TargetDomainName: 2, LogonType: 4 },
  4647: { TargetUserName: 1, TargetDomainName: 2 },
  4648: { SubjectUserName: 1, SubjectDomainName: 2, TargetUserName: 5, TargetDomainName: 6, TargetServerName: 8, ProcessName: 11, IpAddress: 12 },
  4688: { SubjectUserName: 1, SubjectDomainName: 2, NewProcessId: 4, NewProcessName: 5, ProcessId: 7, CommandLine: 8, TargetUserName: 10, ParentProcessName: 13 },
  4698: { SubjectUserName: 1, SubjectDomainName: 2, TaskName: 4 },
  4720: { TargetUserName: 0, TargetDomainName: 1, SubjectUserName: 4 },
  4722: { TargetUserName: 0, TargetDomainName: 1, SubjectUserName: 4 },
  4723: { TargetUserName: 0, TargetDomainName: 1, SubjectUserName: 4 },
  4724: { TargetUserName: 0, TargetDomainName: 1, SubjectUserName: 4 },
  4725: { TargetUserName: 0, TargetDomainName: 1, SubjectUserName: 4 },
  4726: { TargetUserName: 0, TargetDomainName: 1, SubjectUserName: 4 },
  4740: { TargetUserName: 0, TargetDomainName: 1, SubjectUserName: 4 },
  4767: { TargetUserName: 0, TargetDomainName: 1, SubjectUserName: 4 },
  4728: { MemberName: 0, TargetUserName: 2, TargetDomainName: 3, SubjectUserName: 6 },
  4732: { MemberName: 0, TargetUserName: 2, TargetDomainName: 3, SubjectUserName: 6 },
  4756: { MemberName: 0, TargetUserName: 2, TargetDomainName: 3, SubjectUserName: 6 },
  1102: { SubjectUserName: 1, SubjectDomainName: 2 },
  7045: { ServiceName: 0, ImagePath: 1, ServiceType: 2, StartType: 3, AccountName: 4 },
  4104: { ScriptBlockText: 2, Path: 4 },
};

const ACCOUNT: Record<number, number> = {
  4720: ACTIVITY.account.CREATE,
  4722: ACTIVITY.account.ENABLE,
  4723: ACTIVITY.account.PASSWORD_CHANGE,
  4724: ACTIVITY.account.PASSWORD_RESET,
  4725: ACTIVITY.account.DISABLE,
  4726: ACTIVITY.account.DELETE,
  4740: ACTIVITY.account.LOCK,
  4767: ACTIVITY.account.UNLOCK,
  4728: ACTIVITY.account.ATTACH_POLICY,
  4732: ACTIVITY.account.ATTACH_POLICY,
  4756: ACTIVITY.account.ATTACH_POLICY,
};

const LOGON_TYPE: Record<string, string> = { "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive", "11": "CachedInteractive" };

// Event levels: 1 critical, 2 error, 3 warning, 4 information.
const LEVEL: Record<number, number> = { 1: SEVERITY.CRITICAL, 2: SEVERITY.MEDIUM, 3: SEVERITY.LOW };

// "2026-10-26 14:03:12 +0530" → a Date.
export function windowsTime(value: unknown): Date | null {
  const m = typeof value === "string" ? value.match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-])(\d{2})(\d{2})$/) : null;
  if (m) {
    const d = new Date(`${m[1]}T${m[2]}${m[3]}${m[4]}:${m[5]}`);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return dateOf(value);
}

// "Key: value" lines of a rendered message (Sysmon's are one level deep).
export function messageFields(message: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of (message ?? "").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z][A-Za-z ]{0,40}?):\s(.*)$/);
    if (m && !(m[1] in out)) out[m[1].trim()] = m[2].trim();
  }
  return out;
}

const clean = (v: string | undefined) => (v && v !== "-" && v !== "::1" && v !== "127.0.0.1" && v !== "%%" ? v : undefined);
const SYSMON = /sysmon/i;

export function isWindowsEvent(r: Raw) {
  return r.EventID !== undefined && (typeof r.Channel === "string" || typeof r.ProviderName === "string");
}

export function windowsEvent(r: Raw): OcsfEvent {
  const id = num(r.EventID);
  if (id === undefined) throw new MappingError("Windows event has no EventID");
  const time = windowsTime(r.TimeCreated) ?? dateOf(r.timestamp);
  if (!time) throw new MappingError(`Windows event ${id} has no readable TimeCreated`);
  const channel = str(r.Channel) ?? "";
  const computer = str(r.Computer);
  const inserts = Array.isArray(r.StringInserts) ? r.StringInserts : [];
  const map = isRaw(r.EventData) ? r.EventData : null;
  const sysmon = SYSMON.test(channel) || SYSMON.test(String(r.ProviderName ?? ""));
  const msg = sysmon ? messageFields(str(r.Message)) : {};
  const f = (name: string): string | undefined => {
    if (map && name in map) return str(map[name]);
    if (sysmon) return str(msg[name]);
    const pos = POSITIONS[id]?.[name];
    return pos === undefined ? undefined : str(inserts[pos]);
  };
  const user = (name?: string, domain?: string) => (clean(name) ? { name: clean(name), domain: clean(domain) } : undefined);
  const common: OcsfFields = {
    time,
    product: sysmon ? "Sysmon" : "Windows",
    vendor: "Microsoft",
    uid: [computer, channel, str(r.EventRecordID)].every(Boolean) ? `${computer}:${channel}:${str(r.EventRecordID)}` : undefined,
    log_name: channel || undefined,
    activity_name: `${channel || "Windows"} ${id}`,
    severity_id: LEVEL[num(r.Level) ?? 4] ?? SEVERITY.INFORMATIONAL,
    device: { hostname: computer },
    message: str(r.Message)?.slice(0, 500),
    unmapped: { EventID: id, ProviderName: r.ProviderName, Channel: channel, UserID: r.UserID },
  };

  if (sysmon) {
    const proc = () => ({
      name: f("Image")?.split("\\").pop(),
      pid: num(f("ProcessId")),
      cmd_line: f("CommandLine"),
      file: f("Image") ? { path: f("Image"), name: f("Image")!.split("\\").pop(), hashes: hashesOf(f("Hashes")?.match(/SHA256=([A-Fa-f0-9]{64})/)?.[1]) } : undefined,
      parent_process: f("ParentImage") ? { name: f("ParentImage")!.split("\\").pop(), pid: num(f("ParentProcessId")), cmd_line: f("ParentCommandLine"), file: { path: f("ParentImage") } } : undefined,
    });
    const actorUser = user(f("User")?.split("\\").pop(), f("User")?.includes("\\") ? f("User")!.split("\\")[0] : undefined);
    if (id === 1) return ocsfEvent(CLASS.PROCESS, ACTIVITY.process.LAUNCH, { ...common, process: { ...proc(), user: actorUser }, actor: { user: actorUser } });
    if (id === 3) {
      return ocsfEvent(CLASS.NETWORK, ACTIVITY.network.OPEN, {
        ...common,
        actor: { user: actorUser, process: proc() },
        src_endpoint: { ip: clean(f("SourceIp")), port: num(f("SourcePort")), hostname: computer },
        dst_endpoint: { ip: clean(f("DestinationIp")), port: num(f("DestinationPort")), hostname: f("DestinationHostname") },
        connection_info: { protocol_name: f("Protocol") },
      });
    }
    if (id === 11) return ocsfEvent(CLASS.FILE_SYSTEM, ACTIVITY.file.CREATE, { ...common, actor: { user: actorUser, process: proc() }, file: { path: f("TargetFilename"), name: f("TargetFilename")?.split("\\").pop() } });
    if (id === 22) return ocsfEvent(CLASS.DNS, ACTIVITY.dns.QUERY, { ...common, actor: { user: actorUser, process: proc() }, query: f("QueryName") ? { hostname: f("QueryName")! } : undefined, src_endpoint: { hostname: computer }, unmapped: { ...common.unmapped, QueryResults: f("QueryResults") } });
    return ocsfEvent(CLASS.BASE, ACTIVITY.OTHER, common);
  }

  if (id === 4624 || id === 4625 || id === 4648) {
    const failed = id === 4625;
    const logonType = f("LogonType");
    return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGON, {
      ...common,
      severity_id: failed ? SEVERITY.LOW : SEVERITY.INFORMATIONAL,
      status_id: failed ? STATUS.FAILURE : STATUS.SUCCESS,
      status_detail: failed ? (f("FailureReason") ?? f("Status")) : undefined,
      user: user(f("TargetUserName"), f("TargetDomainName")) ?? { name: "unknown" },
      actor: id === 4648 ? { user: user(f("SubjectUserName"), f("SubjectDomainName")) } : undefined,
      src_endpoint: { ip: clean(f("IpAddress")), port: num(f("IpPort")), hostname: clean(f("WorkstationName")) },
      dst_endpoint: { hostname: id === 4648 ? (f("TargetServerName") ?? computer) : computer },
      logon_type: id === 4648 ? "Explicit credentials" : (LOGON_TYPE[logonType ?? ""] ?? logonType),
      auth_protocol: f("AuthenticationPackageName"),
    });
  }
  if (id === 4634 || id === 4647) {
    return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGOFF, { ...common, status_id: STATUS.SUCCESS, user: user(f("TargetUserName"), f("TargetDomainName")) ?? { name: "unknown" }, dst_endpoint: { hostname: computer }, logon_type: LOGON_TYPE[f("LogonType") ?? ""] });
  }
  if (id === 4688) {
    const image = f("NewProcessName");
    return ocsfEvent(CLASS.PROCESS, ACTIVITY.process.LAUNCH, {
      ...common,
      actor: { user: user(f("SubjectUserName"), f("SubjectDomainName")) },
      process: {
        name: image?.split("\\").pop(),
        pid: num(f("NewProcessId")),
        cmd_line: f("CommandLine"),
        file: image ? { path: image, name: image.split("\\").pop() } : undefined,
        parent_process: f("ParentProcessName") ? { name: f("ParentProcessName")!.split("\\").pop(), pid: num(f("ProcessId")), file: { path: f("ParentProcessName") } } : undefined,
        user: user(f("TargetUserName")) ?? user(f("SubjectUserName"), f("SubjectDomainName")),
      },
    });
  }
  if (ACCOUNT[id] !== undefined) {
    const group = id === 4728 || id === 4732 || id === 4756;
    return ocsfEvent(CLASS.ACCOUNT_CHANGE, ACCOUNT[id], {
      ...common,
      severity_id: group && /admin/i.test(f("TargetUserName") ?? "") ? SEVERITY.MEDIUM : SEVERITY.INFORMATIONAL,
      // A group change's subject is the member added; the group is the resource.
      user: group ? { name: f("MemberName")?.match(/CN=([^,]+)/)?.[1] ?? f("MemberName") ?? "unknown" } : (user(f("TargetUserName"), f("TargetDomainName")) ?? { name: "unknown" }),
      actor: { user: user(f("SubjectUserName")) },
      resources: group ? [{ name: f("TargetUserName"), type: "Group" }] : undefined,
    });
  }
  if (id === 1102) return ocsfEvent(CLASS.BASE, ACTIVITY.OTHER, { ...common, activity_name: "LOG_CLEARED", severity_id: SEVERITY.HIGH, actor: { user: user(f("SubjectUserName"), f("SubjectDomainName")) } });
  if (id === 7045) {
    return ocsfEvent(CLASS.BASE, ACTIVITY.OTHER, { ...common, activity_name: "SERVICE_INSTALL", severity_id: SEVERITY.LOW, actor: { user: user(f("AccountName")) }, unmapped: { ...common.unmapped, ServiceName: f("ServiceName"), ImagePath: f("ImagePath"), StartType: f("StartType") } });
  }
  if (id === 4698) return ocsfEvent(CLASS.BASE, ACTIVITY.OTHER, { ...common, activity_name: "SCHEDULED_TASK_CREATE", actor: { user: user(f("SubjectUserName"), f("SubjectDomainName")) }, unmapped: { ...common.unmapped, TaskName: f("TaskName") } });
  if (id === 4104) {
    // The script block is what ran: detectors read it like a command line.
    return ocsfEvent(CLASS.PROCESS, ACTIVITY.OTHER, { ...common, activity_name: "SCRIPT_BLOCK", process: { name: "powershell.exe", cmd_line: f("ScriptBlockText")?.slice(0, 4000) }, unmapped: { ...common.unmapped, Path: f("Path") } });
  }
  return ocsfEvent(CLASS.BASE, ACTIVITY.OTHER, common);
}
