import type { SeverityHint, TelemetrySource } from "@/lib/siem/types";
import { ACTIVITY, CLASS, SEVERITY, STATUS, hashesOf, ocsfEvent, type ClassUid, type OcsfEvent } from "@/lib/ocsf/schema";

// OCSF ⇄ the flat SecurityEvent columns. The columns are an index the
// detectors and queries read; OCSF is the record.
//   columnsFromOcsf — for sources mapped OCSF-first (Windows events, syslog,
//     cloud audit logs, pulled identity logs): the columns are derived.
//   ocsfFromColumns — for events written as columns (the original telemetry
//     adapters, uploaded investigation logs, governance decisions): their
//     OCSF form is derived, so every stored event has one.

export interface EventColumns {
  timestamp: Date;
  source: TelemetrySource;
  platform?: string | null;
  eventType: string;
  userName?: string | null;
  hostName?: string | null;
  service?: string | null;
  processName?: string | null;
  processPid?: number | null;
  parentProcessName?: string | null;
  parentProcessPid?: number | null;
  commandLine?: string | null;
  sourceIp?: string | null;
  destIp?: string | null;
  destPort?: number | null;
  geo?: string | null;
  filePath?: string | null;
  fileHash?: string | null;
  severityHint?: string | null;
  metadata?: Record<string, unknown> | null;
}

const ACCOUNT_EVENT: Record<number, string> = {
  1: "ACCOUNT_CREATE",
  2: "ACCOUNT_ENABLE",
  3: "PASSWORD_CHANGE",
  4: "PASSWORD_RESET",
  5: "ACCOUNT_DISABLE",
  6: "ACCOUNT_DELETE",
  7: "PRIVILEGE_ADD",
  8: "PRIVILEGE_REMOVE",
  9: "ACCOUNT_LOCK",
  10: "MFA_ENABLE",
  11: "MFA_DISABLE",
  12: "ACCOUNT_UNLOCK",
};

const FILE_EVENT: Record<number, string> = { 1: "FILE_CREATE", 2: "FILE_READ", 3: "FILE_MODIFY", 4: "FILE_DELETE", 5: "FILE_RENAME" };

function hint(severityId: number): SeverityHint {
  return severityId >= SEVERITY.HIGH ? "high" : severityId === SEVERITY.MEDIUM ? "medium" : "low";
}

const otherName = (ev: OcsfEvent, fallback: string) => (ev.activity_name ?? fallback).toUpperCase().replace(/[^A-Z0-9]+/g, "_");

export function columnsFromOcsf(ev: OcsfEvent): EventColumns & { classUid: number; sourceEventId?: string } {
  const base = {
    timestamp: new Date(ev.time),
    platform: ev.metadata.product.name,
    classUid: ev.class_uid,
    sourceEventId: ev.metadata.uid,
    severityHint: hint(ev.severity_id),
  };
  // Detectors read a few fields from metadata (url, domain, query, hash,
  // parentProcess, port, protocol, status, …), as the original adapters set them.
  const meta: Record<string, unknown> = { ...(ev.unmapped ?? {}) };
  const ip = (e?: { ip?: string }) => e?.ip;

  switch (ev.class_uid) {
    case CLASS.AUTHENTICATION: {
      const failed = ev.status_id === STATUS.FAILURE;
      // Only a logon that succeeded counts as one: a challenge or an unknown outcome keeps its own name.
      const succeeded = ev.status_id === STATUS.SUCCESS || ev.status_id === undefined;
      const eventType = ev.activity_id === ACTIVITY.auth.LOGON ? (failed ? "LOGIN_FAIL" : succeeded ? "LOGIN_SUCCESS" : otherName(ev, "LOGIN_OTHER")) : ev.activity_id === ACTIVITY.auth.LOGOFF ? "LOGOFF" : otherName(ev, "AUTH");
      Object.assign(meta, { auth_method: ev.auth_protocol, logon_type: ev.logon_type, mfa: ev.is_mfa, reason: ev.status_detail });
      return {
        ...base,
        source: "auth",
        eventType,
        // A failed logon is worth a look on its own, as the original adapter did.
        severityHint: failed && base.severityHint === "low" ? "medium" : base.severityHint,
        userName: ev.user?.name ?? ev.user?.email_addr,
        hostName: ev.dst_endpoint?.hostname ?? ev.device?.hostname ?? ev.src_endpoint?.hostname,
        service: ev.service?.name ?? ev.dst_endpoint?.name,
        sourceIp: ip(ev.src_endpoint),
        geo: ev.src_endpoint?.location?.country,
        metadata: meta,
      };
    }
    case CLASS.ACCOUNT_CHANGE:
      Object.assign(meta, { actor: ev.actor?.user?.name, action: ACCOUNT_EVENT[ev.activity_id] ?? otherName(ev, "ACCOUNT_CHANGE") });
      return {
        ...base,
        source: "auth",
        eventType: ACCOUNT_EVENT[ev.activity_id] ?? otherName(ev, "ACCOUNT_CHANGE"),
        userName: ev.user?.name ?? ev.user?.email_addr,
        hostName: ev.device?.hostname,
        sourceIp: ip(ev.src_endpoint),
        metadata: meta,
      };
    case CLASS.PROCESS: {
      const p = ev.process;
      Object.assign(meta, { parentProcess: p?.parent_process?.file?.path ?? p?.parent_process?.name, hash: p?.file?.hashes?.[0]?.value });
      return {
        ...base,
        source: "endpoint",
        eventType: ev.activity_id === ACTIVITY.process.LAUNCH ? "PROCESS_START" : ev.activity_id === ACTIVITY.process.TERMINATE ? "PROCESS_END" : ev.activity_id === ACTIVITY.process.INJECT ? "PROCESS_INJECT" : ev.activity_id === ACTIVITY.process.OPEN ? "PROCESS_ACCESS" : otherName(ev, "PROCESS"),
        userName: ev.actor?.user?.name ?? p?.user?.name,
        hostName: ev.device?.hostname,
        processName: p?.file?.path ?? p?.name,
        processPid: p?.pid,
        commandLine: p?.cmd_line,
        parentProcessName: p?.parent_process?.file?.path ?? p?.parent_process?.name,
        parentProcessPid: p?.parent_process?.pid,
        fileHash: p?.file?.hashes?.[0]?.value,
        sourceIp: ev.device?.ip,
        metadata: meta,
      };
    }
    case CLASS.FILE_SYSTEM:
      Object.assign(meta, { hash: ev.file?.hashes?.[0]?.value });
      return {
        ...base,
        source: "endpoint",
        eventType: FILE_EVENT[ev.activity_id] ?? otherName(ev, "FILE"),
        userName: ev.actor?.user?.name,
        hostName: ev.device?.hostname,
        processName: ev.actor?.process?.file?.path ?? ev.actor?.process?.name,
        commandLine: ev.actor?.process?.cmd_line,
        filePath: ev.file?.path ?? ev.file?.name,
        fileHash: ev.file?.hashes?.[0]?.value,
        metadata: meta,
      };
    case CLASS.NETWORK: {
      const refused = ev.activity_id === ACTIVITY.network.REFUSE || ev.activity_id === ACTIVITY.network.FAIL || ev.activity_id === ACTIVITY.network.RESET;
      Object.assign(meta, { port: ev.dst_endpoint?.port, protocol: ev.connection_info?.protocol_name, bytes: ev.traffic?.bytes ?? ev.traffic?.bytes_out, action: ev.disposition });
      return {
        ...base,
        source: "network",
        eventType: ev.activity_id === ACTIVITY.network.OPEN ? "CONN_ESTABLISHED" : ev.activity_id === ACTIVITY.network.CLOSE ? "CONN_CLOSED" : refused ? "CONN_DENIED" : ev.activity_id === ACTIVITY.network.TRAFFIC ? "TRAFFIC" : otherName(ev, "NETWORK"),
        userName: ev.actor?.user?.name,
        hostName: ev.src_endpoint?.hostname ?? ev.device?.hostname,
        sourceIp: ip(ev.src_endpoint),
        destIp: ip(ev.dst_endpoint),
        destPort: ev.dst_endpoint?.port,
        geo: ev.dst_endpoint?.location?.country,
        metadata: meta,
      };
    }
    case CLASS.DNS:
      Object.assign(meta, { type: "DNS", query: ev.query?.hostname, domain: ev.query?.hostname });
      return {
        ...base,
        source: "network",
        eventType: "DNS_QUERY",
        hostName: ev.src_endpoint?.hostname ?? ev.device?.hostname,
        sourceIp: ip(ev.src_endpoint),
        destIp: ip(ev.dst_endpoint),
        destPort: ev.dst_endpoint?.port,
        metadata: meta,
      };
    case CLASS.HTTP:
      Object.assign(meta, { type: "HTTP", url: ev.http_request?.url?.url_string, domain: ev.http_request?.url?.hostname, action: ev.disposition });
      return {
        ...base,
        source: "network",
        eventType: "HTTP_REQUEST",
        userName: ev.actor?.user?.name,
        hostName: ev.src_endpoint?.hostname ?? ev.device?.hostname,
        sourceIp: ip(ev.src_endpoint),
        destIp: ip(ev.dst_endpoint),
        destPort: ev.dst_endpoint?.port,
        metadata: meta,
      };
    case CLASS.API: {
      const failed = ev.status_id === STATUS.FAILURE;
      const denied = failed && /denied|unauthori[sz]ed|forbidden|not authori[sz]ed|permission/i.test(`${ev.status ?? ""} ${ev.status_detail ?? ""}`);
      Object.assign(meta, { status: denied ? "DENIED" : failed ? "FAILED" : "SUCCESS", region: ev.cloud?.region, account: ev.cloud?.account?.uid, resource: ev.resources?.[0]?.name });
      return {
        ...base,
        source: "cloud",
        eventType: ev.api?.operation ?? otherName(ev, "API_CALL"),
        severityHint: denied && base.severityHint === "low" ? "medium" : base.severityHint,
        userName: ev.actor?.user?.name ?? ev.actor?.user?.email_addr ?? ev.actor?.user?.uid,
        service: ev.api?.service?.name ?? ev.resources?.[0]?.name,
        sourceIp: ip(ev.src_endpoint),
        metadata: meta,
      };
    }
    default:
      return {
        ...base,
        source: "endpoint",
        eventType: otherName(ev, "EVENT"),
        userName: ev.actor?.user?.name ?? ev.user?.name,
        hostName: ev.device?.hostname ?? ev.src_endpoint?.hostname,
        sourceIp: ip(ev.src_endpoint) ?? ev.device?.ip,
        destIp: ip(ev.dst_endpoint),
        destPort: ev.dst_endpoint?.port,
        metadata: { ...meta, message: ev.message },
      };
  }
}

// ---------------------------------------------------------------- columns → OCSF

const SEVERITY_FROM_HINT: Record<string, number> = { critical: SEVERITY.CRITICAL, high: SEVERITY.HIGH, medium: SEVERITY.MEDIUM, low: SEVERITY.LOW, info: SEVERITY.INFORMATIONAL };

const has = (type: string, ...words: string[]) => words.some((w) => type.includes(w));

function apiActivity(operation: string) {
  const op = operation.toUpperCase();
  if (/(^|_)(CREATE|PUT|ADD|UPLOAD|INSERT|RUN|START|INVITE)/.test(op)) return ACTIVITY.api.CREATE;
  if (/(^|_)(GET|LIST|DESCRIBE|READ|DOWNLOAD|VIEW|SEARCH|EXPORT)/.test(op)) return ACTIVITY.api.READ;
  if (/(^|_)(UPDATE|MODIFY|SET|ATTACH|CHANGE|PATCH|ENABLE|DISABLE|ASSIGN)/.test(op)) return ACTIVITY.api.UPDATE;
  if (/(^|_)(DELETE|REMOVE|DETACH|TERMINATE|DESTROY|PURGE)/.test(op)) return ACTIVITY.api.DELETE;
  return ACTIVITY.OTHER;
}

export function ocsfFromColumns(row: EventColumns, sourceEventId?: string | null): OcsfEvent {
  const type = row.eventType.toLowerCase();
  const meta = row.metadata ?? {};
  const s = (v: unknown) => (typeof v === "string" && v ? v : undefined);
  const common = {
    time: row.timestamp,
    product: row.platform ?? "helios",
    uid: sourceEventId ?? undefined,
    severity_id: SEVERITY_FROM_HINT[(row.severityHint ?? "").toLowerCase()] ?? SEVERITY.INFORMATIONAL,
    activity_name: row.eventType,
    unmapped: meta,
  };
  const user = row.userName ? { name: row.userName } : undefined;
  const device = row.hostName || (row.source !== "network" && row.sourceIp) ? { hostname: row.hostName ?? undefined, ip: row.source !== "network" ? (row.sourceIp ?? undefined) : undefined } : undefined;
  const process = row.processName || row.commandLine
    ? {
        name: row.processName?.split(/[\\/]/).pop(),
        pid: row.processPid ?? undefined,
        cmd_line: row.commandLine ?? undefined,
        file: row.processName ? { path: row.processName, name: row.processName.split(/[\\/]/).pop(), hashes: hashesOf(row.fileHash ?? s(meta.hash)) } : undefined,
        parent_process: row.parentProcessName || s(meta.parentProcess) ? { name: (row.parentProcessName ?? s(meta.parentProcess))!.split(/[\\/]/).pop(), pid: row.parentProcessPid ?? undefined, file: { path: row.parentProcessName ?? s(meta.parentProcess) } } : undefined,
      }
    : undefined;
  const at = (ip?: string | null, port?: number | null, extra: Record<string, unknown> = {}) => (ip || port || Object.keys(extra).length ? { ip: ip ?? undefined, port: port ?? undefined, ...extra } : undefined);

  let classUid: ClassUid = CLASS.BASE;
  let activity: number = ACTIVITY.OTHER;
  const fields: Record<string, unknown> = {};

  if (row.source === "auth" && (has(type, "login", "logon", "auth", "sign") || type === "auth")) {
    classUid = CLASS.AUTHENTICATION;
    activity = has(type, "logoff", "logout") ? ACTIVITY.auth.LOGOFF : ACTIVITY.auth.LOGON;
    const failed = has(type, "fail", "denied");
    Object.assign(fields, {
      status_id: failed ? STATUS.FAILURE : STATUS.SUCCESS,
      user,
      src_endpoint: at(row.sourceIp, null, row.geo ? { location: { country: row.geo } } : {}),
      dst_endpoint: row.hostName ? { hostname: row.hostName } : undefined,
      auth_protocol: s(meta.auth_method),
    });
  } else if (has(type, "account_created", "account_create", "create_user", "user_created")) {
    classUid = CLASS.ACCOUNT_CHANGE;
    activity = ACTIVITY.account.CREATE;
    Object.assign(fields, { user: user ?? (s(meta.target_user) ? { name: s(meta.target_user) } : undefined), device });
  } else if (has(type, "group_member_added", "add_user_to_group", "privilege_add", "role_assign")) {
    classUid = CLASS.ACCOUNT_CHANGE;
    activity = ACTIVITY.account.ATTACH_POLICY;
    Object.assign(fields, { user, device });
  } else if (has(type, "dns") || s(meta.type)?.toUpperCase() === "DNS") {
    classUid = CLASS.DNS;
    activity = ACTIVITY.dns.QUERY;
    const q = s(meta.query) ?? s(meta.domain);
    Object.assign(fields, { query: q ? { hostname: q } : undefined, src_endpoint: at(row.sourceIp, null, row.hostName ? { hostname: row.hostName } : {}), dst_endpoint: at(row.destIp, row.destPort) });
  } else if (row.source === "network" && (s(meta.url) || /^https?$/i.test(s(meta.type) ?? ""))) {
    classUid = CLASS.HTTP;
    activity = ACTIVITY.OTHER;
    Object.assign(fields, {
      http_request: s(meta.url) ? { url: { url_string: s(meta.url) } } : undefined,
      src_endpoint: at(row.sourceIp, null, row.hostName ? { hostname: row.hostName } : {}),
      dst_endpoint: at(row.destIp, row.destPort),
    });
  } else if (row.source === "network" || has(type, "network_connect", "conn_")) {
    classUid = CLASS.NETWORK;
    activity = has(type, "denied", "blocked", "refused", "drop") ? ACTIVITY.network.REFUSE : has(type, "established", "connect", "open") ? ACTIVITY.network.OPEN : has(type, "closed", "close") ? ACTIVITY.network.CLOSE : ACTIVITY.network.TRAFFIC;
    Object.assign(fields, {
      src_endpoint: at(row.sourceIp, null, row.hostName ? { hostname: row.hostName } : {}),
      dst_endpoint: at(row.destIp, row.destPort, row.geo ? { location: { country: row.geo } } : {}),
      connection_info: s(meta.protocol) ?? s(meta.type) ? { protocol_name: s(meta.protocol) ?? s(meta.type) } : undefined,
      traffic: typeof meta.bytes === "number" ? { bytes: meta.bytes } : undefined,
      actor: user ? { user } : undefined,
    });
  } else if (row.source === "cloud") {
    classUid = CLASS.API;
    activity = apiActivity(row.eventType);
    const status = s(meta.status)?.toUpperCase();
    Object.assign(fields, {
      actor: user ? { user } : { user: { name: "unknown" } },
      api: { operation: row.eventType, service: row.service ? { name: row.service } : undefined },
      src_endpoint: { ip: row.sourceIp ?? undefined },
      status_id: status === "DENIED" || status === "FAILED" ? STATUS.FAILURE : STATUS.SUCCESS,
      status: status === "DENIED" ? "Denied" : undefined,
    });
  } else if (has(type, "file_", "file")) {
    classUid = CLASS.FILE_SYSTEM;
    activity = has(type, "create") ? ACTIVITY.file.CREATE : has(type, "delete") ? ACTIVITY.file.DELETE : has(type, "rename") ? ACTIVITY.file.RENAME : has(type, "read") ? ACTIVITY.file.READ : has(type, "modif", "write", "update") ? ACTIVITY.file.UPDATE : ACTIVITY.OTHER;
    Object.assign(fields, { file: { path: row.filePath ?? undefined, name: row.filePath?.split(/[\\/]/).pop(), hashes: hashesOf(row.fileHash ?? undefined) }, actor: { user, process }, device });
  } else if (process || has(type, "process")) {
    classUid = CLASS.PROCESS;
    activity = has(type, "end", "terminate", "exit") ? ACTIVITY.process.TERMINATE : has(type, "access") ? ACTIVITY.process.OPEN : has(type, "inject") ? ACTIVITY.process.INJECT : has(type, "start", "create", "launch") ? ACTIVITY.process.LAUNCH : ACTIVITY.OTHER;
    Object.assign(fields, { process: process ?? { name: "unknown" }, actor: user ? { user } : undefined, device });
  } else {
    Object.assign(fields, { device, actor: user ? { user } : undefined, src_endpoint: at(row.sourceIp, null), dst_endpoint: at(row.destIp, row.destPort) });
  }
  return ocsfEvent(classUid, activity, { ...common, ...fields });
}
