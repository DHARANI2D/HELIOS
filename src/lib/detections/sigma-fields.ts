import type { SigmaEvent } from "@/lib/detections/sigma";

// How Sigma's field names and log sources map onto HELIOS events. A field is
// looked up in the event's columns first (where the name is a known alias),
// then in the OCSF record and the source's own fields, matching the last
// part of each key case-insensitively, so a rule written for Sysmon or
// CloudTrail field names finds the value wherever the mapping put it.
// Pure.

export interface EventRow {
  timestamp: Date;
  source: string;
  platform: string | null;
  eventType: string;
  classUid: number | null;
  userName: string | null;
  hostName: string | null;
  service: string | null;
  processName: string | null;
  processPid: number | null;
  parentProcessName: string | null;
  parentProcessPid: number | null;
  commandLine: string | null;
  sourceIp: string | null;
  destIp: string | null;
  destPort: number | null;
  filePath: string | null;
  fileHash: string | null;
  metadata: unknown;
  ocsf: unknown;
}

type Column = keyof Pick<EventRow, "userName" | "hostName" | "service" | "processName" | "processPid" | "parentProcessName" | "parentProcessPid" | "commandLine" | "sourceIp" | "destIp" | "destPort" | "filePath" | "fileHash" | "eventType">;

// Sigma taxonomy names (Windows/Sysmon, network, web, cloud) → columns.
const ALIASES: Record<string, Column[]> = {
  image: ["processName"],
  newprocessname: ["processName"],
  processname: ["processName"],
  commandline: ["commandLine"],
  processcommandline: ["commandLine"],
  parentimage: ["parentProcessName"],
  parentprocessname: ["parentProcessName"],
  processid: ["processPid"],
  parentprocessid: ["parentProcessPid"],
  user: ["userName"],
  username: ["userName"],
  subjectusername: ["userName"],
  targetusername: ["userName"],
  accountname: ["userName"],
  computer: ["hostName"],
  computername: ["hostName"],
  hostname: ["hostName"],
  workstation: ["hostName"],
  workstationname: ["hostName"],
  destinationip: ["destIp"],
  dst_ip: ["destIp"],
  destinationport: ["destPort"],
  dst_port: ["destPort"],
  sourceip: ["sourceIp"],
  src_ip: ["sourceIp"],
  ipaddress: ["sourceIp"],
  clientip: ["sourceIp"],
  targetfilename: ["filePath"],
  filename: ["filePath"],
  filepath: ["filePath"],
  path: ["filePath"],
  hashes: ["fileHash"],
  sha256: ["fileHash"],
  hash: ["fileHash"],
  servicename: ["service"],
  eventtype: ["eventType"],
};

// Image-like fields hold full paths in Sigma rules ("…\\powershell.exe");
// events that carry only a file name still match an endswith on the path.
const PATH_LIKE = new Set(["processName", "parentProcessName"]);

function flatten(value: unknown, path: string[] = [], out: Array<[string, string]> = []): Array<[string, string]> {
  if (out.length > 400) return out;
  if (value && typeof value === "object") {
    if (Array.isArray(value)) value.forEach((v) => flatten(v, path, out));
    else for (const [k, v] of Object.entries(value)) flatten(v, [...path, k], out);
  } else if (value !== null && value !== undefined) {
    out.push([path[path.length - 1]?.toLowerCase() ?? "", String(value)]);
  }
  return out;
}

export function sigmaEvent(row: EventRow): SigmaEvent {
  const nested = [...flatten(row.metadata), ...flatten(row.ocsf)];
  const byKey = new Map<string, string[]>();
  for (const [k, v] of nested) byKey.set(k, [...(byKey.get(k) ?? []), v]);
  const column = (c: Column): string[] => {
    const v = row[c];
    if (v === null || v === undefined || v === "") return [];
    const s = String(v);
    if (c === "fileHash") return [s, `SHA256=${s.toUpperCase()}`, `sha256=${s.toLowerCase()}`];
    if (PATH_LIKE.has(c) && !/[\\/]/.test(s)) return [s, `\\${s}`];
    return [s];
  };
  let allCache: string[] | null = null;
  return {
    values(field: string) {
      const key = field.toLowerCase();
      const fromColumns = (ALIASES[key] ?? []).flatMap(column);
      const fromRecords = byKey.get(key) ?? (key === "eventid" ? byKey.get("event_code") ?? byKey.get("eventcode") ?? [] : []);
      return [...new Set([...fromColumns, ...fromRecords])];
    },
    all() {
      if (!allCache) {
        const cols: Column[] = ["userName", "hostName", "service", "processName", "parentProcessName", "commandLine", "sourceIp", "destIp", "filePath", "fileHash", "eventType"];
        allCache = [...new Set([...cols.flatMap(column), ...nested.map(([, v]) => v)])];
      }
      return allCache;
    },
  };
}

// Which events a rule's logsource covers. A logsource HELIOS doesn't know
// is checked against every event, and the import says so.
const CATEGORY: Record<string, { classUid?: number[]; eventType: RegExp }> = {
  process_creation: { classUid: [1007], eventType: /process|exec|spawn|4688|sysmon[_ ]?1\b/i },
  network_connection: { classUid: [4001], eventType: /network|connect|flow|firewall/i },
  firewall: { classUid: [4001], eventType: /firewall|network|flow|deny|allow/i },
  dns_query: { classUid: [4003], eventType: /dns/i },
  dns: { classUid: [4003], eventType: /dns/i },
  file_event: { classUid: [1001], eventType: /file/i },
  file_change: { classUid: [1001], eventType: /file/i },
  file_delete: { classUid: [1001], eventType: /file/i },
  file_access: { classUid: [1001], eventType: /file/i },
  file_rename: { classUid: [1001], eventType: /file/i },
  image_load: { eventType: /image|module|dll|load/i },
  registry_event: { eventType: /registry/i },
  registry_set: { eventType: /registry/i },
  registry_add: { eventType: /registry/i },
  registry_delete: { eventType: /registry/i },
  authentication: { classUid: [3002], eventType: /auth|logon|login|sign/i },
  webserver: { classUid: [4002], eventType: /http|web|request/i },
  proxy: { classUid: [4002], eventType: /http|proxy|web/i },
  ps_script: { eventType: /powershell|script/i },
  ps_module: { eventType: /powershell|module/i },
};

const PRODUCT: Record<string, RegExp> = {
  aws: /aws|cloudtrail/i,
  azure: /azure|entra|microsoft/i,
  gcp: /gcp|google/i,
  okta: /okta/i,
  m365: /m365|office|microsoft|defender/i,
  google_workspace: /google/i,
  github: /github/i,
};

export function logsourceFilter(ls: { category?: string; product?: string; service?: string }): { test: (row: EventRow) => boolean; known: boolean } {
  const cat = ls.category ? CATEGORY[ls.category] : undefined;
  const product = ls.product && PRODUCT[ls.product];
  const known = (!ls.category || !!cat) && (!ls.product || ["windows", "linux", "macos"].includes(ls.product) || !!product);
  return {
    known,
    test(row) {
      if (cat && !((row.classUid != null && cat.classUid?.includes(row.classUid)) || cat.eventType.test(row.eventType))) return false;
      if (product && !(product.test(row.platform ?? "") || product.test(row.source))) return false;
      return true;
    },
  };
}
