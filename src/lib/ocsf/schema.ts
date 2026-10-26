// The canonical event schema: OCSF (Open Cybersecurity Schema Framework,
// https://schema.ocsf.io), the classes HELIOS produces. Every stored event
// carries its OCSF form; new source mappings are written OCSF-first and the
// flat columns the detectors read are derived from it (columns.ts). Class
// and activity ids follow the OCSF 1.9.0 schema repository.

export const OCSF_VERSION = "1.9.0";

export const CLASS = {
  BASE: 0,
  FILE_SYSTEM: 1001,
  PROCESS: 1007,
  DETECTION_FINDING: 2004,
  ACCOUNT_CHANGE: 3001,
  AUTHENTICATION: 3002,
  NETWORK: 4001,
  HTTP: 4002,
  DNS: 4003,
  API: 6003,
} as const;

export type ClassUid = (typeof CLASS)[keyof typeof CLASS];

export const CLASS_NAME: Record<ClassUid, string> = {
  0: "Base Event",
  1001: "File System Activity",
  1007: "Process Activity",
  2004: "Detection Finding",
  3001: "Account Change",
  3002: "Authentication",
  4001: "Network Activity",
  4002: "HTTP Activity",
  4003: "DNS Activity",
  6003: "API Activity",
};

// Activity ids per class (99 = Other, 0 = Unknown in every class).
export const ACTIVITY = {
  file: { CREATE: 1, READ: 2, UPDATE: 3, DELETE: 4, RENAME: 5 },
  process: { LAUNCH: 1, TERMINATE: 2, OPEN: 3, INJECT: 4 },
  finding: { CREATE: 1, UPDATE: 2, CLOSE: 3 },
  account: { CREATE: 1, ENABLE: 2, PASSWORD_CHANGE: 3, PASSWORD_RESET: 4, DISABLE: 5, DELETE: 6, ATTACH_POLICY: 7, DETACH_POLICY: 8, LOCK: 9, MFA_ENABLE: 10, MFA_DISABLE: 11, UNLOCK: 12 },
  auth: { LOGON: 1, LOGOFF: 2, TICKET: 3, SERVICE_TICKET: 4 },
  network: { OPEN: 1, CLOSE: 2, RESET: 3, FAIL: 4, REFUSE: 5, TRAFFIC: 6, LISTEN: 7 },
  http: { CONNECT: 1, DELETE: 2, GET: 3, HEAD: 4, OPTIONS: 5, POST: 6, PUT: 7, TRACE: 8, PATCH: 9 },
  dns: { QUERY: 1, RESPONSE: 2, TRAFFIC: 6 },
  api: { CREATE: 1, READ: 2, UPDATE: 3, DELETE: 4 },
  OTHER: 99,
  UNKNOWN: 0,
} as const;

export const SEVERITY = { UNKNOWN: 0, INFORMATIONAL: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5, FATAL: 6 } as const;
export const STATUS = { UNKNOWN: 0, SUCCESS: 1, FAILURE: 2, OTHER: 99 } as const;

export interface OcsfUser {
  name?: string;
  uid?: string;
  email_addr?: string;
  domain?: string;
  type?: string;
}

export interface OcsfEndpoint {
  hostname?: string;
  ip?: string;
  port?: number;
  name?: string;
  uid?: string;
  location?: { country?: string; city?: string };
}

export interface OcsfFile {
  name?: string;
  path?: string;
  hashes?: Array<{ algorithm_id: number; algorithm: string; value: string }>;
}

export interface OcsfProcess {
  name?: string;
  pid?: number;
  cmd_line?: string;
  file?: OcsfFile;
  parent_process?: OcsfProcess;
  user?: OcsfUser;
}

export interface OcsfEvent {
  class_uid: ClassUid;
  category_uid: number;
  activity_id: number;
  activity_name?: string;
  type_uid: number;
  severity_id: number;
  time: number; // epoch milliseconds
  status_id?: number;
  status?: string;
  status_detail?: string;
  message?: string;
  metadata: {
    version: string;
    product: { name: string; vendor_name?: string };
    uid?: string; // the source's own event id
    log_name?: string;
    original_time?: string;
  };
  actor?: { user?: OcsfUser; process?: OcsfProcess; app_name?: string };
  user?: OcsfUser;
  // The service or application signed in to (Authentication).
  service?: { name?: string; uid?: string };
  device?: { hostname?: string; ip?: string; name?: string; os?: { name: string } };
  src_endpoint?: OcsfEndpoint;
  dst_endpoint?: OcsfEndpoint;
  process?: OcsfProcess;
  file?: OcsfFile;
  connection_info?: { protocol_name?: string; direction?: string };
  traffic?: { bytes?: number; bytes_in?: number; bytes_out?: number };
  query?: { hostname: string; type?: string };
  http_request?: { http_method?: string; url?: { url_string?: string; hostname?: string } };
  api?: { operation: string; service?: { name?: string } };
  cloud?: { provider: string; region?: string; account?: { uid?: string } };
  resources?: Array<{ name?: string; uid?: string; type?: string }>;
  finding_info?: { uid?: string; title: string; desc?: string; attacks?: Array<{ technique: { uid: string } }> };
  logon_type?: string;
  auth_protocol?: string;
  is_mfa?: boolean;
  disposition?: string;
  // Source fields with no OCSF home, kept as the source named them.
  unmapped?: Record<string, unknown>;
}

const SHA256 = /^[a-f0-9]{64}$/i;
const SHA1 = /^[a-f0-9]{40}$/i;
const MD5 = /^[a-f0-9]{32}$/i;

export function hashesOf(value: string | undefined): OcsfFile["hashes"] {
  if (!value) return undefined;
  const v = value.trim().toLowerCase();
  if (SHA256.test(v)) return [{ algorithm_id: 3, algorithm: "SHA-256", value: v }];
  if (SHA1.test(v)) return [{ algorithm_id: 2, algorithm: "SHA-1", value: v }];
  if (MD5.test(v)) return [{ algorithm_id: 1, algorithm: "MD5", value: v }];
  return undefined;
}

// Drops undefined fields and empty objects so stored events stay small.
function compact<T>(value: T): T {
  if (Array.isArray(value)) return value.map(compact).filter((v) => v !== undefined) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      const c = compact(v);
      if (c === undefined || c === null || c === "") continue;
      if (typeof c === "object" && !Array.isArray(c) && Object.keys(c).length === 0) continue;
      out[k] = c;
    }
    return out as T;
  }
  return value;
}

export type OcsfFields = Omit<OcsfEvent, "class_uid" | "category_uid" | "activity_id" | "type_uid" | "metadata" | "time" | "severity_id"> & {
  time: Date;
  severity_id?: number;
  product: string;
  vendor?: string;
  uid?: string;
  log_name?: string;
};

// type_uid = class_uid * 100 + activity_id; the category is the class's thousands.
export function ocsfEvent(classUid: ClassUid, activityId: number, fields: OcsfFields): OcsfEvent {
  const { time, product, vendor, uid, log_name, severity_id, ...rest } = fields;
  const t = time.getTime();
  return compact({
    class_uid: classUid,
    category_uid: Math.floor(classUid / 1000),
    activity_id: activityId,
    type_uid: classUid * 100 + activityId,
    severity_id: severity_id ?? SEVERITY.INFORMATIONAL,
    time: Number.isFinite(t) ? t : Date.now(),
    ...rest,
    metadata: { version: OCSF_VERSION, product: { name: product, vendor_name: vendor }, uid, log_name },
  });
}

export function isOcsfEvent(value: unknown): value is OcsfEvent {
  return !!value && typeof value === "object" && typeof (value as OcsfEvent).class_uid === "number" && typeof (value as OcsfEvent).time === "number";
}
