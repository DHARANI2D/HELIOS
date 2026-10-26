import { createHash } from "node:crypto";

import { ACTIVITY, CLASS, SEVERITY, STATUS, ocsfEvent, type OcsfEvent, type OcsfFields } from "@/lib/ocsf/schema";
import { MappingError, dateOf, num, str, type Raw } from "@/lib/ocsf/sources/util";

// Syslog to OCSF, as the HELIOS forwarder (Fluent Bit's syslog input with
// the syslog-rfc5424 / rfc3164 parsers) sends it: pri, time, host, ident,
// pid, message. The message is read as, in order:
//   CEF ("CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext");
//   OPNsense / pfSense filterlog (CSV after "filterlog:");
//   key=value logs (FortiGate traffic, UTM and event logs, and most others);
//   OpenSSH sign-ins ("Accepted|Failed password for … from …");
// and anything else is kept as a Base Event with its text.

// Syslog severity (pri % 8): 0 emergency … 7 debug.
const PRI_SEVERITY = [SEVERITY.CRITICAL, SEVERITY.CRITICAL, SEVERITY.CRITICAL, SEVERITY.HIGH, SEVERITY.MEDIUM, SEVERITY.LOW, SEVERITY.INFORMATIONAL, SEVERITY.INFORMATIONAL];

export function keyValues(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|\S*)/g;
  for (const m of text.matchAll(re)) {
    const v = m[2].startsWith('"') ? m[2].slice(1, -1).replace(/\\"/g, '"') : m[2];
    if (!(m[1] in out)) out[m[1]] = v;
  }
  return out;
}

// CEF extension values escape "=" and "\" with a backslash; keys are single words.
function cefExtension(ext: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /(\w+)=((?:\\=|[^=])*?)(?=\s+\w+=|$)/g;
  for (const m of ext.matchAll(re)) out[m[1]] = m[2].trim().replace(/\\=/g, "=").replace(/\\\\/g, "\\");
  return out;
}

const blocked = (action: string | undefined) => !!action && /deny|denied|drop|block|reject|reset|close-?reject|fail/i.test(action);
const PROTO: Record<string, string> = { "1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp" };

function network(common: OcsfFields, f: { src?: string; dst?: string; spt?: string; dpt?: string; proto?: string; action?: string; bytes?: number; user?: string; url?: string; host?: string }): OcsfEvent {
  const ends = {
    src_endpoint: { ip: f.src, port: num(f.spt) },
    dst_endpoint: { ip: f.dst, port: num(f.dpt), hostname: f.host },
  };
  if (f.url || (f.host && !f.dst)) {
    return ocsfEvent(CLASS.HTTP, ACTIVITY.OTHER, { ...common, ...ends, http_request: { url: { url_string: f.url, hostname: f.host } }, disposition: f.action, actor: f.user ? { user: { name: f.user } } : undefined });
  }
  return ocsfEvent(CLASS.NETWORK, blocked(f.action) ? ACTIVITY.network.REFUSE : f.action ? ACTIVITY.network.OPEN : ACTIVITY.network.TRAFFIC, {
    ...common,
    ...ends,
    connection_info: f.proto ? { protocol_name: PROTO[f.proto] ?? f.proto.toLowerCase() } : undefined,
    disposition: f.action,
    traffic: f.bytes !== undefined ? { bytes: f.bytes } : undefined,
    actor: f.user ? { user: { name: f.user } } : undefined,
  });
}

function fromCef(common: OcsfFields, message: string): OcsfEvent | null {
  const at = message.indexOf("CEF:");
  if (at < 0) return null;
  // Header fields are pipe-delimited with "\|" escapes; the extension follows the 7th pipe.
  const parts: string[] = [];
  let cur = "";
  let rest = "";
  const body = message.slice(at + 4);
  for (let i = 0; i < body.length; i++) {
    if (body[i] === "\\" && (body[i + 1] === "|" || body[i + 1] === "\\")) {
      cur += body[++i];
    } else if (body[i] === "|" && parts.length < 7) {
      parts.push(cur);
      cur = "";
      if (parts.length === 7) {
        rest = body.slice(i + 1);
        break;
      }
    } else cur += body[i];
  }
  if (parts.length < 7) return null;
  const [, vendor, product, , signature, name, sev] = parts;
  const x = cefExtension(rest);
  const sevNum = num(sev);
  const base: OcsfFields = {
    ...common,
    product: product || common.product,
    vendor: vendor || undefined,
    activity_name: name || signature,
    severity_id: sevNum === undefined ? common.severity_id : sevNum >= 9 ? SEVERITY.CRITICAL : sevNum >= 7 ? SEVERITY.HIGH : sevNum >= 4 ? SEVERITY.MEDIUM : sevNum >= 1 ? SEVERITY.LOW : SEVERITY.INFORMATIONAL,
    time: dateOf(num(x.rt) ?? x.rt, x.end) ?? common.time,
    uid: x.externalId ?? common.uid,
    message: x.msg ?? name,
    unmapped: { cef: { signature, ...x } },
  };
  const outcome = (x.outcome ?? x.act ?? "").toLowerCase();
  if (/login|logon|authentication|sign-?in/i.test(`${name} ${x.cat ?? ""}`) && (x.suser || x.duser)) {
    return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGON, {
      ...base,
      status_id: /fail|deny|denied|reject/.test(outcome) ? STATUS.FAILURE : /success|allow|accept/.test(outcome) ? STATUS.SUCCESS : STATUS.UNKNOWN,
      user: { name: x.duser ?? x.suser },
      src_endpoint: { ip: x.src, hostname: x.shost },
      dst_endpoint: { ip: x.dst, hostname: x.dhost },
    });
  }
  if (x.src || x.dst || x.request) return network(base, { src: x.src, dst: x.dst, spt: x.spt, dpt: x.dpt, proto: x.proto, action: x.act ?? x.outcome, bytes: num(x.out) ?? num(x.bytesOut), user: x.suser, url: x.request, host: x.dhost });
  return ocsfEvent(CLASS.BASE, ACTIVITY.OTHER, base);
}

// OPNsense / pfSense: rule, sub-rule, anchor, tracker, interface, reason,
// action, direction, IP version, then for IPv4: tos, ecn, ttl, id, offset,
// flags, protocol id, protocol, length, source, destination, and for TCP/UDP
// source and destination ports.
function fromFilterlog(common: OcsfFields, message: string): OcsfEvent | null {
  const m = message.match(/(?:^|\s)filterlog(?:\[\d+\])?:\s*(.+)$/);
  const csv = m?.[1] ?? (common.unmapped?.ident === "filterlog" ? message : null);
  if (!csv) return null;
  const f = csv.split(",");
  if (f.length < 20) return null;
  const v6 = f[8] === "6";
  // IPv6: class, flow label, hop limit, protocol, protocol id, length, source, destination.
  const [proto, src, dst, spt, dpt] = v6 ? [f[12], f[15], f[16], f[17], f[18]] : [f[16], f[18], f[19], f[20], f[21]];
  const tcpUdp = /^(tcp|udp)$/i.test(proto ?? "");
  return network({ ...common, product: "OPNsense / pfSense filterlog", activity_name: `${f[6]} ${f[7]} on ${f[4]}`, unmapped: { ...common.unmapped, rule: f[0], tracker: f[3], interface: f[4], direction: f[7] } }, {
    src,
    dst,
    spt: tcpUdp ? spt : undefined,
    dpt: tcpUdp ? dpt : undefined,
    proto: proto?.toLowerCase(),
    action: f[6],
  });
}

function fromKeyValues(common: OcsfFields, message: string): OcsfEvent | null {
  const kv = keyValues(message);
  if (Object.keys(kv).length < 3) return null;
  const pick = (...keys: string[]) => keys.map((k) => kv[k]).find((v) => v !== undefined && v !== "");
  const src = pick("srcip", "src", "src_ip", "source_ip", "SRC");
  const dst = pick("dstip", "dst", "dst_ip", "dest_ip", "destination_ip", "DST");
  const user = pick("user", "srcuser", "username", "usrName", "suser");
  const fields = { ...common, unmapped: { ...common.unmapped, kv }, uid: pick("logid") && pick("eventtime") ? `${pick("devid") ?? ""}:${pick("logid")}:${pick("eventtime")}` : common.uid };
  const desc = pick("logdesc", "msg", "action") ?? "";
  // FortiGate (and similar) admin / VPN / user sign-ins.
  if (/login|logon|auth/i.test(`${pick("subtype") ?? ""} ${desc}`) && user && !dst) {
    const status = (pick("status", "result", "action") ?? "").toLowerCase();
    return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGON, {
      ...fields,
      activity_name: desc || "login",
      status_id: /fail|deny|denied|reject/.test(status) ? STATUS.FAILURE : /success|accept|allow/.test(status) ? STATUS.SUCCESS : STATUS.UNKNOWN,
      status_detail: pick("reason"),
      user: { name: user },
      src_endpoint: { ip: src ?? pick("remip", "ui")?.match(/\d+\.\d+\.\d+\.\d+/)?.[0] },
      dst_endpoint: { hostname: pick("devname") ?? common.device?.hostname },
      service: { name: pick("subtype", "service") },
    });
  }
  if (!src && !dst && !pick("url", "hostname")) return null;
  return network({ ...fields, activity_name: desc || pick("type", "subtype") }, {
    src,
    dst,
    spt: pick("srcport", "spt", "src_port", "sport"),
    dpt: pick("dstport", "dpt", "dst_port", "dport"),
    proto: pick("proto", "protocol"),
    action: pick("action", "act", "utmaction"),
    bytes: num(pick("sentbyte", "bytes_sent", "sentbytes", "bytes")),
    user,
    url: pick("url") ? `${pick("hostname") ? `https://${pick("hostname")}` : ""}${pick("url")}` : undefined,
    host: pick("hostname"),
  });
}

const SSH = /(Accepted|Failed) (password|publickey|keyboard-interactive(?:\/pam)?) for (?:invalid user )?(\S+) from (\S+) port (\d+)/;
const SSH_INVALID = /Invalid user (\S+) from (\S+)(?: port (\d+))?/;

function fromSsh(common: OcsfFields, message: string): OcsfEvent | null {
  const m = message.match(SSH);
  const inv = m ? null : message.match(SSH_INVALID);
  if (!m && !inv) return null;
  const failed = m ? m[1] === "Failed" : true;
  return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGON, {
    ...common,
    product: "OpenSSH",
    activity_name: "ssh login",
    severity_id: failed ? SEVERITY.LOW : SEVERITY.INFORMATIONAL,
    status_id: failed ? STATUS.FAILURE : STATUS.SUCCESS,
    status_detail: inv ? "invalid user" : undefined,
    user: { name: m?.[3] ?? inv![1] },
    src_endpoint: { ip: m?.[4] ?? inv![2], port: num(m?.[5] ?? inv?.[3]) },
    dst_endpoint: { hostname: common.device?.hostname },
    service: { name: "sshd" },
    auth_protocol: m?.[2],
  });
}

export function isSyslog(r: Raw) {
  return typeof r.message === "string" && (r.pri !== undefined || r.ident !== undefined || r.helios_input === "syslog");
}

export function syslogRecord(r: Raw): OcsfEvent {
  const message = str(r.message);
  if (!message) throw new MappingError("Syslog record has no message");
  const pri = num(r.pri);
  // The forwarder stamps its own receive time (timestamp); the device's
  // clock (time) is often wrong, and RFC 3164 times have no year.
  const time = dateOf(r.timestamp, r.time) ?? null;
  if (!time) throw new MappingError("Syslog record has no readable time");
  const common: OcsfFields = {
    time,
    product: str(r.ident) ?? "syslog",
    // Syslog has no event id: a resend of the same line (a forwarder retry)
    // has the same host, receive time and text, so that is its id.
    uid: createHash("sha256").update(`${str(r.host) ?? ""}|${str(r.timestamp, r.time) ?? ""}|${message}`).digest("hex").slice(0, 32),
    severity_id: pri === undefined ? SEVERITY.INFORMATIONAL : PRI_SEVERITY[pri % 8],
    device: { hostname: str(r.host) },
    message: message.slice(0, 1000),
    unmapped: { facility: pri === undefined ? undefined : Math.floor(pri / 8), ident: str(r.ident), pid: str(r.pid), msgid: str(r.msgid) },
  };
  return fromCef(common, message) ?? fromFilterlog(common, message) ?? fromSsh(common, message) ?? fromKeyValues(common, message) ?? ocsfEvent(CLASS.BASE, ACTIVITY.OTHER, { ...common, activity_name: "syslog" });
}

// A line from a tailed log file: JSON lines are handled by the generic
// mapper (null here); text is read like a syslog message.
export function fileLine(r: Raw): OcsfEvent | null {
  const line = str(r.log);
  if (!line) throw new MappingError("File record has no log line");
  if (line.startsWith("{")) return null;
  return syslogRecord({ message: line, host: r.host ?? r.hostname, timestamp: r.timestamp, ident: r.helios_file ?? "file" });
}
