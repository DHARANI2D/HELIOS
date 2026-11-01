import { isIP } from "node:net";

import { finding, type NewFinding, type TestFinding } from "@/lib/testing/findings";
import { hostOf, type ScopeTarget } from "@/lib/testing/scope";

// HELIOS's own external exposure check: what an attacker on the internet
// sees of the client's verified targets, without exploiting anything.
//   - services: a TCP connect to well-known ports, and the first bytes a
//     service volunteers (its banner); nothing is sent to it;
//   - TLS: the certificate (expiry, name, issuer) and the protocol;
//   - web: whether HTTP sends people to HTTPS, and the security headers;
//   - email: SPF and DMARC for the names checked.
// Probes are few, slow and bounded (a handful at a time, short timeouts),
// stay inside the authorised window, and each one is logged.

export const SOURCE = "HELIOS exposure check";

export const CHECKS = {
  services: "Exposed services (TCP connect to common ports)",
  tls: "TLS certificates and protocol",
  web: "Web: HTTPS redirect and security headers",
  email: "Email: SPF and DMARC",
} as const;
export type CheckKey = keyof typeof CHECKS;

interface PortRule {
  service: string;
  severity: NewFinding["severity"];
  title: string;
  remediation: string;
}

const RDP_LIKE = "Don't expose it to the internet: put it behind a VPN or zero-trust gateway, or allow only known addresses.";
export const PORTS: Record<number, PortRule> = {
  21: { service: "ftp", severity: "medium", title: "FTP reachable from the internet", remediation: "Replace FTP with SFTP or HTTPS; FTP sends passwords in clear text." },
  22: { service: "ssh", severity: "low", title: "SSH reachable from the internet", remediation: "Allow key-based sign-in only, restrict the source addresses, and keep the server patched." },
  23: { service: "telnet", severity: "critical", title: "Telnet reachable from the internet", remediation: "Turn Telnet off; it sends everything, passwords included, in clear text. Use SSH." },
  25: { service: "smtp", severity: "info", title: "SMTP server reachable", remediation: "Expected for a mail server; make sure it isn't an open relay." },
  80: { service: "http", severity: "info", title: "Web server on HTTP", remediation: "Redirect HTTP to HTTPS." },
  110: { service: "pop3", severity: "medium", title: "POP3 without TLS reachable", remediation: "Use POP3S (995) only." },
  135: { service: "msrpc", severity: "high", title: "Windows RPC reachable from the internet", remediation: RDP_LIKE },
  139: { service: "netbios", severity: "high", title: "NetBIOS reachable from the internet", remediation: "Block NetBIOS at the perimeter." },
  143: { service: "imap", severity: "medium", title: "IMAP without TLS reachable", remediation: "Use IMAPS (993) only." },
  389: { service: "ldap", severity: "high", title: "LDAP reachable from the internet", remediation: "Don't expose directory services; use LDAPS from known networks only." },
  443: { service: "https", severity: "info", title: "Web server on HTTPS", remediation: "Expected for a web service." },
  445: { service: "smb", severity: "critical", title: "SMB file sharing reachable from the internet", remediation: "Block SMB (445) at the perimeter; it is a common ransomware entry point." },
  636: { service: "ldaps", severity: "medium", title: "LDAPS reachable from the internet", remediation: "Allow only known networks to reach the directory." },
  1433: { service: "mssql", severity: "high", title: "SQL Server reachable from the internet", remediation: "Databases shouldn't be reachable from the internet; allow only the application servers." },
  1521: { service: "oracle", severity: "high", title: "Oracle database reachable from the internet", remediation: "Allow only the application servers." },
  2049: { service: "nfs", severity: "high", title: "NFS reachable from the internet", remediation: "Block NFS at the perimeter." },
  2375: { service: "docker", severity: "critical", title: "Docker API without TLS reachable", remediation: "Close it now: anyone reaching it controls the host. Use the local socket or TLS with client certificates." },
  3306: { service: "mysql", severity: "high", title: "MySQL reachable from the internet", remediation: "Allow only the application servers." },
  3389: { service: "rdp", severity: "high", title: "Remote Desktop reachable from the internet", remediation: RDP_LIKE },
  5432: { service: "postgres", severity: "high", title: "PostgreSQL reachable from the internet", remediation: "Allow only the application servers." },
  5900: { service: "vnc", severity: "high", title: "VNC reachable from the internet", remediation: RDP_LIKE },
  5985: { service: "winrm", severity: "high", title: "WinRM (HTTP) reachable from the internet", remediation: RDP_LIKE },
  5986: { service: "winrm", severity: "high", title: "WinRM (HTTPS) reachable from the internet", remediation: RDP_LIKE },
  6379: { service: "redis", severity: "high", title: "Redis reachable from the internet", remediation: "Bind Redis to private addresses and require authentication." },
  8080: { service: "http-alt", severity: "medium", title: "Web service on port 8080", remediation: "Often an admin console or test server: close it or put it behind authentication." },
  8443: { service: "https-alt", severity: "low", title: "Web service on port 8443", remediation: "Often an admin console: restrict who can reach it." },
  9200: { service: "elasticsearch", severity: "high", title: "Elasticsearch reachable from the internet", remediation: "Restrict access and turn on authentication." },
  11211: { service: "memcached", severity: "high", title: "Memcached reachable from the internet", remediation: "Bind to private addresses; it is abused for amplification attacks." },
  27017: { service: "mongodb", severity: "high", title: "MongoDB reachable from the internet", remediation: "Restrict access and turn on authentication." },
};
const TLS_PORTS = [443, 8443, 636, 993, 995, 465, 5986];

export interface CertInfo {
  subject: string;
  issuer: string;
  validTo: string;
  names: string[];
  selfSigned: boolean;
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
}

export interface Net {
  addresses(name: string): Promise<string[]>;
  txt(name: string): Promise<string[][]>;
  connect(ip: string, port: number, timeoutMs: number): Promise<{ open: boolean; banner: string | null }>;
  tls(ip: string, port: number, servername: string | null, timeoutMs: number): Promise<CertInfo | null>;
  http(url: string, timeoutMs: number): Promise<{ status: number; headers: Record<string, string> } | null>;
}

export interface Probe {
  at: string;
  target: string;
  check: string;
  result: string;
}

export interface ExposureOptions {
  checks: CheckKey[];
  net: Net;
  now?: () => Date;
  // Stop early: the window closed or someone cancelled the test.
  shouldStop?: () => Promise<string | null>;
  concurrency?: number;
  timeoutMs?: number;
}

async function pool<T>(items: T[], size: number, fn: (x: T) => Promise<void>) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => {
    while (i < items.length) await fn(items[i++]);
  }));
}

const nameMatches = (pattern: string, host: string) => {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p === h) return true;
  if (p.startsWith("*.")) return h.endsWith(p.slice(1)) && h.split(".").length === p.split(".").length;
  return false;
};

export async function runExposureCheck(targets: ScopeTarget[], opts: ExposureOptions): Promise<{ findings: TestFinding[]; probes: Probe[]; stopped: string | null }> {
  const now = opts.now ?? (() => new Date());
  const timeout = opts.timeoutMs ?? 3000;
  const conc = opts.concurrency ?? 8;
  const probes: Probe[] = [];
  const out: NewFinding[] = [];
  const log = (target: string, check: string, result: string) => probes.push({ at: now().toISOString(), target, check, result });
  const add = (f: Omit<NewFinding, "source">) => out.push({ ...f, source: SOURCE });

  const verified = targets.filter((t) => t.verified);
  const names = [...new Set(verified.map(hostOf).filter((h) => !isIP(h)))];
  // Every address in scope, with the name it was verified through (for SNI and reports).
  const ips = new Map<string, string | null>();
  for (const t of verified) for (const a of t.addresses) if (!ips.has(a) || (!ips.get(a) && !isIP(hostOf(t)))) ips.set(a, isIP(hostOf(t)) ? null : hostOf(t));

  let stopped: string | null = null;
  const stop = async () => (stopped ??= (await opts.shouldStop?.()) ?? null);

  // Services.
  const open = new Map<string, number[]>();
  if (opts.checks.includes("services")) {
    const jobs = [...ips.keys()].flatMap((ip) => Object.keys(PORTS).map((p) => ({ ip, port: Number(p) })));
    await pool(jobs, conc, async ({ ip, port }) => {
      if (await stop()) return;
      const r = await opts.net.connect(ip, port, timeout).catch(() => ({ open: false, banner: null }));
      if (!r.open) return;
      log(ip, `tcp/${port}`, `open${r.banner ? `: ${r.banner.slice(0, 80)}` : ""}`);
      open.set(ip, [...(open.get(ip) ?? []), port]);
      const rule = PORTS[port];
      const label = ips.get(ip) ? `${ips.get(ip)} (${ip})` : ip;
      add({ title: rule.title, severity: rule.severity, target: ip, port, service: rule.service, evidence: `TCP ${port} on ${label} accepted a connection from the internet${r.banner ? `; it announced: ${r.banner.slice(0, 200)}` : ""}.`, remediation: rule.remediation, references: [] });
    });
    for (const ip of ips.keys()) if (!open.has(ip)) log(ip, "tcp", `no common port open (${Object.keys(PORTS).length} checked)`);
  }

  // TLS.
  if (opts.checks.includes("tls") && !(await stop())) {
    const jobs = [...ips.entries()].flatMap(([ip, name]) => TLS_PORTS.filter((p) => !opts.checks.includes("services") || open.get(ip)?.includes(p)).map((port) => ({ ip, name, port })));
    await pool(jobs, conc, async ({ ip, name, port }) => {
      if (await stop()) return;
      const c = await opts.net.tls(ip, port, name, timeout).catch(() => null);
      if (!c) return;
      const where = `${name ?? ip}:${port}`;
      log(ip, `tls/${port}`, `${c.protocol ?? "?"}, ${c.subject}, valid to ${c.validTo}`);
      const days = Math.floor((new Date(c.validTo).getTime() - now().getTime()) / 86_400_000);
      if (days < 0) add({ title: "TLS certificate expired", severity: "high", target: ip, port, service: "tls", evidence: `The certificate on ${where} expired on ${c.validTo.slice(0, 10)}.`, remediation: "Renew the certificate (automate renewal, e.g. ACME).", references: [] });
      else if (days < 14) add({ title: "TLS certificate expires within 14 days", severity: "medium", target: ip, port, service: "tls", evidence: `The certificate on ${where} expires on ${c.validTo.slice(0, 10)} (${days} days).`, remediation: "Renew it now and automate renewal.", references: [] });
      else if (days < 30) add({ title: "TLS certificate expires within 30 days", severity: "low", target: ip, port, service: "tls", evidence: `The certificate on ${where} expires on ${c.validTo.slice(0, 10)} (${days} days).`, remediation: "Plan the renewal; automate it if you can.", references: [] });
      if (name && !c.names.some((n) => nameMatches(n, name))) add({ title: "TLS certificate doesn't match the name", severity: "high", target: ip, port, service: "tls", evidence: `${where} presents a certificate for ${c.names.slice(0, 5).join(", ") || c.subject}.`, remediation: "Install a certificate that covers this name.", references: [] });
      if (c.selfSigned) add({ title: "Self-signed TLS certificate", severity: "medium", target: ip, port, service: "tls", evidence: `${where} presents a self-signed certificate (${c.subject}).`, remediation: "Use a certificate from a trusted authority.", references: [] });
      else if (!c.authorized && c.authorizationError && !/HOSTNAME|ALTNAME|EXPIRED/i.test(c.authorizationError)) add({ title: "TLS certificate not trusted", severity: "medium", target: ip, port, service: "tls", evidence: `${where}: ${c.authorizationError} (issuer ${c.issuer}).`, remediation: "Serve the full chain from a trusted authority.", references: [] });
      if (c.protocol && /^(SSLv|TLSv1(\.[01])?$)/.test(c.protocol)) add({ title: `Outdated TLS protocol (${c.protocol})`, severity: "high", target: ip, port, service: "tls", evidence: `${where} negotiated ${c.protocol} when a modern client offered TLS 1.3.`, remediation: "Allow TLS 1.2 and 1.3 only.", references: [] });
    });
  }

  // Web.
  if (opts.checks.includes("web") && !(await stop())) {
    for (const name of names) {
      if (await stop()) break;
      const resolved = [...ips.entries()].filter(([, n]) => n === name).map(([ip]) => ip);
      const has = (p: number) => !opts.checks.includes("services") || resolved.some((ip) => open.get(ip)?.includes(p));
      if (has(80)) {
        const r = await opts.net.http(`http://${name}/`, timeout * 3).catch(() => null);
        if (r) {
          log(name, "http", `${r.status}${r.headers.location ? ` → ${r.headers.location}` : ""}`);
          if (!(r.status >= 300 && r.status < 400 && (r.headers.location ?? "").startsWith("https://"))) add({ title: "HTTP doesn't redirect to HTTPS", severity: "medium", target: name, port: 80, service: "http", evidence: `http://${name}/ answered ${r.status}${r.headers.location ? ` (Location: ${r.headers.location})` : ""}.`, remediation: "Redirect every HTTP request to HTTPS (301), then send HSTS.", references: [] });
        }
      }
      if (has(443)) {
        const r = await opts.net.http(`https://${name}/`, timeout * 3).catch(() => null);
        if (!r) continue;
        const h = r.headers;
        log(name, "https", `${r.status}; ${["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options"].filter((k) => h[k]).length} of 4 security headers`);
        const missing = (key: string, title: string, severity: NewFinding["severity"], remediation: string) => {
          if (!h[key]) add({ title, severity, target: name, port: 443, service: "https", evidence: `https://${name}/ answered ${r.status} without a ${key} header.`, remediation, references: [] });
        };
        missing("strict-transport-security", "No HSTS header", "medium", "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.");
        missing("content-security-policy", "No Content-Security-Policy header", "low", "Send a Content-Security-Policy that allows only your own scripts.");
        missing("x-content-type-options", "No X-Content-Type-Options header", "low", "Send X-Content-Type-Options: nosniff.");
        if (!h["x-frame-options"] && !/frame-ancestors/i.test(h["content-security-policy"] ?? "")) add({ title: "Page can be framed by other sites", severity: "low", target: name, port: 443, service: "https", evidence: `https://${name}/ sends neither X-Frame-Options nor a CSP frame-ancestors directive.`, remediation: "Send X-Frame-Options: DENY or CSP frame-ancestors 'self'.", references: ["CWE-1021"] });
        const leak = [h.server, h["x-powered-by"], h["x-aspnet-version"]].filter((v) => v && /\d/.test(v));
        if (leak.length) add({ title: "Server software version disclosed", severity: "low", target: name, port: 443, service: "https", evidence: `Headers name the software and version: ${leak.join("; ")}.`, remediation: "Remove version numbers from Server and X-Powered-By headers.", references: ["CWE-200"] });
      }
    }
  }

  // Email (only for the names the client listed, not every host).
  if (opts.checks.includes("email") && !(await stop())) {
    for (const t of verified.filter((x) => x.kind === "name")) {
      const name = t.value;
      const spf = (await opts.net.txt(name).catch(() => [] as string[][])).map((p) => p.join("")).filter((r) => /^v=spf1\b/i.test(r));
      const dmarc = (await opts.net.txt(`_dmarc.${name}`).catch(() => [] as string[][])).map((p) => p.join("")).filter((r) => /^v=DMARC1\b/i.test(r));
      log(name, "email", `SPF ${spf.length ? "present" : "missing"}, DMARC ${dmarc.length ? "present" : "missing"}`);
      if (!spf.length) add({ title: "No SPF record", severity: "medium", target: name, port: null, service: "email", evidence: `${name} publishes no SPF record, so anyone can send mail as it.`, remediation: "Publish SPF listing your mail senders, ending in -all.", references: [] });
      else if (/[+?]all\b|\sall\b/i.test(spf[0]) && !/-all|~all/i.test(spf[0])) add({ title: "SPF allows any sender", severity: "high", target: name, port: null, service: "email", evidence: `SPF: ${spf[0]}`, remediation: "End the SPF record in -all (or ~all while testing).", references: [] });
      else if (/~all/i.test(spf[0])) add({ title: "SPF soft-fails other senders", severity: "low", target: name, port: null, service: "email", evidence: `SPF: ${spf[0]}`, remediation: "Move to -all once DMARC reports show only your senders.", references: [] });
      if (!dmarc.length) add({ title: "No DMARC record", severity: "medium", target: name, port: null, service: "email", evidence: `_dmarc.${name} has no DMARC record, so spoofed mail isn't rejected or reported.`, remediation: "Publish DMARC (start with p=none and reports, then move to quarantine or reject).", references: [] });
      else if (/p=none/i.test(dmarc[0])) add({ title: "DMARC doesn't enforce (p=none)", severity: "low", target: name, port: null, service: "email", evidence: `DMARC: ${dmarc[0]}`, remediation: "Move to p=quarantine, then p=reject.", references: [] });
    }
  }

  const at = now();
  return { findings: out.map((f) => finding(f, at)), probes, stopped };
}
