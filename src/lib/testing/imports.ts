import { child, childrenNamed, findAll, parseXml, textOf, XmlError } from "@/lib/testing/xml";
import type { FindingSeverity, NewFinding } from "@/lib/testing/findings";

// Results from established scanners, brought into a test's report: Tenable
// Nessus (.nessus), Greenbone/OpenVAS (XML report), OWASP ZAP (JSON
// report) and ProjectDiscovery Nuclei (JSON lines). The scans themselves
// run in the client's or the SOC's own scanner under the same written
// authorisation; HELIOS reads the results, keeps what's in scope and
// reports it with everything else.

export const IMPORT_TOOLS = {
  nessus: { label: "Tenable Nessus (.nessus)" },
  openvas: { label: "Greenbone / OpenVAS (XML report)" },
  zap: { label: "OWASP ZAP (JSON report)" },
  nuclei: { label: "Nuclei (JSON lines)" },
} as const;
export type ImportTool = keyof typeof IMPORT_TOOLS;

export class ImportError extends Error {}

export function detectTool(name: string, text: string): ImportTool | null {
  const head = text.slice(0, 4000);
  if (/\.nessus$/i.test(name) || head.includes("<NessusClientData_v2")) return "nessus";
  if (/<report[\s>]/i.test(head) && (head.includes("<results") || head.includes("openvas") || head.includes("gmp") || head.includes("<nvt"))) return "openvas";
  if (/^\s*\{/.test(head) && head.includes('"site"')) return "zap";
  if (/^\s*\{/.test(head) && (head.includes('"template-id"') || head.includes('"templateID"'))) return "nuclei";
  return null;
}

const NESSUS_SEV: Record<string, FindingSeverity> = { "0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical" };
const ZAP_SEV: Record<string, FindingSeverity> = { "0": "info", "1": "low", "2": "medium", "3": "high" };

function cvssSeverity(score: number): FindingSeverity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

const portOf = (s: string | undefined) => {
  const n = Number(/^(\d+)/.exec(s ?? "")?.[1]);
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : null;
};

const strip = (s: string) => s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();

export function parseNessus(text: string): NewFinding[] {
  const root = parseXml(text);
  const out: NewFinding[] = [];
  for (const host of findAll(root, "ReportHost")) {
    const props = Object.fromEntries(childrenNamed(child(host, "HostProperties"), "tag").map((t) => [t.attrs.name, t.text.trim()]));
    const target = props["host-fqdn"] || props["host-ip"] || host.attrs.name;
    for (const item of childrenNamed(host, "ReportItem")) {
      const severity = NESSUS_SEV[item.attrs.severity ?? "0"] ?? "info";
      out.push({
        title: item.attrs.pluginName || textOf(item, "plugin_name") || `Nessus plugin ${item.attrs.pluginID}`,
        severity,
        target,
        port: portOf(item.attrs.port) || null,
        service: item.attrs.svc_name || null,
        evidence: [textOf(item, "synopsis"), textOf(item, "plugin_output")].filter(Boolean).join("\n\n") || textOf(item, "description"),
        remediation: textOf(item, "solution") || "See the vendor's advisory.",
        references: [...childrenNamed(item, "cve").map((c) => c.text.trim()), ...childrenNamed(item, "see_also").flatMap((c) => c.text.split(/\s+/)), `Nessus plugin ${item.attrs.pluginID}`],
        source: "Nessus",
      });
    }
  }
  return out;
}

export function parseOpenVas(text: string): NewFinding[] {
  const root = parseXml(text);
  const out: NewFinding[] = [];
  for (const r of findAll(root, "result")) {
    const host = child(r, "host");
    if (!host) continue;
    const nvt = child(r, "nvt");
    const score = Number(textOf(r, "severity") || textOf(nvt, "cvss_base"));
    const threat = textOf(r, "threat").toLowerCase();
    const severity: FindingSeverity = Number.isFinite(score) && score > 0 ? cvssSeverity(score) : threat === "high" ? "high" : threat === "medium" ? "medium" : threat === "low" ? "low" : "info";
    const tags = Object.fromEntries((textOf(nvt, "tags") || "").split("|").map((kv) => { const i = kv.indexOf("="); return [kv.slice(0, i), kv.slice(i + 1)]; }));
    const hostname = textOf(host, "hostname");
    const port = textOf(r, "port");
    out.push({
      title: textOf(r, "name") || textOf(nvt, "name") || "Greenbone finding",
      severity,
      target: hostname || host.text.trim(),
      port: portOf(port),
      service: port.includes("/") ? port.split("/")[1] || null : null,
      evidence: textOf(r, "description") || tags.summary || "",
      remediation: textOf(nvt, "solution") || tags.solution || "See the vendor's advisory.",
      references: [...findAll(nvt ?? r, "ref").filter((x) => ["cve", "url", "cert-bund", "dfn-cert"].includes(x.attrs.type)).map((x) => x.attrs.id), ...(nvt?.attrs.oid ? [`NVT ${nvt.attrs.oid}`] : [])],
      source: "Greenbone/OpenVAS",
    });
  }
  return out;
}

interface ZapAlert {
  pluginid?: string;
  alert?: string;
  name?: string;
  riskcode?: string;
  desc?: string;
  solution?: string;
  reference?: string;
  cweid?: string;
  instances?: Array<{ uri?: string; method?: string; param?: string; evidence?: string }>;
}

export function parseZap(text: string): NewFinding[] {
  let data: { site?: Array<{ "@name"?: string; "@host"?: string; "@port"?: string; alerts?: ZapAlert[] }> };
  try {
    data = JSON.parse(text);
  } catch {
    throw new ImportError("That isn't a ZAP JSON report");
  }
  const out: NewFinding[] = [];
  for (const site of data.site ?? []) {
    let host = site["@host"] ?? "";
    try {
      host = host || new URL(site["@name"] ?? "").hostname;
    } catch {
      // keep what there is
    }
    for (const a of site.alerts ?? []) {
      const inst = (a.instances ?? []).slice(0, 5);
      out.push({
        title: a.alert || a.name || `ZAP rule ${a.pluginid}`,
        severity: ZAP_SEV[a.riskcode ?? "0"] ?? "info",
        target: host,
        port: portOf(site["@port"]),
        service: "http",
        evidence: [strip(a.desc ?? ""), ...inst.map((i) => `${i.method ?? "GET"} ${i.uri ?? ""}${i.param ? ` (${i.param})` : ""}${i.evidence ? `: ${i.evidence}` : ""}`)].filter(Boolean).join("\n"),
        remediation: strip(a.solution ?? "") || "See the ZAP alert's reference.",
        references: [...(a.cweid && a.cweid !== "-1" ? [`CWE-${a.cweid}`] : []), ...strip(a.reference ?? "").split(/\s+/).filter((r) => r.startsWith("http")), `ZAP rule ${a.pluginid}`],
        source: "OWASP ZAP",
      });
    }
  }
  return out;
}

export function parseNuclei(text: string): NewFinding[] {
  const out: NewFinding[] = [];
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  for (const [i, line] of lines.entries()) {
    let r: { "template-id"?: string; templateID?: string; host?: string; "matched-at"?: string; matched?: string; ip?: string; port?: string; type?: string; info?: { name?: string; severity?: string; description?: string; remediation?: string; reference?: string[] | string; classification?: { "cve-id"?: string[] | string; "cwe-id"?: string[] | string } }; "extracted-results"?: string[] };
    try {
      r = JSON.parse(line);
    } catch {
      throw new ImportError(`Line ${i + 1} isn't JSON (Nuclei writes one finding per line with -jsonl)`);
    }
    const matched = r["matched-at"] ?? r.matched ?? r.host ?? "";
    let host = r.host ?? matched;
    try {
      host = new URL(/^\w+:\/\//.test(host) ? host : `x://${host}`).hostname;
    } catch {
      // keep
    }
    const sev = (r.info?.severity ?? "info").toLowerCase();
    const list = (v: string[] | string | undefined) => (Array.isArray(v) ? v : v ? [v] : []);
    out.push({
      title: r.info?.name || r["template-id"] || r.templateID || "Nuclei finding",
      severity: (["critical", "high", "medium", "low", "info"].includes(sev) ? sev : "info") as FindingSeverity,
      target: host,
      port: portOf(r.port) ?? portOf(/:(\d+)(?:\/|$)/.exec(matched)?.[1]),
      service: r.type ?? null,
      evidence: [`Matched at ${matched}`, r.info?.description ?? "", ...(r["extracted-results"] ?? []).slice(0, 5)].filter(Boolean).join("\n"),
      remediation: r.info?.remediation || "See the template's references.",
      references: [...list(r.info?.classification?.["cve-id"]).map((c) => c.toUpperCase()), ...list(r.info?.classification?.["cwe-id"]).map((c) => c.toUpperCase()), ...list(r.info?.reference), `Nuclei template ${r["template-id"] ?? r.templateID}`],
      source: "Nuclei",
    });
  }
  return out;
}

export function parseImport(tool: ImportTool, text: string): NewFinding[] {
  try {
    switch (tool) {
      case "nessus":
        return parseNessus(text);
      case "openvas":
        return parseOpenVas(text);
      case "zap":
        return parseZap(text);
      case "nuclei":
        return parseNuclei(text);
    }
  } catch (err) {
    if (err instanceof XmlError) throw new ImportError(`The report isn't valid XML: ${err.message}`);
    throw err;
  }
}
