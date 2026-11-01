import { describe, expect, it } from "vitest";

import { parseXml, findAll } from "@/lib/testing/xml";
import { detectTool, parseNessus, parseNuclei, parseOpenVas, parseZap } from "@/lib/testing/imports";
import { ScopeError, inScope, parseTargets, verifyScope, type Resolver } from "@/lib/testing/scope";
import { runExposureCheck, type CertInfo, type Net } from "@/lib/testing/exposure";
import { finding, mergeFindings, severityCounts } from "@/lib/testing/findings";
import { csvCell } from "@/lib/explore/csv";

describe("XML reader for scanner reports", () => {
  it("reads elements, attributes, CDATA and entities", () => {
    const root = parseXml(`<?xml version="1.0"?><a x="1 &amp; 2"><b>t &lt;3 &#65;&#x42;</b><c><![CDATA[<raw> & stuff]]></c><d/></a>`);
    const a = root.children[0];
    expect(a.attrs.x).toBe("1 & 2");
    expect(a.children[0].text).toBe("t <3 AB");
    expect(a.children[1].text).toBe("<raw> & stuff");
    expect(a.children.map((c) => c.name)).toEqual(["b", "c", "d"]);
  });

  it("never resolves external entities or DTDs (no XXE)", () => {
    const evil = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY lol "lol">]><r>&xxe;&lol;</r>`;
    const r = parseXml(evil);
    expect(findAll(r, "r")[0].text).toBe("&xxe;&lol;");
  });

  it("stops on reports too large to be real", () => {
    expect(() => parseXml("<a>" + "<b/>".repeat(20) + "</a>", { maxNodes: 10 })).toThrow(/too large/);
  });
});

const NESSUS = `<?xml version="1.0" ?>
<NessusClientData_v2><Report name="ext">
<ReportHost name="203.0.113.10"><HostProperties><tag name="host-ip">203.0.113.10</tag><tag name="host-fqdn">vpn.example.com</tag></HostProperties>
<ReportItem port="3389" svc_name="msrdp" protocol="tcp" severity="3" pluginID="18405" pluginName="Microsoft Windows Remote Desktop Protocol Server MitM Weakness">
<synopsis>It may be possible to get access to the remote host.</synopsis><solution>Force the use of SSL as a transport layer.</solution><cve>CVE-2005-1794</cve><plugin_output>RDP on 3389</plugin_output></ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information"><description>info</description></ReportItem>
</ReportHost>
<ReportHost name="198.51.100.99"><ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="1" pluginName="SSH weak ciphers"><solution>Disable them.</solution></ReportItem></ReportHost>
</Report></NessusClientData_v2>`;

const OPENVAS = `<report id="r1"><report format_id="x"><results>
<result id="1"><name>SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection</name><host>203.0.113.10<hostname>vpn.example.com</hostname></host><port>443/tcp</port><threat>Medium</threat><severity>4.3</severity>
<description>The service supports TLSv1.0</description><nvt oid="1.3.6.1.4.1.25623.1.0.117274"><name>SSL/TLS deprecated</name><tags>summary=Old TLS|solution=Disable TLSv1.0 and TLSv1.1</tags><refs><ref type="cve" id="CVE-2011-3389"/><ref type="url" id="https://example.org/advisory"/></refs></nvt></result>
</results></report></report>`;

const ZAP = JSON.stringify({ site: [{ "@name": "https://www.example.com", "@host": "www.example.com", "@port": "443", alerts: [{ pluginid: "10038", alert: "Content Security Policy (CSP) Header Not Set", riskcode: "2", desc: "<p>CSP is missing</p>", solution: "<p>Set it</p>", reference: "<p>https://developer.mozilla.org/csp</p>", cweid: "693", instances: [{ uri: "https://www.example.com/", method: "GET" }] }] }] });

const NUCLEI = [
  JSON.stringify({ "template-id": "exposed-git", info: { name: "Exposed .git directory", severity: "high", description: "Git metadata is readable", classification: { "cwe-id": ["cwe-538"] }, reference: ["https://example.org/git"] }, host: "https://www.example.com", "matched-at": "https://www.example.com/.git/config", type: "http" }),
  JSON.stringify({ "template-id": "tech-detect", info: { name: "Tech detect", severity: "info" }, host: "other.example.net", "matched-at": "other.example.net:443" }),
].join("\n");

describe("Scanner imports", () => {
  it("recognises each scanner's report", () => {
    expect(detectTool("scan.nessus", NESSUS)).toBe("nessus");
    expect(detectTool("report.xml", OPENVAS)).toBe("openvas");
    expect(detectTool("zap.json", ZAP)).toBe("zap");
    expect(detectTool("out.jsonl", NUCLEI)).toBe("nuclei");
    expect(detectTool("x.txt", "hello")).toBeNull();
  });

  it("reads Nessus", () => {
    const f = parseNessus(NESSUS);
    expect(f).toHaveLength(3);
    expect(f[0]).toMatchObject({ severity: "high", target: "vpn.example.com", port: 3389, service: "msrdp", source: "Nessus" });
    expect(f[0].references).toContain("CVE-2005-1794");
    expect(f[0].evidence).toContain("RDP on 3389");
    expect(f[1]).toMatchObject({ severity: "info", port: null });
  });

  it("reads Greenbone/OpenVAS", () => {
    const [f] = parseOpenVas(OPENVAS);
    expect(f).toMatchObject({ severity: "medium", target: "vpn.example.com", port: 443, service: "tcp", remediation: "Disable TLSv1.0 and TLSv1.1" });
    expect(f.references).toEqual(expect.arrayContaining(["CVE-2011-3389", "https://example.org/advisory"]));
  });

  it("reads ZAP and Nuclei", () => {
    const [z] = parseZap(ZAP);
    expect(z).toMatchObject({ title: "Content Security Policy (CSP) Header Not Set", severity: "medium", target: "www.example.com", port: 443 });
    expect(z.evidence).toContain("GET https://www.example.com/");
    expect(z.references).toContain("CWE-693");
    const n = parseNuclei(NUCLEI);
    expect(n[0]).toMatchObject({ title: "Exposed .git directory", severity: "high", target: "www.example.com" });
    expect(n[0].references).toEqual(expect.arrayContaining(["CWE-538", "https://example.org/git"]));
    expect(n[1]).toMatchObject({ target: "other.example.net", port: 443 });
    expect(() => parseNuclei("{bad")).toThrow(/Line 1/);
  });
});

function resolver(records: Record<string, string[]>, addrs: Record<string, string[]>): Resolver {
  return { txt: async (n) => (records[n] ?? []).map((r) => [r]), addresses: async (n) => addrs[n] ?? [] };
}

describe("Scope", () => {
  it("accepts names, public IPs and URLs; refuses ranges and private addresses", () => {
    const t = parseTargets("example.com, vpn.example.com 203.0.113.10 https://www.example.com/login");
    expect(t.map((x) => x.kind)).toEqual(["name", "name", "ip", "url"]);
    expect(() => parseTargets("10.0.0.5")).toThrow(ScopeError);
    expect(() => parseTargets("203.0.113.0/24")).toThrow(/ranges/);
    expect(() => parseTargets("https://192.168.1.1/")).toThrow(/private/);
    expect(() => parseTargets("not a host!")).toThrow(ScopeError);
    expect(() => parseTargets(Array.from({ length: 26 }, (_, i) => `h${i}.example.com`).join(" "))).toThrow(/At most 25/);
  });

  it("verifies by DNS TXT, through parents, and IPs only through verified names", async () => {
    const token = "abc123";
    const dns = resolver(
      { "_helios-verify.example.com": ["helios-verify=abc123"], "other.net": ["helios-verify=wrong"] },
      { "example.com": ["203.0.113.1"], "vpn.example.com": ["203.0.113.10"], "www.example.com": ["203.0.113.20"], "other.net": ["198.51.100.1"], "intranet.example.com": ["10.0.0.4"] },
    );
    const t = await verifyScope(parseTargets("example.com vpn.example.com 203.0.113.10 198.51.100.1 other.net https://www.example.com/ intranet.example.com"), token, dns, new Date("2026-11-01T00:00:00Z"));
    const by = Object.fromEntries(t.map((x) => [x.value, x]));
    expect(by["example.com"]).toMatchObject({ verified: true, via: "DNS TXT on _helios-verify.example.com" });
    expect(by["vpn.example.com"]).toMatchObject({ verified: true, via: "parent name example.com is verified", addresses: ["203.0.113.10"] });
    expect(by["203.0.113.10"]).toMatchObject({ verified: true, via: "vpn.example.com resolves to it" });
    expect(by["198.51.100.1"].verified).toBe(false);
    expect(by["other.net"].verified).toBe(false);
    expect(by["https://www.example.com"].verified).toBe(true);
    // A verified name that points inside a network isn't tested from HELIOS.
    expect(by["intranet.example.com"]).toMatchObject({ verified: false });
    expect(by["intranet.example.com"].problem).toMatch(/private/);
    expect(inScope(t, "VPN.example.com")).toBe(true);
    expect(inScope(t, "203.0.113.10")).toBe(true);
    expect(inScope(t, "mail.example.com")).toBe(false);
    expect(inScope(t, "other.net")).toBe(false);
  });
});

function fakeNet(opts: { open: Record<string, number[]>; banners?: Record<string, string>; certs?: Record<string, CertInfo>; http?: Record<string, { status: number; headers: Record<string, string> }>; txt?: Record<string, string[]> }): Net & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    addresses: async () => [],
    txt: async (n) => (opts.txt?.[n] ?? []).map((r) => [r]),
    connect: async (ip, port) => {
      calls.push(`${ip}:${port}`);
      return { open: !!opts.open[ip]?.includes(port), banner: opts.banners?.[`${ip}:${port}`] ?? null };
    },
    tls: async (ip, port) => opts.certs?.[`${ip}:${port}`] ?? null,
    http: async (url) => opts.http?.[url] ?? null,
  };
}

describe("Exposure check", () => {
  const now = new Date("2026-11-01T00:00:00Z");
  const targets = [
    { value: "example.com", kind: "name" as const, verified: true, via: "DNS TXT", verifiedAt: now.toISOString(), addresses: ["203.0.113.1"], problem: null },
    { value: "198.51.100.7", kind: "ip" as const, verified: false, via: null, verifiedAt: null, addresses: ["198.51.100.7"], problem: "unverified" },
  ];

  it("reports exposed services, weak TLS, missing headers and email gaps, and touches only verified targets", async () => {
    const net = fakeNet({
      open: { "203.0.113.1": [22, 80, 443, 3389, 445] },
      banners: { "203.0.113.1:22": "SSH-2.0-OpenSSH_7.4" },
      certs: { "203.0.113.1:443": { subject: "old.example.org", issuer: "Example CA", validTo: "2026-10-20T00:00:00.000Z", names: ["old.example.org"], selfSigned: false, authorized: false, authorizationError: "CERT_HAS_EXPIRED", protocol: "TLSv1.1" } },
      http: { "http://example.com/": { status: 200, headers: {} }, "https://example.com/": { status: 200, headers: { server: "Apache/2.4.49", "x-content-type-options": "nosniff" } } },
      txt: { "example.com": ["v=spf1 include:_spf.example.net +all"], "_dmarc.example.com": ["v=DMARC1; p=none"] },
    });
    const r = await runExposureCheck(targets, { checks: ["services", "tls", "web", "email"], net, now: () => now });
    expect(net.calls.every((c) => c.startsWith("203.0.113.1:"))).toBe(true);
    const titles = r.findings.map((f) => `${f.severity}: ${f.title}`);
    expect(titles).toEqual(expect.arrayContaining([
      "critical: SMB file sharing reachable from the internet",
      "high: Remote Desktop reachable from the internet",
      "low: SSH reachable from the internet",
      "high: TLS certificate expired",
      "high: TLS certificate doesn't match the name",
      "high: Outdated TLS protocol (TLSv1.1)",
      "medium: HTTP doesn't redirect to HTTPS",
      "medium: No HSTS header",
      "low: Server software version disclosed",
      "high: SPF allows any sender",
      "low: DMARC doesn't enforce (p=none)",
    ]));
    expect(r.findings.find((f) => f.port === 22)?.evidence).toContain("OpenSSH_7.4");
    expect(r.findings.some((f) => f.title === "No X-Content-Type-Options header")).toBe(false);
    expect(r.probes.length).toBeGreaterThan(5);
  });

  it("stops when told to (window closed, or cancelled)", async () => {
    const net = fakeNet({ open: { "203.0.113.1": [3389] } });
    let n = 0;
    const r = await runExposureCheck(targets, { checks: ["services", "tls", "web", "email"], net, now: () => now, concurrency: 1, shouldStop: async () => (++n > 3 ? "cancelled" : null) });
    expect(r.stopped).toBe("cancelled");
    expect(net.calls.length).toBeLessThanOrEqual(3);
  });
});

describe("Findings across runs", () => {
  const t0 = new Date("2026-11-01T00:00:00Z");
  const t1 = new Date("2026-11-02T00:00:00Z");
  const mk = (title: string, severity: "high" | "low", source = "HELIOS exposure check") => finding({ title, severity, target: "203.0.113.1", port: 3389, service: null, evidence: "", remediation: "", references: [], source }, t0);

  it("keeps accepted risks, marks what a re-test no longer finds as fixed, and adds new ones", () => {
    const rdp = mk("RDP open", "high");
    const ssh = mk("SSH open", "low");
    const nessus = mk("Nessus thing", "high", "Nessus");
    const before = [{ ...rdp }, { ...ssh, status: "accepted" as const, statusNote: "Jump host" }, nessus];
    const after = mergeFindings(before, [{ ...ssh, lastSeen: t1.toISOString() }, mk("Telnet open", "high")], (f) => f.source === "HELIOS exposure check", t1);
    const by = Object.fromEntries(after.map((f) => [f.title, f]));
    expect(by["RDP open"].status).toBe("fixed");
    expect(by["SSH open"]).toMatchObject({ status: "accepted", statusNote: "Jump host" });
    expect(by["Telnet open"].status).toBe("open");
    // Another tool's finding isn't judged by this run.
    expect(by["Nessus thing"].status).toBe("open");
    expect(severityCounts(after)).toMatchObject({ high: 2, low: 0 });
    // A run that didn't look at a target proves nothing about it.
    expect(mergeFindings(before, [], () => false, t1).find((f) => f.title === "RDP open")?.status).toBe("open");
  });

  it("keeps report cells safe when exported", () => {
    expect(csvCell("=cmd|' /C calc'!A0")).toMatch(/^"?'=/);
  });
});
