import type { CaseSeverity, CaseSource, DetectionSource, SecurityDomain } from "@prisma/client";

// CERT-In's directions of 28 April 2022 (under section 70B(6) of the IT
// Act, in force from 27 June 2022): service providers, intermediaries, data
// centres, body corporates and government organisations report incidents of
// the types in Annexure I to CERT-In within 6 hours of noticing them or
// being told of them. This file is the list and a deterministic first pass
// over a case: it proposes the types a case looks like and why; an analyst
// confirms, and the client approves the report. Pure and client-safe.

export const CERT_IN_HOURS = 6;

export const CERT_IN_CONTACT = {
  email: "incident@cert-in.org.in",
  phone: "+91-1800-11-4949",
  web: "https://www.cert-in.org.in",
} as const;

// Annexure I, in its order and numbering.
export const CERT_IN_CATEGORIES = [
  { code: "i", label: "Targeted scanning/probing of critical networks/systems" },
  { code: "ii", label: "Compromise of critical systems/information" },
  { code: "iii", label: "Unauthorised access of IT systems/data" },
  { code: "iv", label: "Defacement of website or intrusion into a website and unauthorised changes such as inserting malicious code, links to external websites etc." },
  { code: "v", label: "Malicious code attacks such as spreading of virus/worm/Trojan/Bots/Spyware/Ransomware/Cryptominers" },
  { code: "vi", label: "Attack on servers such as Database, Mail and DNS and network devices such as Routers" },
  { code: "vii", label: "Identity Theft, spoofing and phishing attacks" },
  { code: "viii", label: "Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks" },
  { code: "ix", label: "Attacks on Critical infrastructure, SCADA and operational technology systems and Wireless networks" },
  { code: "x", label: "Attacks on Application such as E-Governance, E-Commerce etc." },
  { code: "xi", label: "Data Breach" },
  { code: "xii", label: "Data Leak" },
  { code: "xiii", label: "Attacks on Internet of Things (IoT) devices and associated systems, networks, software, servers" },
  { code: "xiv", label: "Attacks or incident affecting Digital Payment systems" },
  { code: "xv", label: "Attacks through Malicious mobile Apps" },
  { code: "xvi", label: "Fake mobile Apps" },
  { code: "xvii", label: "Unauthorised access to social media accounts" },
  { code: "xviii", label: "Attacks or malicious/suspicious activities affecting Cloud computing systems/servers/software/applications" },
  { code: "xix", label: "Attacks or malicious/suspicious activities affecting systems/servers/networks/software/applications related to Big Data, Block chain, virtual assets, virtual asset exchanges, custodian wallets, Robotics, 3D and 4D Printing, additive manufacturing, Drones" },
  { code: "xx", label: "Attacks or malicious/suspicious activities affecting systems/servers/software/applications related to Artificial Intelligence and Machine Learning" },
] as const;

export type CertInCode = (typeof CERT_IN_CATEGORIES)[number]["code"];

const CODES = new Set<string>(CERT_IN_CATEGORIES.map((c) => c.code));
export const isCertInCode = (code: string): code is CertInCode => CODES.has(code);
export const certInLabel = (code: string) => CERT_IN_CATEGORIES.find((c) => c.code === code)?.label ?? code;

export interface IncidentFacts {
  sourceType: CaseSource;
  domain: SecurityDomain | null;
  severity: CaseSeverity;
  verdict: string | null;
  // ATT&CK ids on the case (sub-techniques included, e.g. T1566.001).
  techniques: string[];
  detectionSources: DetectionSource[];
  // Detection titles and the case title, for the few types only words name.
  titles: string[];
  // The client's assets the case touches, from the inventory.
  assets: Array<{ hostname: string; assetClass: string | null; assetType: string | null; criticality: string }>;
}

export interface CertInMatch {
  code: CertInCode;
  reasons: string[];
}

const SEVERITY_RANK: Record<CaseSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
export const atLeast = (severity: CaseSeverity, min: CaseSeverity) => SEVERITY_RANK[severity] >= SEVERITY_RANK[min];

const BENIGN_VERDICTS = new Set(["clean", "benign", "false_positive"]);

// Technique → type. A parent id matches its sub-techniques.
const TECHNIQUES: Array<[string, CertInCode, string]> = [
  ["T1595", "i", "active scanning"],
  ["T1046", "i", "network service discovery"],
  ["T1078", "iii", "use of valid accounts"],
  ["T1110", "iii", "brute force against accounts"],
  ["T1133", "iii", "external remote services"],
  ["T1021", "iii", "remote services"],
  ["T1491", "iv", "defacement"],
  ["T1486", "v", "data encrypted for impact (ransomware)"],
  ["T1496", "v", "resource hijacking (cryptomining)"],
  ["T1204", "v", "user execution of a malicious file or link"],
  ["T1105", "v", "tool transfer onto the host"],
  ["T1566", "vii", "phishing"],
  ["T1598", "vii", "phishing for information"],
  ["T1656", "vii", "impersonation"],
  ["T1498", "viii", "network denial of service"],
  ["T1499", "viii", "endpoint denial of service"],
  ["T1190", "x", "exploit of a public-facing application"],
  ["T1041", "xi", "exfiltration over the command channel"],
  ["T1048", "xi", "exfiltration over another protocol"],
  ["T1567", "xi", "exfiltration to a web service"],
  ["T1537", "xi", "data moved to another cloud account"],
  ["T1530", "xviii", "data taken from cloud storage"],
  ["T1078.004", "xviii", "use of cloud accounts"],
];

const DETECTIONS: Partial<Record<DetectionSource, Array<[CertInCode, string]>>> = {
  RECONNAISSANCE: [["i", "reconnaissance detected"]],
  GEO_VELOCITY: [["iii", "sign-ins from places too far apart to travel between"]],
  CREDENTIAL_HARVESTING: [["iii", "credential theft"]],
  LATERAL_MOVEMENT: [["iii", "lateral movement between systems"]],
  DATA_EXFILTRATION: [["xi", "data exfiltration detected"]],
  AGENT_DLP: [["xii", "data loss prevention finding"]],
  EMAIL_HEADER_AUTH: [["vii", "sender authentication failed (spoofing)"]],
  EMAIL_BODY_URL: [["vii", "malicious links in an email"]],
  EMAIL_ATTACHMENT_FORENSICS: [["v", "malicious attachment"]],
  EMAIL_SANDBOX_DETONATION: [["v", "malicious behaviour in the sandbox"]],
};

const WORDS: Array<[RegExp, CertInCode, string]> = [
  [/\bdefac/i, "iv", "website defacement"],
  [/\b(ransomware|trojan|worm|botnet|spyware|cryptominer|cryptojack|malware|virus)\b/i, "v", "malicious code"],
  [/\b(ddos|denial[- ]of[- ]service)\b/i, "viii", "denial of service"],
  [/\b(phish|spoof|impersonat)/i, "vii", "phishing or spoofing"],
  [/\bdata leak|\bpublicly (exposed|accessible)|\bpublic bucket/i, "xii", "data exposed"],
];

const SERVER_TYPES: Record<string, string> = { database_server: "database server", mail_gateway: "mail system", infrastructure_server: "DNS server", router: "router", firewall: "firewall", vpn: "VPN gateway", domain_controller: "domain controller" };
const OT_TYPES = new Set(["plc", "scada", "sensor", "building", "medical"]);
const IOT_TYPES = new Set(["camera", "printer", "smart_device"]);
const APP_TYPES = new Set(["web_app", "api", "web_server", "remote_access"]);
// Signs that a system was taken over, not just looked at or sent a lure.
const COMPROMISE: DetectionSource[] = ["FSM_CHAIN", "LATERAL_MOVEMENT", "PERSISTENCE", "IMPACT", "CREDENTIAL_HARVESTING", "DATA_EXFILTRATION", "VENDOR_ALERT"];
const COMPROMISE_TECHNIQUES = /^T(1003|1021|1041|1048|1053|1055|1059|1078|1190|1485|1486|1490|1491|1496|1505|1543|1547|1567)(\.|$)/;

// The Annexure I types a case looks like, with the evidence for each. Empty
// for a case closed as benign, and for one with nothing that maps.
export function classifyIncident(f: IncidentFacts): CertInMatch[] {
  if (f.verdict && BENIGN_VERDICTS.has(f.verdict.toLowerCase())) return [];
  const found = new Map<CertInCode, Set<string>>();
  const add = (code: CertInCode, reason: string) => found.set(code, (found.get(code) ?? new Set()).add(reason));

  for (const t of f.techniques) {
    for (const [id, code, why] of TECHNIQUES) if (t === id || t.startsWith(`${id}.`)) add(code, `ATT&CK ${t}: ${why}`);
    // ATT&CK for ICS techniques are T08xx.
    if (/^T08\d\d/.test(t)) add("ix", `ATT&CK for ICS ${t}`);
  }
  for (const s of new Set(f.detectionSources)) for (const [code, why] of DETECTIONS[s] ?? []) add(code, why);
  for (const title of f.titles) for (const [re, code, why] of WORDS) if (re.test(title)) add(code, `${why} named in “${title.slice(0, 80)}”`);

  if (f.sourceType === "AGENT_GOVERNANCE" || f.domain === "AI_AGENTS") add("xx", "an AI agent or AI system is involved");
  if (f.domain === "CLOUD") add("xviii", "a cloud service is involved");
  if (f.sourceType === "EMAIL_ANALYSIS" && f.verdict?.toLowerCase() === "malicious") add("vii", "email forensics found the message malicious");

  const compromised = f.detectionSources.some((s) => COMPROMISE.includes(s)) || f.techniques.some((t) => COMPROMISE_TECHNIQUES.test(t));
  for (const a of f.assets) {
    const name = a.hostname;
    if (a.assetType && SERVER_TYPES[a.assetType] && compromised) add("vi", `${SERVER_TYPES[a.assetType]} ${name} is involved`);
    if (a.assetType && OT_TYPES.has(a.assetType)) add("ix", `operational technology ${name} is involved`);
    if (a.assetType === "access_point") add("ix", `wireless network device ${name} is involved`);
    if (a.assetType && IOT_TYPES.has(a.assetType)) add("xiii", `IoT device ${name} is involved`);
    if (a.assetType && APP_TYPES.has(a.assetType) && compromised) add("x", `application ${name} is involved`);
    if (a.assetClass === "cloud") add("xviii", `cloud asset ${name} is involved`);
    if (a.assetClass === "mobile" && found.has("v")) add("xv", `malicious code on mobile device ${name}`);
    if ((a.criticality === "critical" || a.criticality === "high") && compromised) add("ii", `${a.criticality} system ${name} shows signs of compromise`);
    if ((a.criticality === "critical" || a.criticality === "high") && found.has("i")) add("i", `the scanning reached ${a.criticality} system ${name}`);
  }

  return CERT_IN_CATEGORIES.filter((c) => found.has(c.code)).map((c) => ({ code: c.code, reasons: [...found.get(c.code)!] }));
}
