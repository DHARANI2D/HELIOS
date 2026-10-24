import type { IngestFormat } from "@/lib/integrations/catalog";

// TEST FIXTURES — synthetic payloads in each vendor's own shape, for the
// mapper tests and `npm run db:seed:test`. Never used by the running app.

const NOW = () => new Date().toISOString();
const HASH = "3f8a1c0e9b7d6a5f4e3d2c1b0a9f8e7d6c5b4a3928170f6e5d4c3b2a19087f6e";

const SAMPLES: Record<IngestFormat, () => unknown> = {
  crowdstrike: () => ({
    metadata: { eventType: "DetectionSummaryEvent", eventCreationTime: Date.now() },
    event: {
      DetectId: `ldt:${Math.random().toString(16).slice(2, 14)}`,
      DetectName: "Credential Theft via LSASS memory access",
      DetectDescription: "A process accessed LSASS memory in a manner consistent with Mimikatz sekurlsa::logonpasswords.",
      Severity: 5,
      SeverityName: "Critical",
      ComputerName: "FIN-LAPTOP-07",
      UserName: "j.alvarez",
      FileName: "rundll32.exe",
      CommandLine: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\Public\\lsass.dmp full",
      SHA256String: HASH,
      Tactic: "Credential Access",
      Technique: "OS Credential Dumping",
      TechniqueId: "T1003.001",
      LocalIP: "10.20.4.17",
    },
  }),
  defender: () => ({
    value: [
      {
        id: `da${Math.random().toString(16).slice(2, 14)}`,
        title: "Suspicious PowerShell download cradle",
        severity: "high",
        description: "An encoded PowerShell command downloaded and executed a payload from a rare external domain.",
        createdDateTime: NOW(),
        mitreTechniques: ["T1059.001", "T1105"],
        evidence: [
          { "@odata.type": "#microsoft.graph.security.deviceEvidence", deviceDnsName: "HR-DESKTOP-12.corp.helios.test" },
          { "@odata.type": "#microsoft.graph.security.userEvidence", userAccount: { accountName: "m.chen" } },
          { "@odata.type": "#microsoft.graph.security.ipEvidence", ipAddress: "185.220.101.34" },
          { "@odata.type": "#microsoft.graph.security.processEvidence", imageFile: { fileName: "powershell.exe" }, processCommandLine: "powershell -nop -w hidden -enc SQBFAFgA..." },
        ],
      },
    ],
  }),
  sentinelone: () => ({
    data: [
      {
        id: String(Date.now()),
        threatInfo: {
          threatId: String(Date.now()),
          threatName: "LockBit.Ransom",
          classification: "Ransomware",
          confidenceLevel: "malicious",
          sha256: HASH,
          originatorProcess: "svchost_update.exe",
          createdAt: NOW(),
          mitigationStatus: "not_mitigated",
        },
        agentRealtimeInfo: { agentComputerName: "FILESRV-02" },
        agentDetectionInfo: { agentIpV4: "10.20.1.5", agentLastLoggedInUserName: "svc_backup" },
      },
    ],
  }),
  wazuh: () => [
    {
      id: String(Date.now()),
      timestamp: NOW(),
      rule: { level: 12, description: "Possible credential dumping: Mimikatz command line", mitre: { id: ["T1003"] } },
      agent: { name: "WEB-PROD-03", ip: "10.20.8.30" },
      data: { srcip: "185.220.101.34", win: { eventdata: { image: "C:\\Temp\\m.exe", commandLine: "m.exe privilege::debug sekurlsa::logonpasswords exit", user: "web_admin" } } },
    },
    {
      timestamp: NOW(),
      rule: { level: 3, description: "Windows logon success" },
      agent: { name: "WEB-PROD-03" },
      data: { srcuser: "web_admin" },
    },
  ],
  entra: () => [
    { id: String(Date.now()), riskEventType: "unfamiliarFeatures", riskLevel: "high", userPrincipalName: "cfo@corp.helios.test", ipAddress: "185.220.101.34", detectedDateTime: NOW() },
    { userPrincipalName: "cfo@corp.helios.test", ipAddress: "185.220.101.34", status: { errorCode: 0 }, location: { countryOrRegion: "RO" }, createdDateTime: NOW() },
  ],
  okta: () =>
    Array.from({ length: 6 }, (_, i) => ({
      eventType: "user.session.start",
      actor: { alternateId: "a.patel@corp.helios.test" },
      client: { ipAddress: "203.0.113.77", geographicalContext: { country: "Brazil" } },
      outcome: { result: i < 5 ? "FAILURE" : "SUCCESS" },
      published: new Date(Date.now() - (6 - i) * 20_000).toISOString(),
    })),
  generic: () => ({
    title: "Outbound connection to known C2 infrastructure",
    severity: "high",
    host: "OPS-LAPTOP-21",
    user: "r.okafor",
    dest_ip: "185.220.101.34",
    technique: "T1071.001",
    timestamp: NOW(),
  }),
};

// Email gateways report message-level alerts, not device alerts.
const EMAIL_SAMPLE = () => ({
  value: [
    {
      id: `fa${Math.random().toString(16).slice(2, 14)}`,
      title: "Email messages containing malicious URL removed after delivery",
      severity: "high",
      description: "A credential-phishing link impersonating Microsoft 365 sign-in was delivered to 14 mailboxes; ZAP removed it. One user clicked.",
      createdDateTime: NOW(),
      mitreTechniques: ["T1566.002"],
      evidence: [
        { "@odata.type": "#microsoft.graph.security.mailboxEvidence", userAccount: { accountName: "l.nguyen", userPrincipalName: "l.nguyen@corp.helios.test" } },
        { "@odata.type": "#microsoft.graph.security.urlEvidence", url: "https://login-microsoft365-secure.helios.test/verify" },
        { "@odata.type": "#microsoft.graph.security.ipEvidence", ipAddress: "185.220.101.34" },
      ],
    },
  ],
});

export function samplePayloadFor(tool: { ingest: IngestFormat | null; category: string }): unknown | null {
  if (!tool.ingest) return null;
  if (tool.category === "email" && tool.ingest === "defender") return EMAIL_SAMPLE();
  return SAMPLES[tool.ingest]();
}
