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
  // Fluent Bit records from the HELIOS forwarder: an RDP password-guessing
  // burst that succeeds, shadow copies deleted, and a firewall deny.
  forwarder: () => {
    const host = "FIN-WS-04.corp.helios.test";
    const at = (secondsAgo: number) => {
      const d = new Date(Date.now() - secondsAgo * 1000);
      return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 19)} +0000`;
    };
    const inserts = (n: number, set: Record<number, string>) => Array.from({ length: n }, (_, i) => set[i] ?? "-");
    const win = (id: number, rec: number, secondsAgo: number, data: string[]) => ({
      ProviderName: "Microsoft-Windows-Security-Auditing", EventID: id, Level: 0, TimeCreated: at(secondsAgo), EventRecordID: rec,
      Channel: "Security", Computer: host, UserID: "", Message: "", StringInserts: data, helios_input: "windows",
    });
    return [
      ...Array.from({ length: 6 }, (_, i) => win(4625, 88100 + i, 120 - i * 10, inserts(21, { 5: "administrator", 6: "CORP", 7: "0xc000006d", 8: "%%2313", 10: "10", 12: "NTLM", 13: "KALI", 19: "203.0.113.50", 20: "50211" }))),
      win(4624, 88110, 50, inserts(23, { 5: "administrator", 6: "CORP", 8: "10", 10: "Negotiate", 11: "KALI", 18: "203.0.113.50", 19: "50240" })),
      win(4688, 88111, 30, inserts(15, { 1: "administrator", 2: "CORP", 4: "0x1a2c", 5: "C:\\Windows\\System32\\vssadmin.exe", 7: "0x9f0", 8: "vssadmin.exe delete shadows /all /quiet", 13: "C:\\Windows\\System32\\cmd.exe" })),
      { pri: "189", time: new Date().toISOString(), host: "FGT-EDGE-01", ident: "", message: 'date=2026-10-26 time=10:00:00 devname="FGT-EDGE-01" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.20.4.17 srcport=51544 dstip=185.220.101.34 dstport=443 proto=6 action="deny" policyid=12 service="HTTPS"', timestamp: new Date().toISOString(), helios_input: "syslog" },
    ];
  },
  // A CloudTrail log file: a failed console sign-in, then logging stopped.
  cloudtrail: () => ({
    Records: [
      { eventVersion: "1.09", eventTime: NOW(), eventSource: "signin.amazonaws.com", eventName: "ConsoleLogin", eventType: "AwsConsoleSignIn", awsRegion: "ap-south-1", sourceIPAddress: "203.0.113.50", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::111122223333:user/ops-admin", accountId: "111122223333", userName: "ops-admin" }, responseElements: { ConsoleLogin: "Failure" }, additionalEventData: { MFAUsed: "No" }, errorMessage: "Failed authentication", eventID: `ct-${Date.now()}-1`, recipientAccountId: "111122223333" },
      { eventVersion: "1.09", eventTime: NOW(), eventSource: "cloudtrail.amazonaws.com", eventName: "StopLogging", eventType: "AwsApiCall", awsRegion: "ap-south-1", sourceIPAddress: "203.0.113.50", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::111122223333:user/ops-admin", accountId: "111122223333", userName: "ops-admin", accessKeyId: "AKIAEXAMPLETEST0001" }, requestParameters: { name: "org-trail" }, eventID: `ct-${Date.now()}-2`, recipientAccountId: "111122223333" },
    ],
  }),
  // A Pub/Sub push delivery of a Cloud Audit Logs entry.
  gcp_audit: () => ({
    message: {
      messageId: String(Date.now()),
      data: Buffer.from(JSON.stringify({
        insertId: `gcp-${Date.now()}`, timestamp: NOW(), logName: "projects/helios-test/logs/cloudaudit.googleapis.com%2Factivity", severity: "NOTICE",
        resource: { type: "gcs_bucket", labels: { project_id: "helios-test", bucket_name: "finance-exports" } },
        protoPayload: { "@type": "type.googleapis.com/google.cloud.audit.AuditLog", serviceName: "storage.googleapis.com", methodName: "storage.setIamPermissions", resourceName: "projects/_/buckets/finance-exports", authenticationInfo: { principalEmail: "ops-admin@corp.helios.test" }, requestMetadata: { callerIp: "203.0.113.50" }, status: {} },
      })).toString("base64"),
    },
    subscription: "projects/helios-test/subscriptions/helios-audit",
  }),
  // The Activity Log REST API's list response.
  azure_activity: () => ({
    value: [
      { eventDataId: `az-${Date.now()}`, eventTimestamp: NOW(), caller: "ops-admin@corp.helios.test", level: "Informational", operationName: { value: "Microsoft.Authorization/roleAssignments/write", localizedValue: "Create role assignment" }, resourceProviderName: { value: "Microsoft.Authorization" }, status: { value: "Succeeded" }, subscriptionId: "00000000-0000-0000-0000-000000000000", resourceId: "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleAssignments/1", httpRequest: { clientIpAddress: "203.0.113.50", method: "PUT" }, category: { value: "Administrative" } },
    ],
  }),
  // The Reports API's login activities: two failures, then a suspicious login.
  google_workspace: () => ({
    items: ["login_failure", "login_failure", "suspicious_login"].map((name, i) => ({
      kind: "admin#reports#activity",
      id: { time: new Date(Date.now() - (3 - i) * 15_000).toISOString(), uniqueQualifier: `${Date.now()}${i}`, applicationName: "login", customerId: "C0test" },
      actor: { email: "a.patel@corp.helios.test", profileId: "1001" },
      ipAddress: "203.0.113.77",
      events: [{ type: name === "suspicious_login" ? "account_warning" : "login", name, parameters: [{ name: "login_type", value: "google_password" }] }],
    })),
  }),
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
