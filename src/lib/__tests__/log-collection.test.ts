import { createVerify, generateKeyPairSync } from "node:crypto";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";

import type { Http, HttpRequest } from "@/lib/connectors/http";
import type { ConnectorCtx } from "@/lib/connectors/types";
import { entraCollector, defenderCollector, azureCollector } from "@/lib/collectors/vendors/microsoft";
import { crowdstrikeCollector, nextLink, oktaCollector, sentineloneCollector } from "@/lib/collectors/vendors/saas";
import { cloudtrailCollector, gcpCollector, s3Objects, workspaceCollector } from "@/lib/collectors/vendors/clouds";
import { COLLECTORS, collectorForTool, streamByKey } from "@/lib/collectors/registry";
import { signAws } from "@/lib/collectors/auth";
import { configHashOf, renderConfig, verifyConfig, type ForwarderOptions } from "@/lib/forwarder/config";
import { median, quietLimit } from "@/lib/ingest/health";
import { mapRecord } from "@/lib/integrations/mappers";

type Reply = { status?: number; data: unknown; headers?: Record<string, string> };

function fake(handler: (url: string, req: HttpRequest) => Reply) {
  const calls: Array<{ url: string; req: HttpRequest }> = [];
  const http = (async (url: string, req: HttpRequest = {}) => {
    calls.push({ url, req });
    const r = handler(url, req);
    return { status: r.status ?? 200, data: r.data, headers: new Headers(r.headers ?? {}) };
  }) as Http;
  return { http, calls };
}

const ctxOf = (http: Http, config: Record<string, string>, secrets: Record<string, string>): ConnectorCtx => ({ http, config, secrets, cacheKey: `t-${Math.random()}` });
const NOW = new Date("2026-10-26T06:00:00Z");
const msToken = (url: string): Reply | null => (url.includes("login.microsoftonline.com") ? { data: { access_token: "ms-token", expires_in: 3600 } } : null);
const MS = { tenantId: "t1", clientId: "c1" };

describe("Microsoft collectors", () => {
  it("polls sign-ins from the checkpoint, follows next links, then moves the checkpoint to the newest record", async () => {
    const { http, calls } = fake((url) => {
      return (
        msToken(url) ??
        (url.includes("skiptoken")
          ? { data: { value: [{ id: "s3", createdDateTime: "2026-10-26T05:40:00Z" }] } }
          : { data: { value: [{ id: "s1", createdDateTime: "2026-10-26T05:59:00Z" }, { id: "s2", createdDateTime: "2026-10-26T05:50:00Z" }], "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc" } })
      );
    });
    const stream = entraCollector.streams[0];
    const ctx = ctxOf(http, MS, { clientSecret: "s" });
    const first = await stream.poll(ctx, JSON.stringify({ since: "2026-10-26T05:30:00Z" }), { now: NOW });
    const query = decodeURIComponent(calls[1].url);
    expect(query).toContain("auditLogs/signIns?$filter=createdDateTime ge 2026-10-26T05:15:00.000Z");
    expect(calls[1].req.headers?.authorization).toBe("Bearer ms-token");
    expect(first).toMatchObject({ more: true, records: [{ id: "s1" }, { id: "s2" }] });
    const second = await stream.poll(ctx, first.cursor, { now: NOW });
    expect(calls[2].url).toContain("$skiptoken=abc");
    expect(second.more).toBe(false);
    expect(JSON.parse(second.cursor!)).toEqual({ since: "2026-10-26T05:59:00Z" });
    // A next link to another host is never followed with the client's token.
    await expect(stream.poll(ctx, JSON.stringify({ since: "2026-10-26T05:30:00Z", next: "https://evil.example/steal" }), { now: NOW })).rejects.toThrow(/Refusing/);
  });

  it("reads Defender alerts and the Azure Activity Log with the right scopes", async () => {
    const scopes: string[] = [];
    const { http, calls } = fake((url, req) => {
      if (url.includes("login.microsoftonline.com")) {
        scopes.push(req.form!.scope);
        return { data: { access_token: "x", expires_in: 3600 } };
      }
      return { data: { value: [] } };
    });
    await defenderCollector.streams[0].poll(ctxOf(http, MS, { clientSecret: "s" }), null, { now: NOW });
    expect(decodeURIComponent(calls[1].url)).toContain("security/alerts_v2?$filter=lastUpdateDateTime ge");
    await azureCollector.streams[0].poll(ctxOf(http, { ...MS, subscriptionId: "sub-1" }, { clientSecret: "s" }), null, { now: NOW });
    expect(decodeURIComponent(calls[3].url)).toMatch(/subscriptions\/sub-1\/providers\/Microsoft\.Insights\/eventtypes\/management\/values\?api-version=2015-04-01&\$filter=eventTimestamp ge '.+' and eventTimestamp le '2026-10-26T06:00:00.000Z'/);
    expect(scopes).toEqual(["https://graph.microsoft.com/.default", "https://management.azure.com/.default"]);
  });
});

describe("SaaS collectors", () => {
  it("polls the Okta System Log in polling mode and keeps its next link as the checkpoint", async () => {
    const { http, calls } = fake(() => ({ data: [{ uuid: "u1" }], headers: { link: '<https://acme.okta.com/api/v1/logs?limit=1000&after=1729>; rel="next", <https://acme.okta.com/api/v1/logs?limit=1000>; rel="self"' } }));
    const r = await oktaCollector.streams[0].poll(ctxOf(http, { orgUrl: "https://acme.okta.com/" }, { apiToken: "tok" }), null, { now: NOW });
    expect(calls[0].url).toMatch(/^https:\/\/acme\.okta\.com\/api\/v1\/logs\?since=.+&sortOrder=ASCENDING&limit=1000$/);
    expect(calls[0].req.headers?.authorization).toBe("SSWS tok");
    expect(r).toMatchObject({ cursor: "https://acme.okta.com/api/v1/logs?limit=1000&after=1729", more: false });
    await oktaCollector.streams[0].poll(ctxOf(http, { orgUrl: "https://acme.okta.com" }, { apiToken: "tok" }), r.cursor, { now: NOW });
    expect(calls[1].url).toBe("https://acme.okta.com/api/v1/logs?limit=1000&after=1729");
    expect(nextLink('<https://x/a>; rel="self"')).toBeUndefined();
  });

  it("queries Falcon alert ids, then fetches them, and advances past the newest", async () => {
    const { http, calls } = fake((url) => {
      if (url.endsWith("/oauth2/token")) return { data: { access_token: "f", expires_in: 1800 } };
      if (url.includes("/alerts/queries/alerts/v2")) return { data: { resources: ["c1", "c2"] } };
      return { data: { resources: [{ composite_id: "c1", updated_timestamp: "2026-10-26T05:10:00Z" }, { composite_id: "c2", updated_timestamp: "2026-10-26T05:20:00Z" }] } };
    });
    const r = await crowdstrikeCollector.streams[0].poll(ctxOf(http, { clientId: "id" }, { clientSecret: "s" }), JSON.stringify({ since: "2026-10-26T05:00:00Z" }), { now: NOW });
    expect(decodeURIComponent(calls[1].url)).toContain("filter=updated_timestamp:>='2026-10-26T05:00:00Z'&sort=updated_timestamp|asc&limit=500");
    expect(calls[2]).toMatchObject({ url: "https://api.crowdstrike.com/alerts/entities/alerts/v2", req: { json: { composite_ids: ["c1", "c2"] } } });
    expect(JSON.parse(r.cursor!)).toEqual({ since: "2026-10-26T05:20:00Z" });
  });

  it("pages SentinelOne threats by cursor", async () => {
    const { http, calls } = fake(() => ({ data: { data: [{ threatInfo: { createdAt: "2026-10-26T05:30:00Z" } }], pagination: { nextCursor: "YWJj" } } }));
    const r = await sentineloneCollector.streams[0].poll(ctxOf(http, { consoleUrl: "https://usea1-acme.sentinelone.net" }, { apiToken: "t" }), null, { now: NOW });
    expect(calls[0].url).toMatch(/\/web\/api\/v2\.1\/threats\?createdAt__gte=.+&sortBy=createdAt&sortOrder=asc&limit=200$/);
    expect(calls[0].req.headers?.authorization).toBe("ApiToken t");
    expect(r.more).toBe(true);
    await sentineloneCollector.streams[0].poll(ctxOf(http, { consoleUrl: "https://usea1-acme.sentinelone.net" }, { apiToken: "t" }), r.cursor, { now: NOW });
    expect(calls[1].url).toContain("cursor=YWJj");
  });
});

describe("cloud collectors", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const saKey = JSON.stringify({ type: "service_account", client_email: "helios@proj.iam.gserviceaccount.com", private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString() });

  it("signs a service-account JWT, impersonating the Workspace admin", async () => {
    let assertion = "";
    const { http, calls } = fake((url, req) => {
      if (url === "https://oauth2.googleapis.com/token") {
        assertion = req.form!.assertion;
        return { data: { access_token: "g", expires_in: 3600 } };
      }
      return { data: { items: [{ id: { time: "2026-10-26T05:00:00Z" } }], nextPageToken: "p2" } };
    });
    const r = await workspaceCollector.streams[0].poll(ctxOf(http, { adminEmail: "admin@acme.example" }, { serviceAccountKey: saKey }), null, { now: NOW });
    const [h, c, s] = assertion.split(".");
    const claims = JSON.parse(Buffer.from(c, "base64url").toString());
    expect(claims).toMatchObject({ iss: "helios@proj.iam.gserviceaccount.com", sub: "admin@acme.example", scope: "https://www.googleapis.com/auth/admin.reports.audit.readonly", aud: "https://oauth2.googleapis.com/token" });
    expect(createVerify("RSA-SHA256").update(`${h}.${c}`).verify(publicKey, Buffer.from(s, "base64url"))).toBe(true);
    expect(calls[1].url).toContain("/admin/reports/v1/activity/users/all/applications/login?startTime=");
    expect(r.more).toBe(true);
  });

  it("pulls the Pub/Sub subscription and acknowledges only on commit, never in a test", async () => {
    const { http, calls } = fake((url) => (url.includes("oauth2") ? { data: { access_token: "g", expires_in: 3600 } } : url.endsWith(":pull") ? { data: { receivedMessages: [{ ackId: "a1", message: { data: "e30=" } }] } } : { data: {} }));
    const ctx = ctxOf(http, { projectId: "p", subscription: "s" }, { serviceAccountKey: saKey });
    const r = await gcpCollector.streams[0].poll(ctx, null, { now: NOW });
    expect(r.records).toHaveLength(1);
    expect(calls.some((c) => c.url.endsWith(":acknowledge"))).toBe(false);
    await r.commit!();
    expect(calls.at(-1)).toMatchObject({ url: "https://pubsub.googleapis.com/v1/projects/p/subscriptions/s:acknowledge", req: { json: { ackIds: ["a1"] } } });
    expect((await gcpCollector.streams[0].poll(ctx, null, { now: NOW, test: true })).commit).toBeUndefined();
  });

  it("reads CloudTrail files named in SQS, then deletes the messages on commit", async () => {
    const file = gzipSync(JSON.stringify({ Records: [{ eventID: "e1", eventName: "ConsoleLogin" }, { eventID: "e2", eventName: "StopLogging" }] }));
    const notification = JSON.stringify({ Records: [{ eventName: "ObjectCreated:Put", awsRegion: "ap-south-1", s3: { bucket: { name: "trail-bucket" }, object: { key: "AWSLogs/111122223333/CloudTrail/ap-south-1/2026/10/26/f+1.json.gz" } } }] });
    const { http, calls } = fake((url, req) => {
      if (url.startsWith("https://sqs.")) return { data: req.headers!["x-amz-target"] === "AmazonSQS.ReceiveMessage" ? { Messages: [{ MessageId: "m1", ReceiptHandle: "rh1", Body: notification }] } : {} };
      return { data: file };
    });
    const ctx = ctxOf(http, { region: "ap-south-1", queueUrl: "https://sqs.ap-south-1.amazonaws.com/111122223333/q", accessKeyId: "AKIDEXAMPLE" }, { secretAccessKey: "secret" });
    const r = await cloudtrailCollector.streams[0].poll(ctx, null, { now: NOW });
    expect(calls[0].req.headers).toMatchObject({ "content-type": "application/x-amz-json-1.0", "x-amz-target": "AmazonSQS.ReceiveMessage" });
    expect(calls[0].req.headers!.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/\d{8}\/ap-south-1\/sqs\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=[a-f0-9]{64}$/);
    expect(calls[1].url).toBe("https://trail-bucket.s3.ap-south-1.amazonaws.com/AWSLogs/111122223333/CloudTrail/ap-south-1/2026/10/26/f%201.json.gz");
    expect(calls[1].req.headers!["x-amz-content-sha256"]).toMatch(/^[a-f0-9]{64}$/);
    expect(r.records).toEqual([{ eventID: "e1", eventName: "ConsoleLogin" }, { eventID: "e2", eventName: "StopLogging" }]);
    await r.commit!();
    expect(JSON.parse(calls.at(-1)!.req.body!)).toEqual({ QueueUrl: "https://sqs.ap-south-1.amazonaws.com/111122223333/q", Entries: [{ Id: "0", ReceiptHandle: "rh1" }] });
    // SNS-wrapped notifications, digests and test events.
    expect(s3Objects(JSON.stringify({ Type: "Notification", Message: notification }))).toHaveLength(1);
    expect(s3Objects(JSON.stringify({ Records: [{ eventName: "ObjectCreated:Put", s3: { bucket: { name: "b" }, object: { key: "AWSLogs/1/CloudTrail-Digest/x.json.gz" } } }] }))).toEqual([]);
    expect(s3Objects(JSON.stringify({ Event: "s3:TestEvent" }))).toEqual([]);
  });

  it("signs SigV4 like AWS's documented example", () => {
    const h = signAws({ method: "GET", url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", region: "us-east-1", service: "iam", headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" }, now: new Date("2015-08-30T12:36:00Z") }, { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" });
    expect(h.authorization).toBe("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
  });

  it("maps every stream's records with a known format, and every collector to catalog tools", () => {
    for (const c of COLLECTORS) for (const s of c.streams) expect(streamByKey(s.key)?.stream.format).toBe(s.format);
    expect(collectorForTool("entra_p2")?.key).toBe("entra_logs");
    expect(collectorForTool("aws_cloudtrail")?.streams[0].format).toBe("cloudtrail");
    // A pulled Falcon alert files as an alert.
    expect(mapRecord("crowdstrike", { composite_id: "c1", display_name: "Credential dumping", severity: 90, device: { hostname: "WS-1" }, updated_timestamp: "2026-10-26T05:00:00Z" }, "endpoint")[0]).toMatchObject({ kind: "alert", alert: { severity: "CRITICAL", host: "WS-1" } });
  });
});

describe("the forwarder configuration", () => {
  const sign = (hash: string) => `sig-${hash}`.padEnd(64, "0").slice(0, 64).replace(/[^a-f0-9]/g, "a");
  const target = { ingestUrl: "https://helios.example.com/api/ingest/int_1", label: "Clinic firewall", issuedAt: new Date("2026-10-26T06:00:00Z") };
  const linux: ForwarderOptions = { os: "linux", syslog: { udpPort: 514, tcpPort: 6514, format: "rfc5424" }, windowsChannels: [], files: ["/var/log/auth.log"], bufferLimitMb: 1024 };

  it("collects syslog and files, buffers to disk, and sends gzip with the token from the environment", () => {
    const { text, hash } = renderConfig(linux, target, sign);
    expect(text).toMatch(/\[INPUT\]\n\s+name\s+syslog\n\s+tag\s+syslog\.udp\n\s+mode\s+udp\n\s+listen\s+0\.0\.0\.0\n\s+port\s+514\n\s+parser\s+syslog-rfc5424/);
    expect(text).toMatch(/mode\s+tcp\n\s+listen\s+0\.0\.0\.0\n\s+port\s+6514/);
    expect(text).toMatch(/name\s+tail\n\s+tag\s+file\.0\n\s+path\s+\/var\/log\/auth\.log/);
    expect(text).toMatch(/storage\.path\s+\/var\/lib\/helios-forwarder\/buffer/);
    expect(text).toMatch(/host\s+helios\.example\.com\n\s+port\s+443\n\s+uri\s+\/api\/ingest\/int_1/);
    expect(text).toContain("header                   Authorization Bearer ${HELIOS_INGEST_TOKEN}");
    expect(text).toContain(`X-Helios-Config ${hash}`);
    expect(text).toMatch(/compress\s+gzip/);
    expect(text).toMatch(/storage\.total_limit_size\s+1024M/);
    expect(text).toMatch(/add\s+helios_input syslog/);
    expect(text).not.toMatch(/winevtlog/);
  });

  it("reads the chosen Windows channels with their event filters", () => {
    const { text } = renderConfig({ ...linux, os: "windows", syslog: null, files: [], windowsChannels: ["security", "sysmon"] }, target, sign);
    expect(text).toMatch(/name\s+winevtlog\n\s+tag\s+win\.security\n\s+channels\s+Security\n\s+event_query\s+\*\[System\[\(EventID=4624 or EventID=4625/);
    expect(text).toMatch(/channels\s+Microsoft-Windows-Sysmon\/Operational/);
    expect(text).toMatch(/db\s+C:\\ProgramData\\helios-forwarder\\winevtlog-security\.sqlite/);
    expect(text).not.toMatch(/name\s+syslog/);
  });

  it("verifies an issued file, and catches an edited or foreign one", () => {
    const { text, hash } = renderConfig(linux, target, sign);
    expect(configHashOf(text)).toEqual({ claimed: hash, actual: hash });
    expect(verifyConfig(text, sign)).toMatchObject({ ok: true, hash });
    expect(verifyConfig(text.replace("port                     443", "port                     8443"), sign)).toMatchObject({ ok: false, reason: expect.stringMatching(/changed/) });
    expect(verifyConfig(text, () => "f".repeat(64))).toMatchObject({ ok: false, reason: expect.stringMatching(/signature/) });
    expect(verifyConfig("[SERVICE]\n    flush 5\n", sign).ok).toBe(false);
    // Same answers, same file.
    expect(renderConfig(linux, target, sign).hash).toBe(hash);
  });
});

describe("source health", () => {
  it("watches telemetry, gives sparse sources a day, and leaves alert feeds alone unless set", () => {
    expect(quietLimit(null, "entra", Array(168).fill(40))).toBe(120);
    expect(quietLimit(null, "entra", [1, 0, 1, 0])).toBe(24 * 60);
    expect(quietLimit(null, "entra", [])).toBe(120);
    expect(quietLimit(null, "crowdstrike", Array(168).fill(5))).toBeNull();
    expect(quietLimit(45, "crowdstrike", [])).toBe(45);
    expect(quietLimit(0, "forwarder", Array(168).fill(500))).toBeNull();
    expect(median([5, 1, 3])).toBe(3);
  });
});

describe("vendor telemetry that isn't an alert", () => {
  it("maps Falcon raw events by event_simpleName, with epoch-millisecond times and the event id", () => {
    const [proc] = mapRecord("crowdstrike", { event_simpleName: "ProcessRollup2", timestamp: "1793431432000", ComputerName: "WS-07", UserName: "jdoe", ImageFileName: "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -enc SQBFAFgA", ParentBaseFileName: "winword.exe", SHA256HashData: "a".repeat(64), id: "e-1", aid: "aid1" }, "endpoint");
    expect(proc).toMatchObject({ kind: "telemetry", source: "endpoint", sourceEventId: "falcon:e-1", data: { event_type: "PROCESS_START", hostname: "WS-07", user: "jdoe", process_name: "powershell.exe", command_line: "powershell -enc SQBFAFgA", parent_process: "winword.exe", timestamp: new Date(1793431432000).toISOString() } });
    expect(mapRecord("crowdstrike", { event_simpleName: "NetworkConnectIP4", ComputerName: "WS-07", LocalAddressIP4: "10.0.0.5", RemoteAddressIP4: "203.0.113.9", RemotePort: "443" }, "endpoint")[0]).toMatchObject({ source: "network", data: { dst_ip: "203.0.113.9", dst_port: "443" } });
    expect(mapRecord("crowdstrike", { event_simpleName: "UserLogonFailed2", ComputerName: "DC-01", UserName: "admin" }, "endpoint")[0]).toMatchObject({ source: "auth", data: { result: "FAILED", user: "admin" } });
    // Other events keep their own name, so they never count as a process start.
    expect(mapRecord("crowdstrike", { event_simpleName: "DnsRequest", ComputerName: "WS-07" }, "endpoint")[0]).toMatchObject({ source: "endpoint", data: { event_type: "DnsRequest" } });
    // Detections still become alerts.
    expect(mapRecord("crowdstrike", { event: { DetectName: "Credential Theft", ComputerName: "WS-07", Severity: 4 } }, "endpoint")[0].kind).toBe("alert");
  });

  it("maps Defender advanced hunting rows, plain or from the streaming API", () => {
    const row = { Timestamp: "2026-10-31T07:00:00Z", DeviceName: "ws-07.corp.example", DeviceId: "d1", ReportId: 77, AccountName: "jdoe", FileName: "rundll32.exe", ProcessCommandLine: "rundll32.exe evil.dll,Start", InitiatingProcessFileName: "excel.exe", SHA256: "b".repeat(64), ActionType: "ProcessCreated" };
    expect(mapRecord("defender", row, "endpoint")[0]).toMatchObject({ kind: "telemetry", source: "endpoint", sourceEventId: "defender:d1:77:DeviceProcessEvents", data: { event_type: "PROCESS_START", hostname: "ws-07.corp.example", process_name: "rundll32.exe", parent_process: "excel.exe" } });
    const streamed = { time: "2026-10-31T07:00:01Z", category: "AdvancedHunting-DeviceLogonEvents", properties: { Timestamp: "2026-10-31T07:00:00Z", DeviceName: "dc-01", AccountName: "admin", ActionType: "LogonFailed", RemoteIP: "198.51.100.4", LogonType: "Network", ReportId: 5, DeviceId: "d2" } };
    expect(mapRecord("defender", streamed, "endpoint")[0]).toMatchObject({ source: "auth", data: { result: "FAILED", user: "admin", source_ip: "198.51.100.4" } });
    expect(mapRecord("defender", { title: "Suspicious PowerShell", severity: "high", evidence: [] }, "endpoint")[0].kind).toBe("alert");
  });
});

describe("stored telemetry rows", () => {
  it("keep the process name and the full command line apart", async () => {
    const { normalize, toEventRow } = await import("@/lib/siem/adapters");
    const row = toEventRow(normalize("endpoint", { hostname: "WS-1", process_name: "powershell.exe", command_line: "powershell -enc SQBFAFgA" }), "b1");
    expect(row).toMatchObject({ processName: "powershell.exe", commandLine: "powershell -enc SQBFAFgA" });
    // With only a command line, it fills both, as before.
    expect(toEventRow(normalize("endpoint", { hostname: "WS-1", command_line: "cmd /c whoami" }), "b1")).toMatchObject({ processName: "cmd /c whoami", commandLine: "cmd /c whoami" });
  });
});
