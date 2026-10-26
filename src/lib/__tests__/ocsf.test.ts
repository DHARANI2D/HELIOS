import { describe, expect, it } from "vitest";

import { CLASS, STATUS } from "@/lib/ocsf/schema";
import { columnsFromOcsf, ocsfFromColumns } from "@/lib/ocsf/columns";
import { rowFromColumns, rowFromOcsf, storedOcsf } from "@/lib/ocsf/rows";
import { entraAudit, entraSignIn, googleLogin, oktaLog } from "@/lib/ocsf/sources/identity";
import { messageFields, windowsEvent, windowsTime } from "@/lib/ocsf/sources/windows";
import { keyValues, syslogRecord } from "@/lib/ocsf/sources/syslog";
import { azureActivity, cloudTrail, gcpAudit } from "@/lib/ocsf/sources/cloud";
import { MappingError } from "@/lib/ocsf/sources/util";
import { mapRecord, recordsAndRejects } from "@/lib/integrations/mappers";
import { samplePayloadFor } from "@/lib/__tests__/fixtures/vendor-payloads";
import { fromEventRow, normalize, toEventRow } from "@/lib/siem/adapters";

describe("OCSF events", () => {
  it("derives class, category and type ids, and drops empty fields", () => {
    const ev = entraSignIn({ id: "s1", createdDateTime: "2026-10-26T04:00:00Z", userPrincipalName: "a@x.test", ipAddress: "203.0.113.9", status: { errorCode: 50126, failureReason: "Invalid username or password" }, location: { countryOrRegion: "IN" } });
    expect(ev).toMatchObject({ class_uid: 3002, category_uid: 3, activity_id: 1, type_uid: 300201, status_id: STATUS.FAILURE, metadata: { version: "1.9.0", product: { name: "Microsoft Entra ID" }, uid: "s1" } });
    expect(ev.device).toBeUndefined();
    expect(columnsFromOcsf(ev)).toMatchObject({ source: "auth", eventType: "LOGIN_FAIL", userName: "a@x.test", sourceIp: "203.0.113.9", geo: "IN", severityHint: "medium", sourceEventId: "s1" });
  });

  it("gives the original adapters' events an OCSF form, and keeps them working for detectors", () => {
    const auth = ocsfFromColumns({ timestamp: new Date(), source: "auth", eventType: "LOGIN_FAIL", userName: "bob", sourceIp: "198.51.100.4", geo: "RU" });
    expect(auth).toMatchObject({ class_uid: CLASS.AUTHENTICATION, status_id: STATUS.FAILURE, user: { name: "bob" }, src_endpoint: { ip: "198.51.100.4", location: { country: "RU" } } });
    const dns = ocsfFromColumns({ timestamp: new Date(), source: "network", eventType: "CONN_ESTABLISHED", metadata: { type: "DNS", query: "x.evil.test" } });
    expect(dns).toMatchObject({ class_uid: CLASS.DNS, query: { hostname: "x.evil.test" } });
    const cloud = ocsfFromColumns({ timestamp: new Date(), source: "cloud", eventType: "DeleteBucket", userName: "ops", metadata: { status: "DENIED" } });
    expect(cloud).toMatchObject({ class_uid: CLASS.API, activity_id: 4, status_id: STATUS.FAILURE });

    const row = toEventRow(normalize("endpoint", { hostname: "WS-1", user: "bob", process: "mimikatz.exe sekurlsa::logonpasswords" }), "b1");
    expect(row).toMatchObject({ classUid: CLASS.PROCESS, commandLine: "mimikatz.exe sekurlsa::logonpasswords" });
    expect((row.ocsf as { process: { cmd_line: string } }).process.cmd_line).toBe("mimikatz.exe sekurlsa::logonpasswords");
    // The stored form leaves `unmapped` to the metadata column, and gets it back.
    expect((row.ocsf as Record<string, unknown>).unmapped).toBeUndefined();
    expect(storedOcsf({ ocsf: row.ocsf as never, metadata: row.metadata as never })?.unmapped).toMatchObject({ hostname: "WS-1" });
  });

  it("reads a process's command line, not just its image, into the detectors' view", () => {
    const records = samplePayloadFor({ ingest: "forwarder", category: "siem" }) as Array<Record<string, unknown>>;
    const row = rowFromOcsf(windowsEvent(records[7]));
    expect(row).toMatchObject({ processName: "C:\\Windows\\System32\\vssadmin.exe", commandLine: "vssadmin.exe delete shadows /all /quiet", parentProcessName: "C:\\Windows\\System32\\cmd.exe", userName: "administrator" });
    const unified = fromEventRow({ id: "e1", timestamp: row.timestamp as Date, source: row.source, eventType: row.eventType, userName: row.userName ?? null, hostName: row.hostName ?? null, service: null, processName: row.processName ?? null, commandLine: row.commandLine ?? null, sourceIp: null, destIp: null, destPort: null, geo: null, severityHint: null, metadata: row.metadata as never });
    expect(unified.actor.process).toBe("vssadmin.exe delete shadows /all /quiet");
    expect(unified.metadata.parentProcess).toBe("C:\\Windows\\System32\\cmd.exe");
    expect(rowFromColumns({ timestamp: new Date(), source: "endpoint", eventType: "PROCESS_START", processName: "a.exe" }).classUid).toBe(CLASS.PROCESS);
  });
});

describe("Windows events from the forwarder", () => {
  const records = samplePayloadFor({ ingest: "forwarder", category: "siem" }) as Array<Record<string, unknown>>;

  it("maps failed and successful logons by template position", () => {
    const failed = windowsEvent(records[0]);
    expect(failed).toMatchObject({ class_uid: CLASS.AUTHENTICATION, status_id: STATUS.FAILURE, user: { name: "administrator", domain: "CORP" }, src_endpoint: { ip: "203.0.113.50", hostname: "KALI" }, logon_type: "RemoteInteractive", auth_protocol: "NTLM" });
    expect(failed.metadata.uid).toBe("FIN-WS-04.corp.helios.test:Security:88100");
    const ok = columnsFromOcsf(windowsEvent(records[6]));
    expect(ok).toMatchObject({ eventType: "LOGIN_SUCCESS", userName: "administrator", sourceIp: "203.0.113.50", hostName: "FIN-WS-04.corp.helios.test" });
  });

  it("prefers named event data, and reads Sysmon from its message", () => {
    const named = windowsEvent({ EventID: 4624, Channel: "Security", Computer: "H", TimeCreated: "2026-10-26 10:00:00 +0530", EventRecordID: 1, EventData: { TargetUserName: "alice", IpAddress: "10.0.0.9", LogonType: "3" } });
    expect(named).toMatchObject({ user: { name: "alice" }, src_endpoint: { ip: "10.0.0.9" }, logon_type: "Network" });
    expect(named.time).toBe(Date.parse("2026-10-26T04:30:00Z"));
    const sysmon = windowsEvent({
      EventID: 1, Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "H", TimeCreated: "2026-10-26 10:00:00 +0000", EventRecordID: 2,
      Message: "Process Create:\r\nRuleName: -\r\nUtcTime: 2026-10-26 10:00:00.000\r\nProcessId: 4242\r\nImage: C:\\Tools\\procdump.exe\r\nCommandLine: procdump.exe -ma lsass.exe out.dmp\r\nUser: CORP\\bob\r\nHashes: SHA256=" + "a".repeat(64) + ",MD5=" + "b".repeat(32) + "\r\nParentImage: C:\\Windows\\explorer.exe",
    });
    expect(columnsFromOcsf(sysmon)).toMatchObject({ eventType: "PROCESS_START", commandLine: "procdump.exe -ma lsass.exe out.dmp", userName: "bob", processPid: 4242, fileHash: "a".repeat(64), parentProcessName: "C:\\Windows\\explorer.exe" });
    expect(messageFields("A: 1\nB: two words")).toEqual({ A: "1", B: "two words" });
    expect(windowsTime("2026-10-26 23:59:59 -0700")?.toISOString()).toBe("2026-10-27T06:59:59.000Z");
  });

  it("sends a record it can't read to the dead-letter queue", () => {
    expect(() => windowsEvent({ EventID: 4624, Channel: "Security", TimeCreated: "yesterday-ish" })).toThrow(MappingError);
    expect(() => mapRecord("forwarder", { EventID: 4624, Channel: "Security", TimeCreated: "x" }, "endpoint")).toThrow(MappingError);
  });
});

describe("syslog from firewalls and servers", () => {
  const t = new Date().toISOString();
  it("maps FortiGate key=value traffic and a sign-in", () => {
    const deny = syslogRecord({ pri: "189", host: "FGT", message: 'type="traffic" subtype="forward" srcip=10.0.0.5 srcport=5000 dstip=198.51.100.7 dstport=443 proto=6 action="deny" sentbyte=60', timestamp: t });
    expect(deny).toMatchObject({ class_uid: CLASS.NETWORK, activity_id: 5, disposition: "deny", connection_info: { protocol_name: "tcp" }, dst_endpoint: { ip: "198.51.100.7", port: 443 } });
    expect(columnsFromOcsf(deny)).toMatchObject({ eventType: "CONN_DENIED", sourceIp: "10.0.0.5", destIp: "198.51.100.7", destPort: 443 });
    const login = syslogRecord({ host: "FGT", ident: "", message: 'logdesc="Admin login failed" type="event" subtype="system" user="admin" srcip=203.0.113.5 status="failed" reason="passwd_invalid"', timestamp: t });
    expect(columnsFromOcsf(login)).toMatchObject({ eventType: "LOGIN_FAIL", userName: "admin", sourceIp: "203.0.113.5" });
    expect(keyValues('a=1 b="two words" c=')).toEqual({ a: "1", b: "two words", c: "" });
  });

  it("maps OPNsense filterlog, CEF and OpenSSH", () => {
    const fl = syslogRecord({ host: "fw", ident: "filterlog", message: "filterlog[123]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.0.2.10,198.51.100.5,51234,22,0,S,1,,64240,,mss", timestamp: t });
    expect(fl).toMatchObject({ class_uid: CLASS.NETWORK, activity_id: 5, src_endpoint: { ip: "192.0.2.10", port: 51234 }, dst_endpoint: { ip: "198.51.100.5", port: 22 } });
    const cef = syslogRecord({ host: "pa", message: "CEF:0|Palo Alto Networks|PAN-OS|11.1|url|THREAT|8|src=10.1.1.4 dst=203.0.113.80 dpt=443 act=block-url request=https://bad.example.test/login suser=corp\\\\bob", timestamp: t });
    expect(cef).toMatchObject({ class_uid: CLASS.HTTP, severity_id: 4, disposition: "block-url", http_request: { url: { url_string: "https://bad.example.test/login" } }, metadata: { product: { name: "PAN-OS", vendor_name: "Palo Alto Networks" } } });
    const ssh = columnsFromOcsf(syslogRecord({ host: "web-1", ident: "sshd", pid: "811", message: "Failed password for invalid user oracle from 203.0.113.44 port 40022 ssh2", timestamp: t }));
    expect(ssh).toMatchObject({ eventType: "LOGIN_FAIL", userName: "oracle", sourceIp: "203.0.113.44", hostName: "web-1" });
    expect(syslogRecord({ host: "h", message: "kernel: something ordinary", timestamp: t })).toMatchObject({ class_uid: CLASS.BASE, message: "kernel: something ordinary" });
  });
});

describe("identity and cloud audit logs", () => {
  it("maps Entra directory audits, Okta and Google logins", () => {
    const role = entraAudit({ id: "a1", activityDateTime: "2026-10-26T04:00:00Z", activityDisplayName: "Add member to role", category: "RoleManagement", result: "success", initiatedBy: { user: { userPrincipalName: "admin@x.test", ipAddress: "203.0.113.1" } }, targetResources: [{ type: "User", userPrincipalName: "eve@x.test", id: "u2" }] });
    expect(role).toMatchObject({ class_uid: CLASS.ACCOUNT_CHANGE, activity_id: 7, user: { name: "eve@x.test" }, actor: { user: { name: "admin@x.test" } }, severity_id: 3 });
    expect(columnsFromOcsf(role)).toMatchObject({ source: "auth", eventType: "PRIVILEGE_ADD", userName: "eve@x.test", sourceIp: "203.0.113.1" });
    const consent = entraAudit({ id: "a2", activityDateTime: "2026-10-26T04:00:00Z", activityDisplayName: "Consent to application", result: "success", initiatedBy: { user: { userPrincipalName: "bob@x.test" } }, targetResources: [{ type: "ServicePrincipal", displayName: "Mail Reader" }] });
    expect(columnsFromOcsf(consent)).toMatchObject({ source: "cloud", eventType: "Consent to application", userName: "bob@x.test" });

    const [first] = (samplePayloadFor({ ingest: "okta", category: "identity" }) as Array<Record<string, unknown>>).map(oktaLog);
    expect(columnsFromOcsf(first)).toMatchObject({ eventType: "LOGIN_FAIL", userName: "a.patel@corp.helios.test", geo: "Brazil" });
    expect(oktaLog({ uuid: "o2", published: new Date().toISOString(), eventType: "user.account.lock", actor: { alternateId: "system" }, target: [{ type: "User", alternateId: "eve@x.test" }], outcome: { result: "SUCCESS" } })).toMatchObject({ class_uid: CLASS.ACCOUNT_CHANGE, activity_id: 9, user: { name: "eve@x.test" } });

    const google = ((samplePayloadFor({ ingest: "google_workspace", category: "identity" }) as { items: Array<Record<string, unknown>> }).items).flatMap(googleLogin).map(columnsFromOcsf);
    expect(google.map((g) => g.eventType)).toEqual(["LOGIN_FAIL", "LOGIN_FAIL", "SUSPICIOUS_LOGIN"]);
    expect(google[2].severityHint).toBe("high");
  });

  it("maps CloudTrail, Cloud Audit Logs and the Azure Activity Log", () => {
    const [signin, stop] = (samplePayloadFor({ ingest: "cloudtrail", category: "cloud" }) as { Records: Array<Record<string, unknown>> }).Records.map(cloudTrail);
    expect(signin).toMatchObject({ class_uid: CLASS.AUTHENTICATION, status_id: STATUS.FAILURE, is_mfa: false, user: { name: "ops-admin" } });
    expect(columnsFromOcsf(stop)).toMatchObject({ source: "cloud", eventType: "StopLogging", service: "cloudtrail.amazonaws.com", userName: "ops-admin", sourceIp: "203.0.113.50" });
    expect(stop.cloud).toMatchObject({ provider: "AWS", region: "ap-south-1" });

    const [gcp] = mapRecord("gcp_audit", samplePayloadFor({ ingest: "gcp_audit", category: "cloud" }) as Record<string, unknown>, "cloud");
    expect(gcp.kind === "event" && columnsFromOcsf(gcp.ocsf)).toMatchObject({ eventType: "storage.setIamPermissions", service: "storage.googleapis.com", userName: "ops-admin@corp.helios.test" });
    expect(gcpAudit({ timestamp: new Date().toISOString(), protoPayload: { methodName: "v1.compute.instances.delete", status: { code: 7 } } })).toMatchObject({ activity_id: 4, status_id: STATUS.FAILURE, status: "Permission denied" });

    const [az] = (samplePayloadFor({ ingest: "azure_activity", category: "cloud" }) as { value: Array<Record<string, unknown>> }).value.map(azureActivity);
    expect(columnsFromOcsf(az)).toMatchObject({ eventType: "Microsoft.Authorization/roleAssignments/write", userName: "ops-admin@corp.helios.test", sourceIp: "203.0.113.50" });
    expect(azureActivity({ time: new Date().toISOString(), operationName: "MICROSOFT.KEYVAULT/VAULTS/DELETE", resultType: "Failed", callerIpAddress: "198.51.100.2", identity: { claims: { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "x@y.test" } } })).toMatchObject({ activity_id: 4, status_id: STATUS.FAILURE, actor: { user: { name: "x@y.test" } } });
  });

  it("finds records in each list shape, and keeps what isn't a record", () => {
    expect(recordsAndRejects({ Records: [{ a: 1 }] }).records).toHaveLength(1);
    expect(recordsAndRejects({ items: [{ a: 1 }, "oops", 3] })).toEqual({ records: [{ a: 1 }], rejected: ["oops", 3] });
  });
});
