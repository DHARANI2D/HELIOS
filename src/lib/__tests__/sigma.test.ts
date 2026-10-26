import { describe, expect, it } from "vitest";

import { compileSigma, splitRules } from "@/lib/detections/sigma";
import { logsourceFilter, sigmaEvent, type EventRow } from "@/lib/detections/sigma-fields";

const row = (over: Partial<EventRow>): EventRow => ({
  timestamp: new Date("2026-10-26T04:00:00Z"), source: "endpoint", platform: "sysmon", eventType: "process_start", classUid: 1007,
  userName: "asha", hostName: "WS-01", service: null, processName: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", processPid: 4242,
  parentProcessName: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", parentProcessPid: 100, commandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
  sourceIp: null, destIp: null, destPort: null, filePath: null, fileHash: null, metadata: { EventID: 1, OriginalFileName: "PowerShell.EXE" }, ocsf: null, ...over,
});

const ENCODED = `
title: Suspicious Encoded PowerShell Command Line
id: ca2092a1-c273-4878-9b4b-0d60115bf5ea
status: test
description: Detects a PowerShell command line with an encoded payload
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\\powershell.exe'
    - OriginalFileName: 'PowerShell.EXE'
  selection_cli:
    CommandLine|contains|windash:
      - ' -e '
      - ' -enc '
      - ' -EncodedCommand '
  filter_main:
    ParentImage|endswith: '\\explorer.exe'
  condition: all of selection_* and not 1 of filter_*
falsepositives:
  - Some admin scripts
level: high
`;

describe("Sigma rules", () => {
  it("compiles a real rule and matches the events it describes", () => {
    const r = compileSigma(ENCODED);
    if (!r.ok) throw new Error(r.errors.join("; "));
    expect(r.rule).toMatchObject({ sigmaId: "ca2092a1-c273-4878-9b4b-0d60115bf5ea", level: "high", techniques: ["T1059.001"], tactics: ["Execution"], logsource: { category: "process_creation", product: "windows" } });
    expect(r.rule.match(sigmaEvent(row({})))).toBe(true);
    // windash: /enc matches -enc.
    expect(r.rule.match(sigmaEvent(row({ commandLine: "powershell.exe /nop /enc SQBFAFgA" })))).toBe(true);
    // The filter: launched from Explorer.
    expect(r.rule.match(sigmaEvent(row({ parentProcessName: "C:\\Windows\\explorer.exe" })))).toBe(false);
    expect(r.rule.match(sigmaEvent(row({ commandLine: "powershell.exe -File backup.ps1" })))).toBe(false);
    // A bare file name still satisfies endswith '\\powershell.exe'.
    expect(r.rule.match(sigmaEvent(row({ processName: "powershell.exe", metadata: {} })))).toBe(true);
  });

  it("handles values, wildcards, modifiers and keyword searches as the spec says", () => {
    const rule = (detection: string) => {
      const r = compileSigma(`title: t\nlogsource: { category: process_creation }\ndetection:\n${detection}\nlevel: low`);
      if (!r.ok) throw new Error(r.errors.join("; "));
      return (over: Partial<EventRow>) => r.rule.match(sigmaEvent(row(over)));
    };
    expect(rule("  sel: { CommandLine: '*-W HIDDEN*' }\n  condition: sel")({})).toBe(true); // case-insensitive wildcard
    expect(rule("  sel: { CommandLine|cased|contains: 'HIDDEN' }\n  condition: sel")({})).toBe(false);
    expect(rule("  sel: { CommandLine|contains|all: ['-nop', '-enc'] }\n  condition: sel")({})).toBe(true);
    expect(rule("  sel: { CommandLine|contains|all: ['-nop', 'mimikatz'] }\n  condition: sel")({})).toBe(false);
    expect(rule("  sel: { CommandLine|re: '-enc\\s+[A-Za-z0-9+/=]{8}' }\n  condition: sel")({})).toBe(true);
    expect(rule("  sel: { DestinationIp|cidr: '10.0.0.0/8' }\n  condition: sel")({ destIp: "10.4.5.6" })).toBe(true);
    expect(rule("  sel: { DestinationIp|cidr: '10.0.0.0/8' }\n  condition: sel")({ destIp: "11.4.5.6" })).toBe(false);
    expect(rule("  sel: { ProcessId|gt: 4000 }\n  condition: sel")({})).toBe(true);
    expect(rule("  sel: { TargetFilename: null }\n  condition: sel")({})).toBe(true);
    expect(rule("  sel: { TargetFilename|exists: true }\n  condition: sel")({ filePath: "C:\\x.dll" })).toBe(true);
    expect(rule("  keywords: ['mimikatz', 'sekurlsa']\n  condition: keywords")({ commandLine: "run sekurlsa::logonpasswords" })).toBe(true);
    // base64offset of "IEX" (UTF-16LE), as in encoded PowerShell.
    expect(rule("  sel: { CommandLine|wide|base64offset|contains: 'IEX' }\n  condition: sel")({})).toBe(true);
    expect(rule("  a: { User: asha }\n  b: { Computer: WS-02 }\n  condition: a and not (b or 1 of c*)\n  c1: { User: root }")({})).toBe(true);
    expect(rule("  sel: { Hashes|contains: 'SHA256=ABCD' }\n  condition: sel")({ fileHash: "abcd1234" })).toBe(true);
  });

  it("refuses what it can't evaluate faithfully, saying why", () => {
    const err = (yaml: string) => { const r = compileSigma(yaml); return r.ok ? [] : r.errors; };
    expect(err("title: t\nlogsource: {}\ndetection:\n  sel: { User: x }\n  condition: sel | count() > 5\nlevel: low")[0]).toMatch(/Aggregations/);
    expect(err("title: t\nlogsource: {}\ndetection:\n  sel: { User|fieldref: x }\n  condition: sel")[0]).toMatch(/modifier \|fieldref isn't supported/);
    expect(err("title: t\nlogsource: {}\ndetection:\n  sel: { User: x }\n  condition: sel and missing")[0]).toMatch(/names "missing"/);
    expect(err("title: t\ndetection:\n  sel: { User|re: '([' }\n  condition: sel")[0]).toMatch(/valid regular expression/);
    expect(err("not: [yaml")[0]).toMatch(/YAML/);
    expect(err("title: t\nlevel: severe\ndetection:\n  sel: { User: x }\n  condition: sel")[0]).toMatch(/level/);
  });

  it("maps log sources to the events they cover", () => {
    expect(logsourceFilter({ category: "process_creation", product: "windows" }).test(row({}))).toBe(true);
    expect(logsourceFilter({ category: "dns_query" }).test(row({}))).toBe(false);
    expect(logsourceFilter({ category: "dns_query" }).test(row({ classUid: 4003, eventType: "dns_query" }))).toBe(true);
    expect(logsourceFilter({ product: "aws", service: "cloudtrail" }).test(row({ platform: "aws-cloudtrail", classUid: 6003, eventType: "api" }))).toBe(true);
    expect(logsourceFilter({ category: "something_new" }).known).toBe(false);
    expect(splitRules(`${ENCODED}\n---\ntitle: second\n`)).toHaveLength(2);
  });
});
