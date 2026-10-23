import { describe, expect, it } from "vitest";

import { parseCsv, parseTelemetry, parseSysmonXml } from "@/lib/investigations/normalize";
import { ancestry, buildEntityGraph } from "@/lib/investigations/graph";
import { heuristicQa, heuristicRca, heuristicReport, heuristicTriage, runForensicRules } from "@/lib/investigations/heuristics";
import { SAMPLE_INVESTIGATION } from "@/lib/investigations/samples";
import { buildEvidence } from "@/lib/investigations/agents";
import { expandIntake, focusGraph } from "@/lib/investigations/service";
import { zipSync, strToU8 } from "fflate";

describe("log normalization", () => {
  it("auto-detects Sysmon JSON and maps process lineage fields", () => {
    const { platform, events } = parseTelemetry(SAMPLE_INVESTIGATION.logs);
    expect(platform).toBe("sysmon");
    expect(events).toHaveLength(21);
    const ps = events.find((e) => e.processPid === 4512 && e.eventType === "process_create")!;
    expect(ps).toMatchObject({ processName: "powershell.exe", parentProcessName: "cmd.exe", parentProcessPid: 4470 });
    expect(ps.timestamp.toISOString()).toBe("2026-10-20T08:01:31.006Z");
  });

  it("parses Sysmon XML exports", () => {
    const xml = `<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>3</EventID><TimeCreated SystemTime="2026-10-20T08:00:00.000Z"/><Computer>ws-9</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\rundll32.exe</Data><Data Name="ProcessId">77</Data><Data Name="DestinationIp">203.0.113.5</Data><Data Name="DestinationPort">8443</Data></EventData></Event></Events>`;
    const [e] = parseSysmonXml(xml);
    expect(e).toMatchObject({ eventType: "network_connect", hostName: "ws-9", processName: "rundll32.exe", processPid: 77, dstIp: "203.0.113.5", dstPort: 8443 });
  });

  it("auto-detects CrowdStrike and Wazuh JSON lines", () => {
    const cs = parseTelemetry(
      '{"event_simpleName":"ProcessRollup2","aid":"x","ComputerName":"h1","FileName":"cmd.exe","TargetProcessId":"5","CommandLine":"cmd /c whoami","timestamp":"1760947200000"}',
    );
    expect(cs.platform).toBe("crowdstrike");
    expect(cs.events[0]).toMatchObject({ eventType: "process_create", hostName: "h1", processName: "cmd.exe", processPid: 5 });

    const wz = parseTelemetry(JSON.stringify([{ rule: { level: 10, id: "5710", groups: ["authentication_failed"] }, agent: { name: "srv" }, data: { srcip: "198.51.100.7", srcuser: "root" }, timestamp: "2026-10-20T08:00:00Z" }]));
    expect(wz.platform).toBe("wazuh");
    expect(wz.events[0]).toMatchObject({ eventType: "auth", hostName: "srv", userName: "root" });
  });

  it("parses quoted CSV with Splunk-style column aliases", () => {
    const rows = parseCsv('_time,host,Image,CommandLine\n2026-10-20T08:00:00Z,ws-1,C:\\x\\cmd.exe,"cmd /c ""echo, hi"""\n');
    expect(rows[0].CommandLine).toBe('cmd /c "echo, hi"');
    const { platform, events } = parseTelemetry('_time,host,Image,CommandLine,pid\n2026-10-20T08:00:00Z,ws-1,C:\\x\\cmd.exe,cmd /c whoami,12\n');
    expect(platform).toBe("splunk_csv");
    expect(events[0]).toMatchObject({ hostName: "ws-1", processName: "cmd.exe", processPid: 12, eventType: "process_create" });
  });

  it("falls back to raw log lines with timestamps and IPs", () => {
    const { platform, events } = parseTelemetry("2026-10-20T08:00:00Z sshd accepted from 198.51.100.3 to 10.0.0.4\n");
    expect(platform).toBe("generic_text");
    expect(events[0]).toMatchObject({ hostIp: "198.51.100.3", dstIp: "10.0.0.4" });
  });
});

describe("entity graph", () => {
  const { events } = parseTelemetry(SAMPLE_INVESTIGATION.logs);
  const graph = buildEntityGraph(events);

  it("reconstructs process lineage from the sample", () => {
    const ps = graph.nodes.find((n) => n.type === "process" && n.pid === 4512)!;
    expect(ancestry(graph, ps.id).map((n) => n.label)).toEqual(["userinit.exe", "explorer.exe", "OUTLOOK.EXE", "WINWORD.EXE", "cmd.exe", "powershell.exe"]);
  });

  it("links network, DNS and file activity to the acting process", () => {
    const rel = (target: string) => graph.edges.find((e) => e.target === target)?.relation;
    expect(rel("ip:185.220.101.5")).toBe("CONNECTED_TO");
    expect(rel("domain:cdn-update-check.xyz")).toBe("RESOLVED");
    expect(graph.nodes.some((n) => n.type === "file" && n.label === "updater.exe")).toBe(true);
    expect(graph.nodes.find((n) => n.label === "userinit.exe")?.observed).toBe(false);
  });

  it("bounds the stored graph around flagged processes", () => {
    expect(focusGraph(graph, [])).toBe(graph); // small graphs are stored whole
  });
});

describe("deterministic investigation engine", () => {
  const { events } = parseTelemetry(SAMPLE_INVESTIGATION.logs);
  const graph = buildEntityGraph(events);
  const findings = runForensicRules(events);

  it("finds the attack chain in the sample and ignores the benign browser noise", () => {
    const rules = findings.map((f) => f.ruleId);
    for (const r of ["office_child_shell", "encoded_powershell", "known_bad_destination", "non_standard_port", "run_key_persistence", "discovery_burst", "credential_dumping", "remote_execution"]) {
      expect(rules, r).toContain(r);
    }
    expect(findings.flatMap((f) => f.events).some((e) => e.processName === "chrome.exe")).toBe(false);
  });

  it("produces a triage, RCA, QA and report consistent with the evidence", () => {
    const triage = heuristicTriage("t", findings);
    expect(triage.severity).toBe("critical");
    expect(triage.mitre_tactic).toMatch(/\(TA\d{4}\)$/);
    const rca = heuristicRca(findings, graph);
    expect(rca.root_cause).toContain("phishing attachment");
    expect(rca.root_cause).toContain("WINWORD.EXE → cmd.exe");
    expect(rca.timeline[0]).toMatch(/^08:01:30 - /);
    expect(rca.mitre_techniques.map((t) => t.id)).toContain("T1003.001");
    const qa = heuristicQa(rca, events, graph);
    expect(qa.is_valid).toBe(true);
    const report = heuristicReport({ title: "t", triage, rca, qa, findings, events });
    expect(report).toContain("## Containment & mitigation");
    expect(report).toContain("`185.220.101.5`");
  });

  it("reports nothing on benign telemetry", () => {
    const benign = parseTelemetry('[{"EventID":1,"Image":"C:\\\\Program Files\\\\App\\\\app.exe","ProcessId":"1","ParentImage":"C:\\\\Windows\\\\explorer.exe","ParentProcessId":"2","UtcTime":"2026-10-20 08:00:00"}]').events;
    const f = runForensicRules(benign);
    expect(f).toEqual([]);
    expect(heuristicTriage("t", f).severity).toBe("low");
  });

  it("QA catches a timeline claim with no matching event and impossible causality", () => {
    const rca = { root_cause: "x", timeline: ["23:59:59 - invented event"], confidence_score: 0.9, mitre_techniques: [] };
    expect(heuristicQa(rca, events, graph).issues[0]).toContain("does not correspond");

    const skewed = parseTelemetry(JSON.stringify([
      { EventID: 1, Image: "a.exe", ProcessId: "9", UtcTime: "2026-10-20 08:00:10", Computer: "h" },
      { EventID: 3, Image: "a.exe", ProcessId: "9", DestinationIp: "203.0.113.1", UtcTime: "2026-10-20 08:00:05", Computer: "h" },
    ])).events;
    const qa = heuristicQa({ ...rca, timeline: [] }, skewed, buildEntityGraph(skewed));
    expect(qa.is_valid).toBe(false);
    expect(qa.issues[0]).toContain("before its observed creation");
  });

  it("builds LLM evidence that cites every flagged event", () => {
    const evidence = buildEvidence(events, findings, graph);
    expect(evidence).toContain("<detector_findings>");
    expect(evidence).toContain("All 21 normalized events are included.");
    expect(evidence).toContain("powershell.exe(4512) -CONNECTED_TO-> 185.220.101.5");
  });
});

describe("intake", () => {
  it("expands ZIP bundles and reports binary members instead of dropping them silently", () => {
    const zip = zipSync({ "logs/a.json": strToU8('[{"host":"h","process":"cmd.exe"}]'), "logs/b.evtx": new Uint8Array([0x45, 0x6c, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0]) });
    const { texts, skipped } = expandIntake([{ name: "bundle.zip", bytes: zip }]);
    expect(texts.map((t) => t.name)).toEqual(["bundle.zip/logs/a.json"]);
    expect(skipped[0]).toContain("logs/b.evtx");
  });
});
