import { describe, it, expect } from "vitest";

import { geoVelocityDetector } from "./geoVelocity";
import { fsmChainDetector } from "./fsmChain";
import { anomalousActionDetector } from "./anomalousAction";
import { threatIntelDetector } from "./threatIntel";
import { reconnaissanceDetector } from "./reconnaissance";
import { credentialHarvestingDetector } from "./credentialHarvesting";
import { lateralMovementDetector } from "./lateralMovement";
import { dataExfiltrationDetector } from "./dataExfiltration";
import { persistenceDetector } from "./persistence";
import { defenseEvasionDetector } from "./defenseEvasion";
import { impactDetector } from "./impact";
import type { NormalizedEvent } from "../types";

let seq = 0;
function ev(partial: Partial<NormalizedEvent> & { minutesAgo?: number }): NormalizedEvent {
  const { minutesAgo = 0, ...rest } = partial;
  seq += 1;
  return {
    id: `ev-${seq}`,
    timestamp: new Date(Date.now() - minutesAgo * 60_000),
    source: "ENDPOINT",
    eventType: "PROCESS_START",
    actor: {},
    network: {},
    metadata: {},
    ...rest,
  };
}

describe("GeoVelocityDetector", () => {
  it("flags a user logging in from two far-apart locations too fast", () => {
    const events = [
      ev({ source: "AUTH", eventType: "LOGIN_SUCCESS", actor: { user: "j.doe" }, network: { geo: "US" }, minutesAgo: 30 }),
      ev({ source: "AUTH", eventType: "LOGIN_SUCCESS", actor: { user: "j.doe" }, network: { geo: "RU" }, minutesAgo: 5 }),
    ];
    const detections = geoVelocityDetector.run(events);
    expect(detections).toHaveLength(1);
    expect(detections[0].signals).toContain("impossible_travel");
  });

  it("does not flag logins from the same location", () => {
    const events = [
      ev({ source: "AUTH", eventType: "LOGIN_SUCCESS", actor: { user: "j.doe" }, network: { geo: "US" }, minutesAgo: 30 }),
      ev({ source: "AUTH", eventType: "LOGIN_SUCCESS", actor: { user: "j.doe" }, network: { geo: "US" }, minutesAgo: 5 }),
    ];
    expect(geoVelocityDetector.run(events)).toHaveLength(0);
  });

  it("does not flag a slow, plausible location change", () => {
    const events = [
      ev({ source: "AUTH", eventType: "LOGIN_SUCCESS", actor: { user: "j.doe" }, network: { geo: "US" }, minutesAgo: 600 }),
      ev({ source: "AUTH", eventType: "LOGIN_SUCCESS", actor: { user: "j.doe" }, network: { geo: "RU" }, minutesAgo: 5 }),
    ];
    expect(geoVelocityDetector.run(events)).toHaveLength(0);
  });
});

describe("FSMChainDetector", () => {
  it("flags failed login -> success -> sensitive action", () => {
    const events = [
      ev({ source: "AUTH", eventType: "LOGIN_FAIL", actor: { user: "svc" }, minutesAgo: 10 }),
      ev({ source: "AUTH", eventType: "LOGIN_SUCCESS", actor: { user: "svc" }, minutesAgo: 9 }),
      ev({ source: "CLOUD", eventType: "IAM_POLICY_UPDATE", actor: { user: "svc" }, minutesAgo: 8 }),
    ];
    const detections = fsmChainDetector.run(events);
    expect(detections).toHaveLength(1);
    expect(detections[0].matchedEvents).toHaveLength(3);
  });

  it("does not flag a clean login with no sensitive follow-up", () => {
    const events = [
      ev({ source: "AUTH", eventType: "LOGIN_FAIL", actor: { user: "svc" }, minutesAgo: 10 }),
      ev({ source: "AUTH", eventType: "LOGIN_SUCCESS", actor: { user: "svc" }, minutesAgo: 9 }),
    ];
    expect(fsmChainDetector.run(events)).toHaveLength(0);
  });

  it("does not flag a direct successful login with no prior failure", () => {
    const events = [
      ev({ source: "AUTH", eventType: "LOGIN_SUCCESS", actor: { user: "svc" }, minutesAgo: 9 }),
      ev({ source: "CLOUD", eventType: "IAM_POLICY_UPDATE", actor: { user: "svc" }, minutesAgo: 8 }),
    ];
    expect(fsmChainDetector.run(events)).toHaveLength(0);
  });
});

describe("AnomalousActionDetector", () => {
  it("flags a discovery command followed by a suspicious one", () => {
    const events = [
      ev({ actor: { user: "attacker", process: "whoami /all" }, minutesAgo: 4 }),
      ev({ actor: { user: "attacker", process: "powershell.exe -enc AAAA" }, minutesAgo: 3 }),
    ];
    expect(anomalousActionDetector.run(events)).toHaveLength(1);
  });

  it("does not flag an isolated suspicious process with no discovery step first", () => {
    const events = [ev({ actor: { user: "attacker", process: "powershell.exe -enc AAAA" }, minutesAgo: 3 })];
    expect(anomalousActionDetector.run(events)).toHaveLength(0);
  });
});

describe("ThreatIntelDetector", () => {
  it("flags a known malicious source IP", () => {
    const events = [ev({ source: "NETWORK", network: { sourceIp: "45.33.22.11" } })];
    const detections = threatIntelDetector.run(events);
    expect(detections).toHaveLength(1);
    expect(detections[0].signals).toContain("intel_malicious_ip");
  });

  it("flags a known suspicious process name", () => {
    const events = [ev({ actor: { process: "mimikatz.exe privilege::debug" } })];
    const detections = threatIntelDetector.run(events);
    expect(detections[0].signals).toContain("intel_suspicious_process");
  });

  it("does not flag a clean IP and process", () => {
    const events = [ev({ source: "NETWORK", network: { sourceIp: "8.8.8.8" }, actor: { process: "notepad.exe" } })];
    expect(threatIntelDetector.run(events)).toHaveLength(0);
  });
});

describe("ReconnaissanceDetector", () => {
  it("flags port scanning (10+ distinct ports from one source)", () => {
    const events = Array.from({ length: 12 }, (_, i) =>
      ev({ source: "NETWORK", network: { sourceIp: "192.168.1.77" }, metadata: { port: 1000 + i } }),
    );
    const detections = reconnaissanceDetector.run(events);
    expect(detections.some((d) => d.signals.includes("port_scanning"))).toBe(true);
  });

  it("does not flag a handful of distinct ports", () => {
    const events = Array.from({ length: 3 }, (_, i) =>
      ev({ source: "NETWORK", network: { sourceIp: "192.168.1.77" }, metadata: { port: 1000 + i } }),
    );
    expect(reconnaissanceDetector.run(events)).toHaveLength(0);
  });

  it("flags OSINT platform access", () => {
    const events = [ev({ source: "NETWORK", metadata: { url: "https://github.com/target-org" } })];
    expect(reconnaissanceDetector.run(events)[0].signals).toContain("osint_gathering");
  });
});

describe("CredentialHarvestingDetector", () => {
  it("flags a credential dumping tool", () => {
    const events = [ev({ actor: { process: "mimikatz.exe sekurlsa::logonpasswords" } })];
    expect(credentialHarvestingDetector.run(events)[0].signals).toContain("credential_dumping");
  });

  it("flags password spraying (5+ accounts, 5+ failures, one source IP)", () => {
    const events = ["alice", "bob", "carol", "dave", "erin"].map((user) =>
      ev({ source: "AUTH", network: { sourceIp: "45.33.22.11" }, actor: { user }, metadata: { result: "FAILED" } }),
    );
    expect(credentialHarvestingDetector.run(events).some((d) => d.signals.includes("password_spraying"))).toBe(true);
  });

  it("does not flag a single failed login", () => {
    const events = [ev({ source: "AUTH", network: { sourceIp: "45.33.22.11" }, actor: { user: "alice" }, metadata: { result: "FAILED" } })];
    expect(credentialHarvestingDetector.run(events)).toHaveLength(0);
  });
});

describe("LateralMovementDetector", () => {
  it("flags internal-to-internal RDP", () => {
    const events = [ev({ source: "NETWORK", network: { sourceIp: "10.0.2.15", destIp: "10.0.2.40" }, metadata: { service: "RDP" } })];
    expect(lateralMovementDetector.run(events)[0].signals).toContain("rdp_lateral_movement");
  });

  it("does not flag RDP to an external IP", () => {
    const events = [ev({ source: "NETWORK", network: { sourceIp: "10.0.2.15", destIp: "203.0.113.5" }, metadata: { service: "RDP" } })];
    expect(lateralMovementDetector.run(events)).toHaveLength(0);
  });

  it("flags PsExec execution", () => {
    const events = [ev({ actor: { process: "psexec.exe \\\\FILESRV01 cmd.exe" } })];
    expect(lateralMovementDetector.run(events)[0].signals).toContain("psexec_execution");
  });
});

describe("DataExfiltrationDetector", () => {
  it("flags a large network transfer", () => {
    const events = [ev({ source: "NETWORK", metadata: { bytes_transferred: 200 * 1024 * 1024 } })];
    expect(dataExfiltrationDetector.run(events)[0].signals).toContain("large_data_transfer");
  });

  it("does not flag a small transfer", () => {
    const events = [ev({ source: "NETWORK", metadata: { bytes_transferred: 1024 } })];
    expect(dataExfiltrationDetector.run(events)).toHaveLength(0);
  });

  it("flags a large cloud upload", () => {
    const events = [ev({ source: "CLOUD", metadata: { action: "S3_OBJECT_UPLOAD", size: 50 * 1024 * 1024 } })];
    expect(dataExfiltrationDetector.run(events)[0].signals).toContain("cloud_exfiltration");
  });
});

describe("PersistenceDetector", () => {
  it("flags a registry run-key modification", () => {
    const events = [ev({ actor: { process: "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x" } })];
    expect(persistenceDetector.run(events)[0].signals).toContain("registry_persistence");
  });

  it("does not flag an unrelated registry read", () => {
    const events = [ev({ actor: { process: "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" } })];
    expect(persistenceDetector.run(events)).toHaveLength(0);
  });
});

describe("DefenseEvasionDetector", () => {
  it("flags Windows event log clearing", () => {
    const events = [ev({ actor: { process: "wevtutil cl System" } })];
    expect(defenseEvasionDetector.run(events)[0].signals).toContain("log_clearing");
  });

  it("flags antivirus being disabled", () => {
    const events = [ev({ actor: { process: "Set-MpPreference -DisableRealtimeMonitoring $true" } })];
    expect(defenseEvasionDetector.run(events)[0].signals).toContain("disable_av");
  });
});

describe("ImpactDetector", () => {
  it("flags mass file modification as potential ransomware", () => {
    const events = [ev({ metadata: { files_modified: 4000 } })];
    expect(impactDetector.run(events)[0].signals).toContain("ransomware");
  });

  it("flags mass deletion commands", () => {
    const events = [ev({ actor: { process: "rm -rf /data" } })];
    expect(impactDetector.run(events)[0].signals).toContain("data_destruction");
  });

  it("does not flag a normal process with no destructive markers", () => {
    const events = [ev({ actor: { process: "notepad.exe" }, metadata: { files_modified: 1 } })];
    expect(impactDetector.run(events)).toHaveLength(0);
  });
});
