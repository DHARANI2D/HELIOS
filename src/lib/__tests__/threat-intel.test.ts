import { describe, expect, it } from "vitest";

import { classifyIndicator, extractIndicators, isPrivateIp, refang } from "@/lib/threat-intel/indicators";
import { localVerdict, verdictForScore } from "@/lib/threat-intel/local-intel";
import { scoreVirusTotalStats } from "@/lib/threat-intel/providers";

describe("indicator extraction", () => {
  it("refangs defanged IOCs", () => {
    expect(refang("hxxps://evil[.]example[.]com/a")).toBe("https://evil.example.com/a");
    expect(refang("user[@]corp[.]com")).toBe("user@corp.com");
  });

  it("extracts URLs, their hosts, public IPs, hashes and emails", () => {
    const iocs = extractIndicators(
      "beacon to hxxps://c2-server[.]evil/beacon from 10.0.0.5 to 99.88.77.66; drop sha256 " +
        "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3 mail ops@corp.io",
    );
    const values = iocs.map((i) => `${i.type}:${i.value}`);
    expect(values).toContain("URL:https://c2-server.evil/beacon");
    expect(values).toContain("DOMAIN:c2-server.evil");
    expect(values).toContain("IP:99.88.77.66");
    expect(values).not.toContain("IP:10.0.0.5");
    expect(values).toContain("FILE_HASH:9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3");
    expect(values).toContain("EMAIL_ADDRESS:ops@corp.io");
    // The email's domain isn't double-counted as a standalone domain IOC.
    expect(values).not.toContain("DOMAIN:corp.io");
  });

  it("does not mistake filenames for domains", () => {
    const iocs = extractIndicators("powershell.exe -enc ... wrote invoice.docx and update.dll");
    expect(iocs.filter((i) => i.type === "DOMAIN")).toEqual([]);
  });

  it("classifies single indicators", () => {
    expect(classifyIndicator("8.8.8.8")).toEqual({ type: "IP", value: "8.8.8.8" });
    expect(classifyIndicator("Example.COM")).toEqual({ type: "DOMAIN", value: "example.com" });
    expect(classifyIndicator("hxxp://x[.]io/p")?.type).toBe("URL");
    expect(classifyIndicator("d41d8cd98f00b204e9800998ecf8427e")?.type).toBe("FILE_HASH");
    expect(classifyIndicator("not an ioc")).toBeNull();
  });

  it("recognizes private and reserved ranges", () => {
    for (const ip of ["10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0"]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
    for (const ip of ["8.8.8.8", "172.32.0.1", "185.220.101.5"]) expect(isPrivateIp(ip), ip).toBe(false);
  });
});

describe("built-in intel", () => {
  it("flags known C2 IPs and the Tor exit range", () => {
    expect(localVerdict("IP", "99.88.77.66").score).toBeGreaterThanOrEqual(0.9);
    expect(localVerdict("IP", "185.220.101.200").score).toBe(0.7);
    expect(localVerdict("IP", "8.8.8.8").score).toBe(0);
  });

  it("flags brand impersonation but not the brand itself", () => {
    expect(localVerdict("DOMAIN", "paypal-account-verify.xyz").score).toBeGreaterThan(0);
    expect(localVerdict("DOMAIN", "paypal.com").score).toBe(0);
    expect(localVerdict("URL", "https://microsoftonline-login.top/x").reasons.length).toBeGreaterThan(0);
  });

  it("only reports 'clean' when a real provider was consulted", () => {
    expect(verdictForScore(0, false)).toBe("unknown");
    expect(verdictForScore(0, true)).toBe("clean");
    expect(verdictForScore(0.75, false)).toBe("malicious");
    expect(verdictForScore(0.45, true)).toBe("suspicious");
    expect(verdictForScore(null, true)).toBe("unknown");
  });

  it("saturates VirusTotal engine counts into a 0-1 score", () => {
    expect(scoreVirusTotalStats({ malicious: 0, suspicious: 0 })).toBe(0);
    expect(scoreVirusTotalStats({ malicious: 1 })).toBeCloseTo(0.46);
    expect(scoreVirusTotalStats({ malicious: 10 })).toBe(1);
    expect(scoreVirusTotalStats({ suspicious: 1 })).toBeCloseTo(0.23);
  });
});
