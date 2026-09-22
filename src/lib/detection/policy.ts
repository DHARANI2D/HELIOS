// Ported from signal-fusion's config/policy.ts SecurityPolicy.

export const SecurityPolicy = {
  geoVelocity: {
    maxKmPerHour: 900,
  },
  threatIntel: {
    maliciousIps: ["99.88.77.66", "45.33.22.11", "103.22.11.55"],
    suspiciousProcesses: [
      "mimikatz.exe",
      "nc.exe",
      "pingsweep.ps1",
      "cobaltstrike.beacon",
      "psexec.exe",
    ],
  },
  fsmChain: {
    sensitiveSources: ["CLOUD", "ENDPOINT"] as const,
  },
};
