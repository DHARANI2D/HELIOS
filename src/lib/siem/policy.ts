// Ported from signal-fusion's config/policy.ts — detection thresholds in one
// place. Known-bad indicators come from the shared indicator store (feeds,
// provider lookups, blocks — lib/threat-intel/snapshot.ts), never a list here.

export const SecurityPolicy = {
  geoVelocity: {
    maxKmPerHour: 800, // faster than this between two logins = impossible travel
    unknownDistanceKm: 1000, // assumed when a location isn't in the centroid table
    // With GeoIP coordinates, two logins closer than this (after taking off
    // each address's accuracy radius) aren't travel worth flagging.
    minKm: 500,
  },
  threatIntel: {
    suspiciousProcesses: ["mimikatz.exe", "nc.exe", "pingsweep.ps1", "cobaltstrike.beacon", "psexec.exe"],
  },
  fsmChain: {
    sensitiveSources: ["cloud", "endpoint"],
    maxChainTimeGapMs: 1000 * 60 * 30, // 30 minutes
  },
  bruteForce: {
    minDistinctUsers: 5,
    minFailures: 5,
  },
  exfiltration: {
    networkBytesThreshold: 100 * 1024 * 1024, // 100 MB
    cloudUploadBytesThreshold: 10 * 1024 * 1024, // 10 MB
    longDnsQueryLength: 50,
    longDnsQueryCount: 10,
  },
  reconnaissance: {
    portScanDistinctPorts: 10,
    dnsEnumerationQueries: 50,
  },
};

// Approximate country centroids (lat, lon) for the geo-velocity detector.
// signal-fusion assumed a flat 1000 km between any two different locations;
// this keeps that as the fallback but uses real distances where it can.
export const GEO_CENTROIDS: Record<string, [number, number]> = {
  "united states": [39.8, -98.6],
  usa: [39.8, -98.6],
  us: [39.8, -98.6],
  canada: [56.1, -106.3],
  mexico: [23.6, -102.5],
  brazil: [-14.2, -51.9],
  "united kingdom": [55.4, -3.4],
  uk: [55.4, -3.4],
  ireland: [53.4, -8.2],
  france: [46.2, 2.2],
  germany: [51.2, 10.5],
  netherlands: [52.1, 5.3],
  spain: [40.5, -3.7],
  italy: [41.9, 12.6],
  poland: [51.9, 19.1],
  ukraine: [48.4, 31.2],
  russia: [61.5, 105.3],
  turkey: [39.0, 35.2],
  israel: [31.0, 34.9],
  iran: [32.4, 53.7],
  "saudi arabia": [23.9, 45.1],
  uae: [23.4, 53.8],
  india: [20.6, 79.0],
  china: [35.9, 104.2],
  "north korea": [40.3, 127.5],
  "south korea": [35.9, 127.8],
  japan: [36.2, 138.3],
  singapore: [1.35, 103.8],
  australia: [-25.3, 133.8],
  nigeria: [9.1, 8.7],
  "south africa": [-30.6, 22.9],
  egypt: [26.8, 30.8],
};

// ISO 3166-1 alpha-2 codes (what GeoIP databases and many sources give) for
// the same countries.
const ISO_NAMES: Record<string, string> = {
  us: "united states", ca: "canada", mx: "mexico", br: "brazil", gb: "united kingdom", ie: "ireland", fr: "france", de: "germany", nl: "netherlands",
  es: "spain", it: "italy", pl: "poland", ua: "ukraine", ru: "russia", tr: "turkey", il: "israel", ir: "iran", sa: "saudi arabia", ae: "uae", in: "india",
  cn: "china", kp: "north korea", kr: "south korea", jp: "japan", sg: "singapore", au: "australia", ng: "nigeria", za: "south africa", eg: "egypt",
};
for (const [code, name] of Object.entries(ISO_NAMES)) GEO_CENTROIDS[code] ??= GEO_CENTROIDS[name];
