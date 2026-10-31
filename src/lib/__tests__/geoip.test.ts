import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { buildMmdb, double, testAsnDb, testCityDb, uint16 } from "@/lib/__tests__/fixtures/mmdb-builder";
import { describeGeo, enrichAll, enrichGeo, geoLookup, geoStatus, plainIp, storedGeo } from "@/lib/geoip";
import { normalize } from "@/lib/siem/adapters";
import { runDetections } from "@/lib/siem/engine";
import { travelKm } from "@/lib/siem/detectors/behavioral";
import type { UnifiedEvent } from "@/lib/siem/types";

const dir = mkdtempSync(path.join(tmpdir(), "helios-geoip-"));
const cityPath = path.join(dir, "city.mmdb");
const asnPath = path.join(dir, "asn.mmdb");

beforeAll(() => {
  writeFileSync(cityPath, testCityDb());
  writeFileSync(asnPath, testAsnDb());
  process.env.HELIOS_GEOIP_CITY_DB = cityPath;
  process.env.HELIOS_GEOIP_ASN_DB = asnPath;
});
afterAll(() => {
  delete process.env.HELIOS_GEOIP_CITY_DB;
  delete process.env.HELIOS_GEOIP_ASN_DB;
  rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.useRealTimers());

describe("looking up where an address is", () => {
  it("reads city, coordinates and network for IPv4 and IPv6", () => {
    expect(geoLookup("198.51.100.7")).toEqual({ country: "IN", countryName: "India", city: "Mumbai", lat: 19.076, lon: 72.8777, accuracyKm: 20, asn: 64500, asOrg: "Test Telecom India" });
    expect(geoLookup("2001:db8:100::5")).toMatchObject({ country: "DE", city: "Frankfurt am Main", asn: 64503 });
    // A country-only answer: no city, a wide radius.
    expect(geoLookup("198.19.4.4")).toMatchObject({ country: "US", city: null, accuracyKm: 1000 });
    expect(describeGeo(geoLookup("203.0.113.140"))).toBe("São Paulo, Brazil · AS64502 Test Hosting Brasil");
  });

  it("takes addresses as logs write them, and never looks up private ones", () => {
    expect(plainIp("[2001:db8:100::5]")).toBe("2001:db8:100::5");
    expect(plainIp("::ffff:198.51.100.7")).toBe("198.51.100.7");
    expect(plainIp("fe80::1%eth0")).toBe("fe80::1");
    expect(plainIp("not-an-ip")).toBeNull();
    expect(geoLookup("::ffff:198.51.100.7")?.city).toBe("Mumbai");
    for (const ip of ["10.1.2.3", "192.168.0.10", "127.0.0.1", "::1", "fe80::1"]) expect(geoLookup(ip)).toBeNull();
    expect(geoLookup("8.8.8.8")).toBeNull(); // not in the test data
    expect(geoLookup(null)).toBeNull();
  });

  it("says what's loaded, and credits DB-IP when its data is in use", () => {
    expect(geoStatus()).toMatchObject({ city: { type: "GeoIP2-City", path: cityPath }, asn: { type: "GeoLite2-ASN" }, attribution: null });
  });

  it("picks up a database replaced on disk, and keeps going when one can't be read", () => {
    vi.useFakeTimers({ now: Date.now() });
    const dbip = buildMmdb({ databaseType: "DBIP-City-Lite", networks: [["198.51.100.0/24", { country: { iso_code: "IN" }, city: { names: { en: "Pune" } }, location: { latitude: double(18.52), longitude: double(73.86), accuracy_radius: uint16(10) } }]] });
    writeFileSync(cityPath, dbip);
    utimesSync(cityPath, new Date(), new Date(Date.now() + 5_000));
    // Rechecked at most once a minute.
    expect(geoLookup("198.51.100.7")?.city).toBe("Mumbai");
    vi.setSystemTime(Date.now() + 61_000);
    expect(geoLookup("198.51.100.7")?.city).toBe("Pune");
    expect(geoStatus().attribution).toMatch(/DB-IP/);

    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    process.env.HELIOS_GEOIP_ASN_DB = path.join(dir, "missing.mmdb");
    vi.setSystemTime(Date.now() + 61_000);
    expect(geoLookup("198.51.100.7")).toMatchObject({ city: "Pune", asn: null });
    expect(geoLookup("198.51.100.8")).toMatchObject({ asn: null });
    expect(errors).toHaveBeenCalledTimes(1);
    expect(geoStatus().asn).toMatchObject({ error: "can't be read" });
    errors.mockRestore();
    process.env.HELIOS_GEOIP_ASN_DB = asnPath;
    writeFileSync(cityPath, testCityDb());
    utimesSync(cityPath, new Date(), new Date(Date.now() + 10_000));
    vi.setSystemTime(Date.now() + 61_000);
    expect(geoLookup("198.51.100.7")?.city).toBe("Mumbai");
  });
});

describe("adding it to events", () => {
  it("stores the country, the detail, and the OCSF location and network", () => {
    const row = enrichGeo({ sourceIp: "198.51.100.7", destIp: "10.0.0.5", geo: null, metadata: { vendor: "x" }, ocsf: { class_uid: 3002, src_endpoint: { ip: "198.51.100.7" }, dst_endpoint: { ip: "10.0.0.5" } } });
    expect(row.geo).toBe("IN");
    expect(row.metadata).toEqual({ vendor: "x", geoip: { src: { country: "IN", countryName: "India", city: "Mumbai", lat: 19.076, lon: 72.8777, accuracyKm: 20, asn: 64500, asOrg: "Test Telecom India" } } });
    expect(row.ocsf).toMatchObject({ src_endpoint: { ip: "198.51.100.7", location: { country: "IN", city: "Mumbai", coordinates: [72.8777, 19.076] }, autonomous_system: { number: 64500, name: "Test Telecom India" } }, dst_endpoint: { ip: "10.0.0.5" } });
    expect(storedGeo(row.metadata)?.city).toBe("Mumbai");
  });

  it("uses the destination when the source is internal, and keeps what the source said", () => {
    expect(enrichGeo({ sourceIp: "10.0.0.5", destIp: "203.0.113.9", geo: null, metadata: null }).geo).toBe("BR");
    const own = enrichGeo({ sourceIp: "198.51.100.7", geo: "India", metadata: {}, ocsf: { src_endpoint: { ip: "198.51.100.7", location: { city: "Navi Mumbai" } } } });
    expect(own.geo).toBe("India");
    expect((own.ocsf as { src_endpoint: { location: { city: string } } }).src_endpoint.location.city).toBe("Navi Mumbai");
    const internal = { sourceIp: "10.0.0.5", destIp: "10.0.0.6", geo: null, metadata: { a: 1 } };
    expect(enrichGeo(internal)).toBe(internal);
  });

  it("does nothing at all without a database", () => {
    const saved = [process.env.HELIOS_GEOIP_CITY_DB, process.env.HELIOS_GEOIP_ASN_DB];
    delete process.env.HELIOS_GEOIP_CITY_DB;
    delete process.env.HELIOS_GEOIP_ASN_DB;
    const rows = [{ sourceIp: "198.51.100.7", geo: null, metadata: null }];
    expect(enrichAll(rows)).toBe(rows);
    expect(geoLookup("198.51.100.7")).toBeNull();
    [process.env.HELIOS_GEOIP_CITY_DB, process.env.HELIOS_GEOIP_ASN_DB] = saved;
  });
});

describe("impossible travel with GeoIP", () => {
  const at = (minutes: number) => new Date(Date.UTC(2026, 9, 20, 8, 0) + minutes * 60_000).toISOString();
  const login = (user: string, ip: string, minutes: number): UnifiedEvent => {
    const e = normalize("auth", { user, result: "SUCCESS", source_ip: ip, timestamp: at(minutes) });
    const g = enrichGeo({ sourceIp: ip, geo: null, metadata: {} });
    return { ...e, id: `${user}-${ip}-${minutes}`, network: { ...e.network, geo: g.geo ?? undefined }, metadata: (g.metadata ?? {}) as Record<string, unknown> };
  };
  const travel = (events: UnifiedEvent[]) => runDetections(events).filter((d) => d.detectionSource === "GEO_VELOCITY");

  it("catches travel inside one country that country-level data misses", () => {
    // Mumbai to Delhi (~1,150 km) in 30 minutes.
    const d = travel([login("asha", "198.51.100.7", 0), login("asha", "192.0.2.10", 30)]);
    expect(d).toHaveLength(1);
    expect(d[0].reasoning.join(" ")).toMatch(/Mumbai, India and then Delhi, India .*GeoIP positions, less their accuracy radii/);
    // The same trip over three hours is a flight.
    expect(travel([login("asha", "198.51.100.7", 0), login("asha", "192.0.2.10", 180)])).toHaveLength(0);
  });

  it("measures between cities, less the accuracy radii", () => {
    const t = travelKm(login("u", "198.51.100.7", 0), login("u", "203.0.113.9", 60))!;
    expect(t.precise).toBe(true);
    expect(t.km).toBeGreaterThan(13_500);
    expect(t.km).toBeLessThan(13_800);
    expect(travel([login("b", "198.51.100.7", 0), login("b", "203.0.113.9", 60)])).toHaveLength(1);
  });

  it("doesn't call a country-wide guess travel", () => {
    // A US mobile address is only known within 1,000 km; Frankfurt is far
    // beyond that, so it still counts.
    expect(travelKm(login("c", "198.19.4.4", 0), login("c", "198.18.9.9", 5))).toMatchObject({ km: 0, precise: true });
    expect(travel([login("c", "198.19.4.4", 0), login("c", "198.18.9.9", 5)])).toHaveLength(0);
    expect(travel([login("c", "198.19.4.4", 0), login("c", "2001:db8:100::7", 30)])).toHaveLength(1);
  });

  it("falls back to country centroids for ISO codes when there are no coordinates", () => {
    const plain = (user: string, geo: string, minutes: number): UnifiedEvent => ({ ...normalize("auth", { user, result: "SUCCESS", geo_location: geo, timestamp: at(minutes) }), id: `${user}-${geo}-${minutes}` });
    expect(travelKm(plain("d", "IN", 0), plain("d", "BR", 60))?.km).toBeGreaterThan(10_000);
    expect(travel([plain("d", "IN", 0), plain("d", "BR", 60)])).toHaveLength(1);
    // The same country written two ways is no distance at all.
    expect(travelKm(plain("e", "IN", 0), plain("e", "India", 60))?.km).toBe(0);
  });
});
