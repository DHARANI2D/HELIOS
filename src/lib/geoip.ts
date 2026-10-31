import { readFileSync, statSync } from "node:fs";
import { isIP } from "node:net";

import { Reader, type AsnResponse, type CityResponse, type Response } from "maxmind";

import { isPrivateAddress } from "@/lib/net/public-fetch";

// Where an IP address is, from MaxMind-format databases on the server's own
// disk: no lookup leaves the machine. Two files, both optional:
//
//   HELIOS_GEOIP_CITY_DB  GeoLite2-City / GeoIP2-City (or a -Country file:
//                         country only), or DB-IP's IP-to-City Lite
//   HELIOS_GEOIP_ASN_DB   GeoLite2-ASN, or DB-IP's IP-to-ASN Lite
//
// Keep them current with MaxMind's geoipupdate (or a monthly DB-IP
// download); a file that changes on disk is picked up within a minute.
// Private and reserved addresses are never looked up.

export interface GeoInfo {
  country: string | null; // ISO 3166-1 alpha-2
  countryName: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  // MaxMind's radius around lat/lon the address is likely within.
  accuracyKm: number | null;
  asn: number | null;
  asOrg: string | null;
}

interface Loaded<T extends Response> {
  path: string;
  mtimeMs: number;
  checkedAt: number;
  reader: Reader<T>;
}

const RECHECK_MS = 60_000;
const warned = new Set<string>();
let cityDb: Loaded<CityResponse> | null = null;
let asnDb: Loaded<AsnResponse> | null = null;

function load<T extends CityResponse | AsnResponse>(path: string | undefined, current: Loaded<T> | null): Loaded<T> | null {
  if (!path) return null;
  const now = Date.now();
  if (current?.path === path && now - current.checkedAt < RECHECK_MS) return current;
  try {
    const { mtimeMs } = statSync(path);
    if (current?.path === path && current.mtimeMs === mtimeMs) {
      current.checkedAt = now;
      return current;
    }
    return { path, mtimeMs, checkedAt: now, reader: new Reader<T>(readFileSync(path)) };
  } catch (e) {
    const key = `${path}:${e instanceof Error ? e.message : e}`;
    if (!warned.has(key)) {
      warned.add(key);
      console.error(`[geoip] can't read ${path}: ${e instanceof Error ? e.message : e}`);
    }
    // A failed refresh keeps the copy already loaded.
    return current?.path === path ? current : null;
  }
}

function readers() {
  cityDb = load(process.env.HELIOS_GEOIP_CITY_DB, cityDb);
  asnDb = load(process.env.HELIOS_GEOIP_ASN_DB, asnDb);
  return { city: cityDb?.reader ?? null, asn: asnDb?.reader ?? null };
}

export function geoConfigured() {
  return !!(process.env.HELIOS_GEOIP_CITY_DB || process.env.HELIOS_GEOIP_ASN_DB);
}

// An address as people and logs write it: brackets, a zone, an IPv4-mapped
// IPv6 form.
export function plainIp(raw: string): string | null {
  const ip = raw.trim().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  const v = mapped ? mapped[1] : ip;
  return isIP(v) ? v : null;
}

export function geoLookup(raw: string | null | undefined): GeoInfo | null {
  if (!raw) return null;
  const ip = plainIp(raw);
  if (!ip || isPrivateAddress(ip)) return null;
  const { city, asn } = readers();
  if (!city && !asn) return null;
  let c: CityResponse | null = null;
  let a: AsnResponse | null = null;
  try {
    c = city?.get(ip) ?? null;
    a = asn?.get(ip) ?? null;
  } catch {
    // An IPv6 address against an IPv4-only database.
    return null;
  }
  if (!c && !a) return null;
  const country = c?.country ?? c?.registered_country;
  return {
    country: country?.iso_code ?? null,
    countryName: country?.names?.en ?? null,
    city: c?.city?.names?.en ?? null,
    lat: c?.location?.latitude ?? null,
    lon: c?.location?.longitude ?? null,
    accuracyKm: c?.location?.accuracy_radius ?? null,
    asn: a?.autonomous_system_number ?? null,
    asOrg: a?.autonomous_system_organization ?? null,
  };
}

// "Mumbai, India · AS64500 Test Telecom India"
export function describeGeo(g: GeoInfo | null | undefined): string | null {
  if (!g) return null;
  const place = [g.city, g.countryName ?? g.country].filter(Boolean).join(", ");
  const as = g.asn ? `AS${g.asn}${g.asOrg ? ` ${g.asOrg}` : ""}` : "";
  return [place, as].filter(Boolean).join(" · ") || null;
}

// What's loaded, for the settings page. DB-IP's free databases ask for
// attribution wherever their data is shown.
export function geoStatus() {
  readers();
  const info = (d: Loaded<CityResponse> | Loaded<AsnResponse> | null, env: string) =>
    d ? { path: d.path, type: d.reader.metadata.databaseType, built: d.reader.metadata.buildEpoch.toISOString() } : process.env[env] ? { path: process.env[env]!, type: null, built: null, error: "can't be read" } : null;
  const city = info(cityDb, "HELIOS_GEOIP_CITY_DB");
  const asn = info(asnDb, "HELIOS_GEOIP_ASN_DB");
  const dbip = [city?.type, asn?.type].some((t) => t && /db-?ip/i.test(t));
  return { city, asn, attribution: dbip ? "IP geolocation by DB-IP (db-ip.com), CC BY 4.0" : null };
}

// ------------------------------------------------------------ events

// The compact form stored on an event's metadata (metadata.geoip).
export type StoredGeo = Partial<Omit<GeoInfo, "countryName">> & { countryName?: string | null };

function compact(g: GeoInfo): StoredGeo {
  return Object.fromEntries(Object.entries(g).filter(([, v]) => v != null)) as StoredGeo;
}

type JsonObject = Record<string, unknown>;
const isObject = (v: unknown): v is JsonObject => !!v && typeof v === "object" && !Array.isArray(v);

function ocsfEndpoint(endpoint: unknown, ip: string, g: GeoInfo) {
  if (!isObject(endpoint) || endpoint.ip !== ip) return endpoint;
  const location = isObject(endpoint.location) ? endpoint.location : {};
  return {
    ...endpoint,
    location: {
      ...(g.country ? { country: g.country } : {}),
      ...(g.city ? { city: g.city } : {}),
      ...(g.lat != null && g.lon != null ? { coordinates: [g.lon, g.lat] } : {}),
      ...location,
    },
    ...(g.asn && !endpoint.autonomous_system ? { autonomous_system: { number: g.asn, ...(g.asOrg ? { name: g.asOrg } : {}) } } : {}),
  };
}

export interface GeoRow {
  sourceIp?: string | null;
  destIp?: string | null;
  geo?: string | null;
  metadata?: unknown;
  ocsf?: unknown;
}

// Adds where the event's addresses are: the country to `geo` when the
// source didn't give one (the source address's, else the destination's),
// the detail to metadata.geoip, and the location and AS to the OCSF
// endpoints. A row with nothing to look up comes back as it was.
export function enrichGeo<T extends GeoRow>(row: T): T {
  const src = geoLookup(row.sourceIp);
  const dst = geoLookup(row.destIp);
  if (!src && !dst) return row;
  const metadata = isObject(row.metadata) ? row.metadata : {};
  const ocsf = isObject(row.ocsf) ? row.ocsf : null;
  return {
    ...row,
    geo: row.geo || src?.country || dst?.country || null,
    metadata: { ...metadata, geoip: { ...(src ? { src: compact(src) } : {}), ...(dst ? { dst: compact(dst) } : {}) } },
    ...(ocsf
      ? {
          ocsf: {
            ...ocsf,
            ...(src && row.sourceIp ? { src_endpoint: ocsfEndpoint(ocsf.src_endpoint, row.sourceIp, src) } : {}),
            ...(dst && row.destIp ? { dst_endpoint: ocsfEndpoint(ocsf.dst_endpoint, row.destIp, dst) } : {}),
          },
        }
      : {}),
  } as T;
}

export function enrichAll<T extends GeoRow>(rows: T[]): T[] {
  return geoConfigured() ? rows.map(enrichGeo) : rows;
}

// The stored detail back off an event's metadata.
export function storedGeo(metadata: unknown, side: "src" | "dst" = "src"): StoredGeo | null {
  const g = isObject(metadata) && isObject(metadata.geoip) ? metadata.geoip[side] : null;
  return isObject(g) ? (g as StoredGeo) : null;
}
