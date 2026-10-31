import { isIP } from "node:net";

// Builds small MaxMind DB (.mmdb) files for tests, from the published format
// spec (https://maxmind.github.io/MaxMind-DB/): an IPv6 search tree with
// 24-bit records, IPv4 networks under ::/96, the data section and the
// metadata. The maxmind reader HELIOS uses reads them back, which is the
// check that they're well formed. Tests use documentation ranges only.

export type MmdbValue = string | number | boolean | MmdbValue[] | { [key: string]: MmdbValue } | { double: number } | { uint: number; bytes: 2 | 4 | 8 };

// Explicit number types where the spec wants them; a bare integer is a
// uint32, a bare fraction a double.
export const double = (n: number): MmdbValue => ({ double: n });
export const uint16 = (n: number): MmdbValue => ({ uint: n, bytes: 2 });
export const uint32 = (n: number): MmdbValue => ({ uint: n, bytes: 4 });
export const uint64 = (n: number): MmdbValue => ({ uint: n, bytes: 8 });

function control(type: number, size: number): Buffer {
  const extended = type > 7;
  const first = (extended ? 0 : type) << 5;
  const ext = extended ? [type - 7] : [];
  if (size < 29) return Buffer.from([first | size, ...ext]);
  if (size < 285) return Buffer.from([first | 29, ...ext, size - 29]);
  if (size < 65821) return Buffer.from([first | 30, ...ext, (size - 285) >> 8, (size - 285) & 0xff]);
  const s = size - 65821;
  return Buffer.from([first | 31, ...ext, (s >> 16) & 0xff, (s >> 8) & 0xff, s & 0xff]);
}

function unsigned(n: number, type: number): Buffer {
  const bytes: number[] = [];
  // Plain arithmetic: exact for the integers tests use (below 2^53).
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return Buffer.concat([control(type, bytes.length), Buffer.from(bytes)]);
}

export function encode(value: MmdbValue): Buffer {
  if (typeof value === "string") {
    const b = Buffer.from(value, "utf8");
    return Buffer.concat([control(2, b.length), b]);
  }
  if (typeof value === "boolean") return control(14, value ? 1 : 0);
  if (typeof value === "number") {
    if (Number.isInteger(value) && value >= 0) return unsigned(value, 6);
    return encode(double(value));
  }
  if (Array.isArray(value)) return Buffer.concat([control(11, value.length), ...value.map(encode)]);
  if ("double" in value && typeof value.double === "number" && Object.keys(value).length === 1) {
    const b = Buffer.alloc(8);
    b.writeDoubleBE(value.double);
    return Buffer.concat([control(3, 8), b]);
  }
  if ("uint" in value && "bytes" in value && Object.keys(value).length === 2) {
    const v = value as { uint: number; bytes: 2 | 4 | 8 };
    return unsigned(v.uint, v.bytes === 2 ? 5 : v.bytes === 4 ? 6 : 9);
  }
  const entries = Object.entries(value as Record<string, MmdbValue>);
  return Buffer.concat([control(7, entries.length), ...entries.flatMap(([k, v]) => [encode(k), encode(v)])]);
}

// The network's bits in the 128-bit tree (IPv4 lives under ::/96).
function prefixBits(cidr: string): number[] {
  const [addr, lenText] = cidr.split("/");
  const len = Number(lenText);
  let bits: number[] = [];
  if (isIP(addr) === 4) {
    bits = Array(96).fill(0);
    for (const octet of addr.split(".").map(Number)) for (let i = 7; i >= 0; i--) bits.push((octet >> i) & 1);
    return bits.slice(0, 96 + len);
  }
  const [head, tail = ""] = addr.split("::");
  const groups = (s: string) => (s ? s.split(":").map((g) => parseInt(g, 16)) : []);
  const h = groups(head);
  const t = groups(tail);
  const all = [...h, ...Array(8 - h.length - t.length).fill(0), ...t];
  for (const g of all) for (let i = 15; i >= 0; i--) bits.push((g >> i) & 1);
  return bits.slice(0, len);
}

interface Node {
  child: [Node | number | null, Node | number | null]; // a node, a data offset, or empty
}

export function buildMmdb(opts: { databaseType: string; networks: Array<[cidr: string, data: MmdbValue]>; buildEpoch?: number }): Buffer {
  // Data section: each record once, at its offset.
  const chunks: Buffer[] = [];
  const offsets: number[] = [];
  let at = 0;
  for (const [, data] of opts.networks) {
    const b = encode(data);
    offsets.push(at);
    chunks.push(b);
    at += b.length;
  }
  const dataSection = Buffer.concat(chunks);

  // The tree: a leaf record holds { data: offset }.
  const root: Node = { child: [null, null] };
  opts.networks.forEach(([cidr], i) => {
    const bits = prefixBits(cidr);
    let node = root;
    for (let d = 0; d < bits.length - 1; d++) {
      const next = node.child[bits[d]];
      if (next == null) node.child[bits[d]] = { child: [null, null] };
      else if (typeof next === "number") throw new Error(`${cidr} is inside another network`);
      node = node.child[bits[d]] as Node;
    }
    node.child[bits[bits.length - 1]] = -1 - offsets[i]; // marks a data record
  });

  // Number the nodes breadth first, then write the records.
  const order: Node[] = [];
  const index = new Map<Node, number>();
  const queue = [root];
  while (queue.length) {
    const n = queue.shift()!;
    index.set(n, order.length);
    order.push(n);
    for (const c of n.child) if (c && typeof c === "object") queue.push(c);
  }
  const nodeCount = order.length;
  const tree = Buffer.alloc(nodeCount * 6);
  const record = (c: Node | number | null) => (c == null ? nodeCount : typeof c === "number" ? nodeCount + 16 + (-1 - c) : index.get(c)!);
  order.forEach((n, i) => {
    tree.writeUIntBE(record(n.child[0]), i * 6, 3);
    tree.writeUIntBE(record(n.child[1]), i * 6 + 3, 3);
  });

  const metadata = encode({
    binary_format_major_version: uint16(2),
    binary_format_minor_version: uint16(0),
    build_epoch: uint64(opts.buildEpoch ?? 1_790_000_000),
    database_type: opts.databaseType,
    description: { en: "HELIOS test data (documentation ranges only)" },
    ip_version: uint16(6),
    languages: ["en"],
    node_count: uint32(nodeCount),
    record_size: uint16(24),
  });
  return Buffer.concat([tree, Buffer.alloc(16), dataSection, Buffer.from([0xab, 0xcd, 0xef]), Buffer.from("MaxMind.com"), metadata]);
}

// Made-up places on documentation and benchmark ranges (RFC 5737, 3849,
// 2544), in GeoIP2-City and GeoLite2-ASN form.
export const TEST_PLACES = [
  { cidr: "198.51.100.0/24", iso: "IN", country: "India", city: "Mumbai", lat: 19.076, lon: 72.8777, accuracy: 20, asn: 64500, org: "Test Telecom India" },
  { cidr: "192.0.2.0/24", iso: "IN", country: "India", city: "Delhi", lat: 28.6139, lon: 77.209, accuracy: 20, asn: 64501, org: "Test Broadband Delhi" },
  { cidr: "203.0.113.0/24", iso: "BR", country: "Brazil", city: "São Paulo", lat: -23.5505, lon: -46.6333, accuracy: 50, asn: 64502, org: "Test Hosting Brasil" },
  { cidr: "2001:db8:100::/48", iso: "DE", country: "Germany", city: "Frankfurt am Main", lat: 50.1109, lon: 8.6821, accuracy: 100, asn: 64503, org: "Test Cloud Europe" },
  // Country only, as a mobile network often is: no city, a wide radius.
  { cidr: "198.18.0.0/15", iso: "US", country: "United States", city: null, lat: 37.751, lon: -97.822, accuracy: 1000, asn: 64504, org: "Test Mobile US" },
];

export function testCityDb() {
  return buildMmdb({
    databaseType: "GeoIP2-City",
    networks: TEST_PLACES.map((p) => [
      p.cidr,
      {
        country: { iso_code: p.iso, names: { en: p.country } },
        location: { latitude: double(p.lat), longitude: double(p.lon), accuracy_radius: uint16(p.accuracy) },
        ...(p.city ? { city: { names: { en: p.city } } } : {}),
      },
    ]),
  });
}

export function testAsnDb() {
  return buildMmdb({ databaseType: "GeoLite2-ASN", networks: TEST_PLACES.map((p) => [p.cidr, { autonomous_system_number: uint32(p.asn), autonomous_system_organization: p.org }]) });
}
