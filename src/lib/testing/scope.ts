import { isIP } from "node:net";

import { isPrivateAddress } from "@/lib/net/public-fetch";

// What a security test may touch, and the proof it's the client's.
// HELIOS tests only what the client has shown it controls:
//   - a name (example.com, vpn.example.com) is verified by a DNS TXT
//     record "helios-verify=<token>" on the name itself or on
//     _helios-verify.<name>, or by a parent name in the same test that is;
//   - an IP address only if a verified name in the test resolves to it;
//   - a URL by its host.
// Private and internal addresses are never tested from HELIOS; ranges
// (CIDR) aren't accepted: list the addresses.

export interface ScopeTarget {
  value: string;
  kind: "name" | "ip" | "url";
  verified: boolean;
  via: string | null;
  verifiedAt: string | null;
  addresses: string[];
  problem: string | null;
}

export const MAX_TARGETS = 25;
const NAME = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

export class ScopeError extends Error {}

export function parseTargets(input: string): ScopeTarget[] {
  const values = [...new Set(input.split(/[\s,;]+/).map((v) => v.trim()).filter(Boolean))];
  if (!values.length) throw new ScopeError("List at least one domain, host name, IP address or URL to test");
  if (values.length > MAX_TARGETS) throw new ScopeError(`At most ${MAX_TARGETS} targets in one test`);
  return values.map((raw) => {
    const base = { verified: false, via: null, verifiedAt: null, addresses: [], problem: null };
    if (raw.includes("/") && !/^https?:\/\//i.test(raw)) throw new ScopeError(`${raw}: ranges aren't accepted; list the addresses or names`);
    if (/^https?:\/\//i.test(raw)) {
      let u: URL;
      try {
        u = new URL(raw);
      } catch {
        throw new ScopeError(`${raw} isn't a valid URL`);
      }
      const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
      if (isIP(host) && isPrivateAddress(host)) throw new ScopeError(`${raw}: private and internal addresses aren't tested from HELIOS`);
      if (!isIP(host) && !NAME.test(host)) throw new ScopeError(`${raw}: the host isn't a valid name`);
      return { ...base, value: `${u.protocol}//${u.host}${u.pathname === "/" ? "" : u.pathname}`, kind: "url" as const };
    }
    const v = raw.toLowerCase().replace(/\.$/, "");
    if (isIP(v)) {
      if (isPrivateAddress(v)) throw new ScopeError(`${v}: private and internal addresses aren't tested from HELIOS`);
      return { ...base, value: v, kind: "ip" as const };
    }
    if (!NAME.test(v)) throw new ScopeError(`${raw} isn't a domain, host name, IP address or URL`);
    return { ...base, value: v, kind: "name" as const };
  });
}

export const hostOf = (t: Pick<ScopeTarget, "value" | "kind">) => (t.kind === "url" ? new URL(t.value).hostname.replace(/^\[|\]$/g, "").toLowerCase() : t.value);

export interface Resolver {
  txt(name: string): Promise<string[][]>;
  addresses(name: string): Promise<string[]>;
}

export const verifyRecord = (token: string) => `helios-verify=${token}`;

// Checks each target and records how it was verified (or why not).
export async function verifyScope(targets: ScopeTarget[], token: string, dns: Resolver, now = new Date()): Promise<ScopeTarget[]> {
  const expected = verifyRecord(token);
  const at = now.toISOString();
  const names = new Map<string, { verified: boolean; via: string | null; addresses: string[] }>();

  const hasRecord = async (name: string) => {
    for (const q of [name, `_helios-verify.${name}`]) {
      const records = await dns.txt(q).catch(() => [] as string[][]);
      if (records.some((parts) => parts.join("").trim() === expected)) return q;
    }
    return null;
  };

  // Names first (shortest first, so parents settle before children).
  const allNames = [...new Set(targets.filter((t) => t.kind !== "ip").map(hostOf).filter((h) => !isIP(h)))].sort((a, b) => a.split(".").length - b.split(".").length);
  for (const name of allNames) {
    const parent = [...names.entries()].find(([n, s]) => s.verified && name.endsWith(`.${n}`));
    const record = parent ? null : await hasRecord(name);
    const addresses = await dns.addresses(name).catch(() => [] as string[]);
    names.set(name, { verified: !!(parent || record), via: parent ? `parent name ${parent[0]} is verified` : record ? `DNS TXT on ${record}` : null, addresses });
  }
  const verifiedAddresses = new Map<string, string>();
  for (const [name, s] of names) if (s.verified) for (const a of s.addresses) if (!verifiedAddresses.has(a)) verifiedAddresses.set(a, name);

  return targets.map((t) => {
    const host = hostOf(t);
    if (t.kind === "ip" || isIP(host)) {
      const ip = host;
      const by = verifiedAddresses.get(ip);
      return { ...t, verified: !!by, via: by ? `${by} resolves to it` : null, verifiedAt: by ? at : null, addresses: [ip], problem: by ? null : "No verified name in this test resolves to this address" };
    }
    const s = names.get(host)!;
    const priv = s.addresses.filter(isPrivateAddress);
    const problem = !s.verified
      ? `No TXT record "${expected}" on ${host} or _helios-verify.${host}, and no verified parent name in this test`
      : !s.addresses.length
        ? `${host} doesn't resolve`
        : priv.length
          ? `${host} resolves to private or internal addresses (${priv.join(", ")}); those aren't tested from HELIOS`
          : null;
    return { ...t, verified: s.verified && !problem, via: s.via, verifiedAt: s.verified && !problem ? at : null, addresses: s.addresses.filter((a) => !isPrivateAddress(a)), problem };
  });
}

// Is a host or address a scanner reported one of this test's verified
// targets (or an address they resolve to)? Only what was authorised is
// reported, not the rest of the domain.
export function inScope(targets: ScopeTarget[], hostOrIp: string): boolean {
  const h = hostOrIp.toLowerCase().replace(/\.$/, "");
  return targets.some((t) => t.verified && (hostOf(t) === h || t.addresses.includes(h)));
}
