import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

import { isPrivateIp } from "@/lib/threat-intel/indicators";

// Fetching a URL someone typed (a client admin, say) from the server: only
// https, only to hosts that resolve to public addresses, and no redirects,
// so it can't be pointed at the cloud metadata endpoint or an internal
// service. The address is checked at lookup; a host that changes its DNS
// between the check and the fetch is the remaining gap.

export function isPrivateAddress(ip: string) {
  if (isIP(ip) === 4) return isPrivateIp(ip);
  const v6 = ip.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v6);
  if (mapped) return isPrivateIp(mapped[1]);
  return v6 === "::" || v6 === "::1" || /^fe[89ab]/.test(v6) || /^f[cd]/.test(v6) || v6.startsWith("ff");
}

export async function assertPublicUrl(raw: string) {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("That isn't a URL");
  }
  if (url.protocol !== "https:") throw new Error("Only https:// addresses");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = isIP(host) ? [host] : (await lookup(host, { all: true }).catch(() => [])).map((a) => a.address);
  if (!addresses.length) throw new Error(`${host} doesn't resolve`);
  if (addresses.some(isPrivateAddress)) throw new Error(`${host} is a private or internal address`);
  return url;
}

export async function publicFetch(raw: string, init: RequestInit = {}, fetchImpl: typeof fetch = fetch) {
  const url = await assertPublicUrl(raw);
  const res = await fetchImpl(url, { ...init, redirect: "manual", signal: init.signal ?? AbortSignal.timeout(20_000) });
  if (res.status >= 300 && res.status < 400) throw new Error(`${url.host} answered with a redirect; give the final address`);
  return res;
}
