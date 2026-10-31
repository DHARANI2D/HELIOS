import { headers } from "next/headers";

// Fixed-window counters in this server's memory: enough to stop one visitor
// hammering a public form. Limits that must hold across server instances
// (the website's daily AI budget) are counted in the database instead.

const windows = new Map<string, { start: number; count: number }>();
const MAX_KEYS = 10_000;

export function rateLimit(key: string, limit: number, windowMs: number, now = Date.now()): { ok: boolean; retryAfterMs: number } {
  if (windows.size > MAX_KEYS) {
    for (const [k, w] of windows) if (now - w.start > windowMs) windows.delete(k);
  }
  const w = windows.get(key);
  if (!w || now - w.start > windowMs) {
    windows.set(key, { start: now, count: 1 });
    return { ok: true, retryAfterMs: 0 };
  }
  if (w.count >= limit) return { ok: false, retryAfterMs: windowMs - (now - w.start) };
  w.count++;
  return { ok: true, retryAfterMs: 0 };
}

// The visitor's address. Each proxy in front of the app (load balancer,
// ingress) appends the address it was reached from to X-Forwarded-For, so
// only the entries those proxies added can be believed: anything to their
// left is whatever the visitor chose to send. HELIOS_TRUSTED_PROXIES is how
// many proxies sit in front of the app (default 1); the visitor is that
// many entries from the right. With no proxy (0), the server records the
// connection's own address only when the request didn't bring the header,
// so the address can't be trusted and every visitor counts as one.
export function trustedProxies(env: Record<string, string | undefined> = process.env) {
  const n = Number(env.HELIOS_TRUSTED_PROXIES ?? 1);
  return Number.isInteger(n) && n >= 0 && n <= 10 ? n : 1;
}

export function addressFrom(forwardedFor: string | null, hops = trustedProxies()): string {
  if (hops === 0) return "unknown";
  const entries = (forwardedFor ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  return entries.length >= hops ? entries[entries.length - hops] : (entries[0] ?? "unknown");
}

export async function clientAddress(): Promise<string> {
  return addressFrom((await headers()).get("x-forwarded-for"));
}
