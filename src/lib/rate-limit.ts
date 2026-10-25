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

// The visitor's address as the reverse proxy in front of the app reports it.
export async function clientAddress(): Promise<string> {
  const h = await headers();
  return h.get("x-forwarded-for")?.split(",")[0]?.trim() || h.get("x-real-ip")?.trim() || "unknown";
}
