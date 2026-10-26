// Field access for source mappers: vendor JSON is loosely typed, so every
// read goes through these.

export type Raw = Record<string, unknown>;

export function get(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const key of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Raw)[key];
  }
  return cur;
}

export function str(...values: unknown[]): string | undefined {
  for (const v of values) {
    if (typeof v === "string" && v.trim() && v.trim() !== "-") return v.trim();
    if (typeof v === "number" && Number.isFinite(v)) return String(v);
  }
  return undefined;
}

export function num(...values: unknown[]): number | undefined {
  for (const v of values) {
    const n = typeof v === "number" ? v : typeof v === "string" && v.trim() ? Number(v) : NaN;
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

// A timestamp from ISO text, epoch seconds or milliseconds; null when none parses.
export function dateOf(...values: unknown[]): Date | null {
  for (const v of values) {
    if (typeof v === "string" || typeof v === "number") {
      const d = new Date(typeof v === "number" && v < 1e12 ? v * 1000 : v);
      if (!Number.isNaN(d.getTime())) return d;
    }
  }
  return null;
}

export const asArray = (v: unknown): Raw[] => (Array.isArray(v) ? v.filter((x): x is Raw => !!x && typeof x === "object") : []);

export const isRaw = (v: unknown): v is Raw => !!v && typeof v === "object" && !Array.isArray(v);

// Raised by a mapper for a record it recognises but can't read; the record
// goes to the dead-letter queue with this reason.
export class MappingError extends Error {}
