import { canonicalJson, type Rulebook } from "@/lib/rulebook/schema";

// What changed between two rulebook versions, as readable lines:
// "actions.ISOLATE_HOST.mode: approve → auto", "+ assets.neverIsolate: …".
// Lists compare by item, so reordering isn't a change. Pure.

export interface DiffLine {
  path: string;
  kind: "changed" | "added" | "removed";
  before?: string;
  after?: string;
}

function show(value: unknown): string {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const o = value as Record<string, unknown>;
    if ("kind" in o && "value" in o) return `${o.kind} ${o.value}${o.note ? ` (${o.note})` : ""}`;
    if ("label" in o && "start" in o) return `${o.label} ${String(o.start).slice(0, 16)} → ${String(o.end).slice(0, 16)}`;
    if ("name" in o && "channel" in o) return `${o.name} via ${o.channel} (${o.contact}), ${o.timeoutMinutes} min`;
  }
  return typeof value === "string" ? value : canonicalJson(value);
}

function walk(path: string, a: unknown, b: unknown, out: DiffLine[]) {
  if (Array.isArray(a) || Array.isArray(b)) {
    const before = (Array.isArray(a) ? a : []).map((x) => [canonicalJson(x), x] as const);
    const after = (Array.isArray(b) ? b : []).map((x) => [canonicalJson(x), x] as const);
    const had = new Set(before.map(([k]) => k));
    const has = new Set(after.map(([k]) => k));
    for (const [k, x] of before) if (!has.has(k)) out.push({ path, kind: "removed", before: show(x) });
    for (const [k, x] of after) if (!had.has(k)) out.push({ path, kind: "added", after: show(x) });
    return;
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const keys = [...new Set([...Object.keys(a as object), ...Object.keys(b as object)])].sort();
    for (const k of keys) walk(path ? `${path}.${k}` : k, (a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], out);
    return;
  }
  if (canonicalJson(a) !== canonicalJson(b)) out.push({ path, kind: "changed", before: a === undefined ? "—" : show(a), after: b === undefined ? "—" : show(b) });
}

export function diffRulebooks(before: Rulebook | null, after: Rulebook): DiffLine[] {
  const out: DiffLine[] = [];
  walk("", before ?? {}, after, out);
  return out;
}
