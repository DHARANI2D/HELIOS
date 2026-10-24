import { db } from "@/lib/db";
import { getCategory, toolFromRow, type CategoryKey, type ToolDefinition } from "@/lib/integrations/catalog";

// The tool catalog from the database. Ingest and dispatch read it on every
// request, so it is memoized briefly; catalog edits call invalidateCatalog().

const TTL_MS = 30_000;
let cached: { at: number; tools: ToolDefinition[] } | null = null;

export async function listCatalogTools(opts: { includeInactive?: boolean } = {}): Promise<ToolDefinition[]> {
  if (!cached || Date.now() - cached.at > TTL_MS) {
    const rows = await db.catalogTool.findMany({ orderBy: [{ category: "asc" }, { vendor: "asc" }, { name: "asc" }] });
    cached = { at: Date.now(), tools: rows.filter((r) => getCategory(r.category)).map(toolFromRow) };
  }
  return opts.includeInactive ? cached.tools : cached.tools.filter((t) => t.active);
}

// Inactive tools still resolve, so integrations onboarded before a tool was
// retired keep working.
export async function getCatalogTool(key: string): Promise<ToolDefinition | undefined> {
  return (await listCatalogTools({ includeInactive: true })).find((t) => t.key === key);
}

export async function catalogToolsIn(category: CategoryKey): Promise<ToolDefinition[]> {
  return (await listCatalogTools()).filter((t) => t.category === category);
}

export function invalidateCatalog() {
  cached = null;
}
