"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { dbFor } from "@/lib/tenant-db";
import { requirePermission } from "@/lib/session";
import { selectedTenantId } from "@/lib/access";
import { logAction } from "@/lib/audit";
import { action } from "@/lib/action";
import { RANGES, parseQuery, type RangeKey } from "@/lib/explore/query";
import { searchEvents } from "@/lib/explore/search";
import { cursorOf, exploreParams, parseCursor, searchInputFor } from "@/lib/explore/request";
import { suggestSearch } from "@/lib/explore/assistant";

// Explore: the next page of results, one event in full, the search
// assistant, and saved searches. Every call re-checks the permission and
// the client scope; a client user only ever reaches their own logs.

export const moreEventsAction = action(async function moreEventsAction(params: Record<string, string>, cursor: string) {
  const user = await requirePermission("events.search");
  const p = exploreParams(params, user, await selectedTenantId(user));
  const r = await searchEvents(searchInputFor(p, user, { cursor: parseCursor(cursor), facets: false }));
  return { rows: r.rows.map((e) => ({ ...e, timestamp: e.timestamp.toISOString() })), next: r.more ? cursorOf(r.rows[r.rows.length - 1]) : null };
});

export const eventDetailAction = action(async function eventDetailAction(id: string, timestamp: string) {
  const user = await requirePermission("events.search");
  const at = new Date(timestamp);
  if (Number.isNaN(at.getTime())) throw new Error("Not found");
  const scope = user.isClient ? { tenantId: user.tenantId ?? "__none__" } : {};
  const e = await dbFor(user).securityEvent.findFirst({ where: { id: z.string().max(64).parse(id), timestamp: at, ...scope } });
  if (!e) throw new Error("Not found");
  const integration = e.integrationId ? await dbFor(user).integration.findFirst({ where: { id: e.integrationId }, select: { name: true } }) : null;
  return { ...e, timestamp: e.timestamp.toISOString(), ingestedAt: e.ingestedAt.toISOString(), integrationName: integration?.name ?? null };
});

export const suggestSearchAction = action(async function suggestSearchAction(question: string, tenant: string | null) {
  const user = await requirePermission("events.search");
  const tenantId = user.isClient ? user.tenantId : tenant && tenant !== "all" ? tenant : null;
  const s = await suggestSearch(z.string().max(600).parse(question), { tenantId, userId: user.id });
  await logAction({ actorId: user.id, action: "explore.assistant", detail: { engine: s.engine, model: s.model, query: s.query } });
  return s;
});

const saveSchema = z.object({
  name: z.string().trim().min(1).max(120),
  query: z.string().max(2000),
  range: z.string().refine((r) => r in RANGES, "Pick a time range"),
  tenant: z.string().max(64).nullable(),
  shared: z.boolean(),
});

export const saveSearchAction = action(async function saveSearchAction(input: z.input<typeof saveSchema>) {
  const user = await requirePermission("events.search");
  const s = saveSchema.parse(input);
  parseQuery(s.query);
  const tenantId = user.isClient ? user.tenantId : s.tenant && s.tenant !== "all" ? s.tenant : null;
  if (user.isClient && !tenantId) throw new Error("Not found");
  const saved = await dbFor(user).savedSearch.create({ data: { name: s.name, query: s.query, range: s.range as RangeKey, tenantId, ownerId: user.id, shared: s.shared } });
  revalidatePath("/explore");
  return { id: saved.id };
});

export const deleteSearchAction = action(async function deleteSearchAction(id: string) {
  const user = await requirePermission("events.search");
  const res = await dbFor(user).savedSearch.deleteMany({ where: { id, ownerId: user.id } });
  if (!res.count) throw new Error("Only the person who saved a search can delete it");
  revalidatePath("/explore");
});
