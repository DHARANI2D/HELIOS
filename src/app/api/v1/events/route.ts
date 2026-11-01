import { ApiError, authenticate, handle, json } from "@/lib/api/http";
import { QueryError } from "@/lib/explore/query";
import { searchEvents } from "@/lib/explore/search";
import { cursorOf, exploreParams, parseCursor, searchInputFor } from "@/lib/explore/request";

// GET /api/v1/events?q=<Explore search>&range=24h|from=…&to=…[&tenant=<id>|all][&limit=100][&cursor=…][&facets=1]
// The Explore search over the API: a client's token searches that client's
// logs only. Newest first; pass `next` back as cursor for the next page.
export const GET = handle(async (request: Request) => {
  const p = await authenticate(request, { permissions: ["events.search"] });
  const sp = new URL(request.url).searchParams;
  try {
    const params = exploreParams(sp, p, null);
    const cursor = parseCursor(sp.get("cursor"));
    const limit = Math.min(Math.max(Number(sp.get("limit") ?? 100) || 100, 1), 500);
    const r = await searchEvents(searchInputFor(params, p, { cursor, limit, facets: sp.get("facets") === "1" }));
    return json({ total: cursor ? null : r.total, from: r.from, to: r.to, events: r.rows, next: r.more ? cursorOf(r.rows[r.rows.length - 1]) : null, histogram: cursor ? undefined : r.histogram, facets: r.facets.length ? r.facets : undefined, ms: r.ms });
  } catch (err) {
    if (err instanceof QueryError) throw new ApiError(400, err.message);
    throw err;
  }
});
