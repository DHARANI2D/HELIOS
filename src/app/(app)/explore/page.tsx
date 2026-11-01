import { pageGuard } from "@/lib/session";
import { selectedTenantId } from "@/lib/access";
import { QueryError } from "@/lib/explore/query";
import { searchEvents, type SearchResult } from "@/lib/explore/search";
import { cursorOf, exploreParams, searchInputFor } from "@/lib/explore/request";
import { savedSearchesFor, tenantsForExplore } from "@/lib/explore/saved";
import { resolveAgent } from "@/lib/ai/resolve";
import { ExploreView } from "@/components/explore/explore-view";

// Explore: one search over every log HELIOS holds for a client, from all
// of that client's tools, the way analysts search Splunk, Chronicle, QRadar
// or Wazuh. The search assistant turns a question into a search on the
// client's chosen model. Client users search their own logs only.
export default async function ExplorePage({ searchParams }: PageProps<"/explore">) {
  const user = await pageGuard("events.search");
  const sp = await searchParams;
  const now = new Date();
  const selected = user.isClient ? null : await selectedTenantId(user);
  let error: string | null = null;
  let result: SearchResult | null = null;
  const params = (() => {
    try {
      return exploreParams(sp, user, selected, now);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      return exploreParams({}, user, selected, now);
    }
  })();

  if (!error) {
    try {
      result = await searchEvents(searchInputFor(params, user));
    } catch (err) {
      if (!(err instanceof QueryError)) throw err;
      error = err.message;
    }
  }

  const [saved, tenants, assistant] = await Promise.all([
    savedSearchesFor(user),
    user.isClient ? Promise.resolve([]) : tenantsForExplore(),
    resolveAgent("search", { tenantId: params.tenant ?? (user.isClient ? user.tenantId : null), userId: user.id }).then((r) => (r.provider ? `${r.provider.name} (${r.provider.model})` : null)),
  ]);

  return (
    <ExploreView
      params={{ q: params.q, range: params.range, from: params.from.toISOString(), to: params.to.toISOString(), tenant: params.tenant ?? "all" }}
      isClient={user.isClient}
      error={error}
      result={
        result && {
          ...result,
          rows: result.rows.map((r) => ({ ...r, timestamp: r.timestamp.toISOString() })),
          next: result.more ? cursorOf(result.rows[result.rows.length - 1]) : null,
        }
      }
      tenants={tenants.map((t) => ({ id: t.id, name: t.name, isTest: t.isTest }))}
      saved={saved.map((s) => ({ id: s.id, name: s.name, query: s.query, range: s.range, tenant: s.tenantId, tenantName: s.tenant?.name ?? null, shared: s.shared, mine: s.ownerId === user.id, owner: s.owner.name ?? s.owner.email }))}
      assistant={assistant}
    />
  );
}
