import type { SessionUser } from "@/lib/session";
import { RANGES, QueryError, type RangeKey } from "@/lib/explore/query";
import type { SearchInput } from "@/lib/explore/search";

// A search as the page, the CSV export and the REST API receive it:
// q, range (15m … 90d) or from/to, tenant (staff: a client id or "all"),
// cursor. A client user always searches their own client's logs.

export interface ExploreParams {
  q: string;
  range: RangeKey | "custom";
  from: Date;
  to: Date;
  tenant: string | null;
}

type Params = URLSearchParams | Record<string, string | string[] | undefined>;
const get = (p: Params, k: string): string | undefined => {
  const v = p instanceof URLSearchParams ? p.get(k) : p[k];
  return (Array.isArray(v) ? v[0] : v) ?? undefined;
};

export function exploreParams(p: Params, user: Pick<SessionUser, "isClient" | "tenantId">, selectedTenant: string | null, now = new Date()): ExploreParams {
  const q = (get(p, "q") ?? "").slice(0, 2000);
  const fromRaw = get(p, "from");
  const toRaw = get(p, "to");
  let range: ExploreParams["range"] = (get(p, "range") as RangeKey) in RANGES ? (get(p, "range") as RangeKey) : "24h";
  let from: Date;
  let to: Date;
  if (fromRaw) {
    from = new Date(fromRaw);
    to = toRaw ? new Date(toRaw) : now;
    if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) throw new QueryError("from and to must be dates (ISO 8601)");
    range = "custom";
  } else {
    to = now;
    from = new Date(now.getTime() - RANGES[range as RangeKey].ms);
  }
  const asked = get(p, "tenant");
  const tenant = user.isClient ? (user.tenantId ?? "__none__") : asked === "all" ? null : asked || selectedTenant;
  return { q, range, from, to, tenant };
}

export function searchInputFor(params: ExploreParams, user: Pick<SessionUser, "isClient" | "tenantId">, extra: Partial<SearchInput> = {}): SearchInput {
  return {
    q: params.q,
    from: params.from,
    to: params.to,
    tenantId: params.tenant,
    rlsTenant: user.isClient ? (user.tenantId ?? "__none__") : null,
    ...extra,
  };
}

export function parseCursor(raw: string | null | undefined): { t: string; id: string } | null {
  if (!raw) return null;
  const [t, id] = raw.split("|");
  if (!t || !id || Number.isNaN(new Date(t).getTime()) || !/^[\w-]{1,64}$/.test(id)) throw new QueryError("Invalid cursor");
  return { t: new Date(t).toISOString(), id };
}

export const cursorOf = (row: { timestamp: Date; id: string }) => `${row.timestamp.toISOString()}|${row.id}`;
