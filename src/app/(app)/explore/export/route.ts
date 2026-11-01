import { currentUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { selectedTenantId } from "@/lib/access";
import { logAction } from "@/lib/audit";
import { QueryError } from "@/lib/explore/query";
import { exportEvents } from "@/lib/explore/search";
import { exploreParams, searchInputFor } from "@/lib/explore/request";
import { toCsv } from "@/lib/explore/csv";

const CAP = 10_000;

// The events matching an Explore search as CSV (newest first, up to 10,000).
export async function GET(request: Request) {
  const user = await currentUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (!can(user, "events.search")) return new Response("Forbidden", { status: 403 });
  try {
    const p = exploreParams(new URL(request.url).searchParams, user, user.isClient ? null : await selectedTenantId(user));
    const rows = await exportEvents(searchInputFor(p, user), CAP);
    await logAction({ actorId: user.id, action: "explore.export", detail: { q: p.q, from: p.from.toISOString(), to: p.to.toISOString(), tenant: p.tenant, rows: rows.length } });
    const header = ["timestamp", "eventType", "source", "platform", "hostName", "userName", "processName", "parentProcessName", "commandLine", "sourceIp", "destIp", "destPort", "filePath", "fileHash", "severityHint", "geo", "classUid", "tenantId", "caseId", "integrationId", "id"] as const;
    const body = toCsv([...header], rows.map((r) => header.map((h) => r[h])));
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
    return new Response(body, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="helios-events-${stamp}.csv"`, "cache-control": "private, no-store" } });
  } catch (err) {
    if (err instanceof QueryError) return new Response(err.message, { status: 400 });
    throw err;
  }
}
