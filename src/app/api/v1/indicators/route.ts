import { authenticate, handle, json } from "@/lib/api/http";
import { logAction } from "@/lib/audit";
import { lookup } from "@/lib/api/v1";

// GET /api/v1/indicators?value=<ip|domain|url|hash|email>[&refresh=1]
export const GET = handle(async (request: Request) => {
  const p = await authenticate(request, { permissions: ["intel.view"] });
  const result = await lookup(p, new URL(request.url).searchParams);
  await logAction({ actorId: p.id, action: "intel.lookup", detail: { type: result.type, value: result.value, cached: result.cached, via: "api" } });
  return json(result);
});
