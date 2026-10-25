import { authenticate, handle, json } from "@/lib/api/http";
import { metrics } from "@/lib/api/v1";

// GET /api/v1/metrics?range=7d|30d|90d|365d | month=YYYY-MM [&tenantId=]
export const GET = handle(async (request: Request) => {
  const p = await authenticate(request, { permissions: ["reports.view"] });
  return json(await metrics(p, new URL(request.url).searchParams));
});
