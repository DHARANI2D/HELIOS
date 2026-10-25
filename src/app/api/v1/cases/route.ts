import { authenticate, handle, json } from "@/lib/api/http";
import { listCases } from "@/lib/api/v1";

// GET /api/v1/cases?status=open|closed|all|<STATUS>&severity=&source=&tenantId=&since=&limit=&cursor=
export const GET = handle(async (request: Request) => {
  const p = await authenticate(request, { permissions: ["cases.view"] });
  return json(await listCases(p, new URL(request.url).searchParams));
});
