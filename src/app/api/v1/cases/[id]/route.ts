import { authenticate, handle, json } from "@/lib/api/http";
import { getCase, updateCase } from "@/lib/api/v1";

// GET /api/v1/cases/:id — the case with detections, indicators, ATT&CK,
// timeline, response actions and comments (clients see no internal notes).
export const GET = handle(async (request: Request, ctx: RouteContext<"/api/v1/cases/[id]">) => {
  const p = await authenticate(request, { permissions: ["cases.view"] });
  return json(await getCase(p, (await ctx.params).id));
});

// PATCH /api/v1/cases/:id { status?, severity?, assignee?: email | null, note? }
export const PATCH = handle(async (request: Request, ctx: RouteContext<"/api/v1/cases/[id]">) => {
  const p = await authenticate(request, { write: true, permissions: ["cases.view"] });
  return json(await updateCase(p, (await ctx.params).id, await request.json().catch(() => null)));
});
