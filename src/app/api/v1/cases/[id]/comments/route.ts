import { authenticate, handle, json } from "@/lib/api/http";
import { commentOnCase } from "@/lib/api/v1";

// POST /api/v1/cases/:id/comments { body, clientVisible? } — internal unless
// clientVisible; client tokens always post visible replies.
export const POST = handle(async (request: Request, ctx: RouteContext<"/api/v1/cases/[id]/comments">) => {
  const p = await authenticate(request, { write: true, permissions: ["cases.comment"] });
  return json(await commentOnCase(p, (await ctx.params).id, await request.json().catch(() => null)), 201);
});
