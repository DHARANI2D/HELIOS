import type { NextRequest } from "next/server";

import { logAction } from "@/lib/audit";
import { safeEqual } from "@/lib/secrets";
import { ingestForIntegration, integrationForToken } from "@/lib/integrations/service";
import { parseBody } from "@/lib/integrations/mappers";

// Push endpoint for onboarded tools:
//   POST /api/ingest/<integrationId>
//   Authorization: Bearer <ingest token shown at onboarding>
// Body: the tool's native alert/event JSON (array, {events|data|value|...},
// single object, or JSON Lines), or {"inventory": [...]} for endpoints.

const MAX_BYTES = 10 * 1024 * 1024;
const RATE_LIMIT_PER_MINUTE = 120;
const hits = new Map<string, { windowStart: number; count: number }>();

function rateLimited(id: string) {
  const now = Date.now();
  const entry = hits.get(id);
  if (!entry || now - entry.windowStart > 60_000) {
    hits.set(id, { windowStart: now, count: 1 });
    return false;
  }
  entry.count++;
  return entry.count > RATE_LIMIT_PER_MINUTE;
}

function json(body: unknown, status = 200) {
  return Response.json(body, { status });
}

export async function POST(request: NextRequest, ctx: RouteContext<"/api/ingest/[integrationId]">) {
  const { integrationId } = await ctx.params;
  const integration = await integrationForToken(request.headers.get("authorization"));
  // The token must belong to the integration in the URL.
  if (!integration || !safeEqual(integration.id, integrationId)) return json({ error: "Invalid or revoked ingest token" }, 401);
  if (rateLimited(integration.id)) return json({ error: `Rate limit: ${RATE_LIMIT_PER_MINUTE} requests per minute` }, 429);

  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > MAX_BYTES) return json({ error: "Payload larger than 10 MB" }, 413);
  const text = await request.text();
  if (text.length > MAX_BYTES) return json({ error: "Payload larger than 10 MB" }, 413);

  let body: unknown;
  try {
    body = parseBody(text);
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : "Malformed body" }, 400);
  }

  try {
    const result = await ingestForIntegration(integration, body);
    await logAction({ action: "integration.ingest", detail: { integrationId: integration.id, ...result } });
    return json({ ok: true, ...result });
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : "Ingest failed" }, 422);
  }
}
