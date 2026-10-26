import { gunzipSync } from "node:zlib";
import type { NextRequest } from "next/server";

import { safeEqual } from "@/lib/secrets";
import { integrationForToken } from "@/lib/integrations/service";
import { parseBody, recordsFrom } from "@/lib/integrations/mappers";
import { QuotaError, enqueueBatch } from "@/lib/ingest/queue";
import { noteForwarderConfig } from "@/lib/forwarder/service";

// The ingest edge for onboarded tools and the HELIOS forwarder:
//   POST /api/ingest/<integrationId>
//   Authorization: Bearer <ingest token shown at onboarding>
//   Content-Encoding: gzip (optional)
// Body: the tool's native alert/event JSON (array, {events|data|value|...},
// single object, or JSON Lines), or {"inventory": [...]} for endpoints.
// It authenticates, checks the body parses, and queues it: 202 Accepted with
// the batch id. Mapping, detection and cases happen in the ingest workers.

const MAX_BYTES = 10 * 1024 * 1024;
const MAX_DECOMPRESSED = 50 * 1024 * 1024;
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

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return Response.json(body, { status, headers });
}

export async function POST(request: NextRequest, ctx: RouteContext<"/api/ingest/[integrationId]">) {
  const { integrationId } = await ctx.params;
  const integration = await integrationForToken(request.headers.get("authorization"));
  // The token must belong to the integration in the URL.
  if (!integration || !safeEqual(integration.id, integrationId)) return json({ error: "Invalid or revoked ingest token" }, 401);
  if (rateLimited(integration.id)) return json({ error: `Rate limit: ${RATE_LIMIT_PER_MINUTE} requests per minute` }, 429, { "retry-after": "60" });

  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > MAX_BYTES) return json({ error: "Payload larger than 10 MB" }, 413);
  const raw = Buffer.from(await request.arrayBuffer());
  if (raw.length > MAX_BYTES) return json({ error: "Payload larger than 10 MB" }, 413);

  let text: string;
  const encoding = (request.headers.get("content-encoding") ?? "").toLowerCase();
  if (encoding === "gzip") {
    try {
      text = gunzipSync(raw, { maxOutputLength: MAX_DECOMPRESSED }).toString("utf8");
    } catch (err) {
      const tooBig = err instanceof RangeError || (err as { code?: string }).code === "ERR_BUFFER_TOO_LARGE";
      return json({ error: tooBig ? "Payload larger than 50 MB uncompressed" : "Body isn't valid gzip" }, tooBig ? 413 : 400);
    }
  } else if (!encoding || encoding === "identity") {
    text = raw.toString("utf8");
  } else {
    return json({ error: `Unsupported Content-Encoding ${encoding}; send gzip or none` }, 415);
  }

  let records: number;
  try {
    records = recordsFrom(parseBody(text)).length;
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : "Malformed body" }, 400);
  }

  // The HELIOS forwarder says which signed configuration it runs.
  const configHash = request.headers.get("x-helios-config");
  const channel = configHash ? "forwarder" : "push";
  if (configHash) await noteForwarderConfig(integration, configHash);

  try {
    const batch = await enqueueBatch(integration, text, { channel });
    return json({ accepted: true, batchId: batch.id, records }, 202);
  } catch (err) {
    if (err instanceof QuotaError) return json({ error: err.message }, 429, { "retry-after": String(err.retryAfterSeconds) });
    throw err;
  }
}
