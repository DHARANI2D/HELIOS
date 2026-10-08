import { NextResponse } from "next/server";

import { handleIngest, type IngestPayload } from "@/lib/integrations/service";
import type { EventSource } from "@prisma/client";

const VALID_SOURCES: EventSource[] = ["AUTH", "ENDPOINT", "NETWORK", "CLOUD"];

// The one generic connector in the integration framework: any external
// tool that can send a webhook POSTs here with its own secret. No
// request is trusted without that secret matching the Integration row
// looked up by [id] — see src/lib/integrations/service.ts's handleIngest.
export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  const authHeader = request.headers.get("authorization");
  const secret = authHeader?.startsWith("Bearer ") ? authHeader.slice("Bearer ".length) : null;
  if (!secret) {
    return NextResponse.json({ error: "Missing Authorization: Bearer <secret>" }, { status: 401 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const payload = body as Partial<IngestPayload>;
  if (!payload.source || !VALID_SOURCES.includes(payload.source) || !Array.isArray(payload.events)) {
    return NextResponse.json(
      { error: `Body must be { source: ${VALID_SOURCES.join("|")}, events: object[] }` },
      { status: 400 },
    );
  }

  const result = await handleIngest(id, secret, { source: payload.source, events: payload.events });
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json(result, { status: result.status });
}
