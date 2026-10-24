import { db } from "@/lib/db";

// Liveness/readiness for load balancers and uptime monitors. Reports only
// coarse state — no data, no configuration details.
export async function GET() {
  const started = Date.now();
  try {
    await db.$queryRaw`SELECT 1`;
    return Response.json({ status: "ok", database: "ok", latencyMs: Date.now() - started, time: new Date().toISOString() });
  } catch {
    return Response.json({ status: "degraded", database: "unreachable", time: new Date().toISOString() }, { status: 503 });
  }
}
