// Liveness: the server process is up and answering. It doesn't touch the
// database, so an orchestrator restarts a stuck process but not every
// process when the database is briefly unreachable; /api/health (which
// checks the database) is the readiness probe.
export function GET() {
  return Response.json({ status: "ok" }, { headers: { "Cache-Control": "no-store" } });
}
