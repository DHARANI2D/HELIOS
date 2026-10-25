// Runs once when a server instance starts: background jobs (Node.js only).
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { startJobs } = await import("@/lib/jobs/scheduler");
    startJobs();
  }
}
