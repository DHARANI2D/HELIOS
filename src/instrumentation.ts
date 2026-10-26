// Runs once when a server instance starts (Node.js only): the KMS-protected
// master key is decrypted before any request, then background jobs start.
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { initKeyManagement } = await import("@/lib/keys");
    await initKeyManagement();
    const { startJobs } = await import("@/lib/jobs/scheduler");
    startJobs();
  }
}
