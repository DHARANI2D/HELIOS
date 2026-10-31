// The background worker as its own process: `npm run worker`, or the
// worker container (dist/worker.mjs, built by scripts/build-worker.mjs).
// By default it runs the log-collection jobs (ingest queue, pull
// collectors, source health, retention); HELIOS_JOBS=core,ingest makes it
// run every timed job, so the web servers can run none (HELIOS_JOBS=none).
// Any number of workers can run: batches are claimed with SKIP LOCKED and
// every job is safe to run on several instances.
import { initKeyManagement } from "@/lib/keys";
import { jobGroups, startJobs } from "@/lib/jobs/scheduler";

void (async () => {
  await initKeyManagement();
  const groups = jobGroups(["ingest"]);
  startJobs(groups);
  console.log(`HELIOS worker started: ${groups.length ? groups.join(", ") : "no"} jobs`);
})().catch((err) => {
  console.error("HELIOS worker couldn't start", err);
  process.exit(1);
});

// A job that starts work without waiting for it (an AI first response, an
// enrichment) must not take every other job down with it: log and go on.
process.on("unhandledRejection", (err) => console.error("A background task failed", err));

const stop = () => process.exit(0);
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
// The jobs' timers are unref'd; keep the process alive.
setInterval(() => undefined, 60_000);
