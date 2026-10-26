// The ingest worker as its own process: `npm run worker`. Runs the
// log-collection jobs (ingest queue, pull collectors, source health); set
// HELIOS_INGEST_WORKER=external on the web servers so they leave them to
// it. Any number of workers can run: batches are claimed with SKIP LOCKED.
import { initKeyManagement } from "@/lib/keys";
import { startJobs } from "@/lib/jobs/scheduler";

void (async () => {
  await initKeyManagement();
  startJobs(["ingest"]);
  console.log("HELIOS ingest worker started");
})().catch((err) => {
  console.error("HELIOS ingest worker couldn't start", err);
  process.exit(1);
});

const stop = () => process.exit(0);
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
// The jobs' timers are unref'd; keep the process alive.
setInterval(() => undefined, 60_000);
