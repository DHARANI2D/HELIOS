// Background work that runs on a timer inside the server process: approval
// escalation along client approver chains, connector verification, time
// boxes, and the autonomy-ladder review.
// Started once from src/instrumentation.ts; off with HELIOS_BACKGROUND_JOBS=off.
// Each job is safe to repeat and to run on several instances.

interface Job {
  name: string;
  everyMs: number;
  run: () => Promise<unknown>;
}

const JOBS: Job[] = [
  { name: "approval escalation", everyMs: 60_000, run: async () => (await import("@/lib/rulebook/escalation")).escalatePendingApprovals() },
  // Follows connector requests until the vendor confirms them.
  { name: "connector verification", everyMs: 30_000, run: async () => (await import("@/lib/connectors/safety")).verifyInProgress() },
  // Rolls back time-boxed actions whose time is up.
  { name: "time boxes", everyMs: 60_000, run: async () => (await import("@/lib/connectors/safety")).rollBackExpired() },
  // Connector credentials about to expire.
  { name: "credential reminders", everyMs: 6 * 3_600_000, run: async () => (await import("@/lib/connectors/safety")).credentialReminders() },
  // Demotes on a bad week, proposes promotions; idempotent, so hourly is fine.
  { name: "autonomy ladder review", everyMs: 3_600_000, run: async () => (await import("@/lib/shadow/service")).reviewLadders() },
];

const STARTED = Symbol.for("helios.jobs.started");

export function startJobs() {
  const g = globalThis as typeof globalThis & { [STARTED]?: boolean };
  if (g[STARTED] || process.env.HELIOS_BACKGROUND_JOBS === "off") return;
  g[STARTED] = true;
  for (const job of JOBS) {
    let running = false;
    const tick = async () => {
      if (running) return;
      running = true;
      try {
        await job.run();
      } catch (err) {
        console.error(`Background job "${job.name}" failed`, err);
      } finally {
        running = false;
      }
    };
    setInterval(tick, job.everyMs).unref();
  }
}
