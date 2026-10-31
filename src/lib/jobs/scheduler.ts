// Background work that runs on a timer: approval escalation along client
// approver chains, connector verification, time boxes, regulatory clocks,
// the autonomy-ladder review, on-call paging, QA sampling, the daily
// digest, and log collection (the ingest queue, pull
// collectors, source health). Started once from src/instrumentation.ts in
// the web process; with HELIOS_INGEST_WORKER=external the log-collection
// jobs run in `npm run worker` (src/worker.ts) instead. Off with
// HELIOS_BACKGROUND_JOBS=off.
// Each job is safe to repeat and to run on several instances.

interface Job {
  name: string;
  everyMs: number;
  group: "core" | "ingest";
  run: () => Promise<unknown>;
}

const INGEST_JOBS: Job[] = [
  // Backstop for the kick after each enqueue, and for retries coming due.
  { name: "ingest queue", group: "ingest", everyMs: 2_000, run: async () => (await import("@/lib/ingest/queue")).drainQueue() },
  { name: "ingest cleanup", group: "ingest", everyMs: 3_600_000, run: async () => (await import("@/lib/ingest/queue")).pruneBatches() },
  { name: "log collectors", group: "ingest", everyMs: 30_000, run: async () => (await import("@/lib/collectors/run")).runDueCollectors() },
  { name: "source health", group: "ingest", everyMs: 5 * 60_000, run: async () => (await import("@/lib/ingest/health")).checkSourceHealth() },
  // Archives events past their hot period and deletes what's past retention.
  { name: "log retention", group: "ingest", everyMs: 3_600_000, run: async () => (await import("@/lib/retention/service")).runRetention() },
];

const JOBS: Job[] = [
  { name: "approval escalation", group: "core", everyMs: 60_000, run: async () => (await import("@/lib/rulebook/escalation")).escalatePendingApprovals() },
  // Follows connector requests until the vendor confirms them.
  { name: "connector verification", group: "core", everyMs: 30_000, run: async () => (await import("@/lib/connectors/safety")).verifyInProgress() },
  // Rolls back time-boxed actions whose time is up.
  { name: "time boxes", group: "core", everyMs: 60_000, run: async () => (await import("@/lib/connectors/safety")).rollBackExpired() },
  // Connector credentials about to expire.
  { name: "credential reminders", group: "core", everyMs: 6 * 3_600_000, run: async () => (await import("@/lib/connectors/safety")).credentialReminders() },
  // Sends queued email, SMS and WhatsApp alerts, with retries.
  { name: "alert deliveries", group: "core", everyMs: 10_000, run: async () => (await import("@/lib/alerts/outbox")).processDeliveries() },
  // Opens CERT-In reports for qualifying cases and chases regulatory deadlines.
  { name: "regulatory clocks", group: "core", everyMs: 60_000, run: async () => (await import("@/lib/compliance/service")).checkRegulatoryClocks() },
  // Demotes on a bad week, proposes promotions; idempotent, so hourly is fine.
  { name: "autonomy ladder review", group: "core", everyMs: 3_600_000, run: async () => (await import("@/lib/shadow/service")).reviewLadders() },
  // Pages the on-call analyst for severe cases, escalates unanswered pages, sends handoffs.
  { name: "on-call paging", group: "core", everyMs: 60_000, run: async () => (await import("@/lib/operations/paging")).runPaging() },
  // Draws last week's QA sample once the week is over.
  { name: "QA sampling", group: "core", everyMs: 3_600_000, run: async () => (await import("@/lib/operations/qa")).runQaSampling() },
  // The daily digest, once the set hour has passed.
  { name: "daily digest", group: "core", everyMs: 10 * 60_000, run: async () => (await import("@/lib/operations/digest")).sendDigests() },
  // Pulls rulebooks kept in Git into drafts when the file changes.
  { name: "rulebook git sync", group: "core", everyMs: 3_600_000, run: async () => (await import("@/lib/rulebook/git-sync")).syncAllRulebooks() },
  // Rulebook review dates and lapsing allowlist entries.
  { name: "rulebook reviews", group: "core", everyMs: 6 * 3_600_000, run: async () => (await import("@/lib/rulebook/reminders")).remindRulebookReviews() },
  // Drafts invoices for billing periods that started, chases overdue ones, renews or ends contracts.
  { name: "commercial clocks", group: "core", everyMs: 3_600_000, run: async () => (await import("@/lib/billing/service")).commercialClocks() },
];

const STARTED = Symbol.for("helios.jobs.started");

export function startJobs(groups: Array<Job["group"]> = process.env.HELIOS_INGEST_WORKER === "external" ? ["core"] : ["core", "ingest"]) {
  const g = globalThis as typeof globalThis & { [STARTED]?: boolean };
  if (g[STARTED] || process.env.HELIOS_BACKGROUND_JOBS === "off") return;
  g[STARTED] = true;
  for (const job of [...JOBS, ...INGEST_JOBS].filter((j) => groups.includes(j.group))) {
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
