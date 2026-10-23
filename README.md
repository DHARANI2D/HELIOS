# HELIOS

**A unified security operations platform**: one Next.js application consolidating four previously separate tools into a single product.

| Feature area | Ported from | What it does |
|---|---|---|
| Cases & Alerts | `signal-fusion` | Telemetry ingestion, 11 SIEM detectors, 48 replayable ATT&CK attack scenarios, and correlation of detections into cases |
| Investigations | `asip` | Log normalization (Sysmon, CrowdStrike, Wazuh, Google SecOps, Splunk CSV, JSON/JSONL, raw text), a process-lineage graph, and a triage → RCA ⇄ adversarial QA → report pipeline (Claude agent swarm or deterministic engine) |
| Email & File Forensics | `desas` | SPF/DKIM/DMARC and sender-identity checks, phishing content and link heuristics, attachment forensics, HTTP-level link detonation, and scored verdicts |
| Agent Governance | `aegis` | Zero-trust identity, trust scoring, DLP, and breach investigation for autonomous AI agents |
| Threat Intelligence | all four | One shared IOC store: built-in intel plus VirusTotal and AbuseIPDB, 24h cache, and a blocklist feed |
| Response Playbooks | `signal-fusion` | Trigger-matched containment workflows on *any* case source, with an admin approval gate |
| MITRE ATT&CK Coverage | all four | Matrix of the techniques HELIOS rules can detect vs. the techniques observed in cases |
| Audit Log | `aegis` | A hash-chained, tamper-evident record of every write action, with verification and export |

Every module writes through one case writer into one shared data model. That means:
- one `Case` / `Detection` / `TimelineEntry` stream;
- one `SecurityEvent` telemetry table;
- one MITRE ATT&CK reference set;
- one threat-indicator cache;
- one audit chain.

So a phishing verdict, a SIEM correlation, an investigation, and a rogue AI agent all show up in the same case list. They also share the coverage matrix and trigger the same playbooks.

See [`docs/architecture.md`](docs/architecture.md) for how the pieces fit together, and [`docs/porting-notes.md`](docs/porting-notes.md) for what changed relative to each legacy app (bugs fixed, behaviour intentionally not ported). The original sources live in `legacy/components/` for reference only.

## Stack

- **Framework**: Next.js 16 (App Router, Server Actions, `after()` for background work), React 19, TypeScript.
- **UI**: Tailwind CSS 4 and shadcn/ui primitives, set up manually under `src/components/ui` because the shadcn CLI registry isn't reachable from this environment's network. Also ECharts and Cytoscape (process graphs).
- **Data**: Prisma + PostgreSQL 16, TanStack Query on the client, Zustand for local UI state.
- **Auth**: Auth.js (credentials provider + Prisma adapter). Every Server Action re-checks the session, because the proxy redirect isn't a security boundary.
- **AI**: `@anthropic-ai/sdk` (Claude, structured outputs) for the Investigations agent swarm.
- **Tests**: Vitest, with unit tests plus a Postgres-backed integration suite.

## Getting started

### 1. Start Postgres

```bash
docker compose up -d
```

If Docker isn't available, any local Postgres 16 instance works; point `DATABASE_URL` at it.

### 2. Configure environment

```bash
cp .env.example .env
# set AUTH_SECRET; everything else is optional
```

`.env.example` documents every variable. None of the integrations is required:

| Variable | Without it |
|---|---|
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | Built-in intel only (known C2 / Tor ranges, suspicious TLDs, brand impersonation) |
| `ANTHROPIC_API_KEY` | Investigations use the deterministic forensic engine instead of the Claude agent swarm |
| `SLACK_WEBHOOK_URL` | `NOTIFY_SLACK` playbook actions are recorded as simulated |

### 3. Install dependencies and set up the database

```bash
npm install
npm run db:migrate   # applies prisma/migrations
npm run db:seed      # admin user, MITRE ATT&CK reference set, starter playbooks
```

### 4. Run the app

```bash
npm run dev
```

Visit `http://localhost:3000` and sign in with the seeded admin account, `admin@helios.local` / `helios-admin`. Override these with `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` before seeding.

### Try it

Each module has a built-in demo:

- **Cases & Alerts**: click **Run simulation** to replay signal-fusion's attack scenarios through the live ingestion and detection pipeline.
- **Investigations**: click **Load sample**, then **Start investigation**. The sample is a phishing macro → encoded PowerShell → C2 → persistence → LSASS dump → PsExec trace.
- **Email & File Forensics**: click **Analyze sample phishing email**. It carries failing SPF/DKIM/DMARC, a look-alike login link, and a macro-enabled `.docm`.
- **Agent Governance**: run any of the five scenarios.

Then look at the **Response Playbooks** approval queue, the **MITRE ATT&CK Coverage** matrix, and the **Audit Log**. Use **Verify chain integrity** on the Audit Log page to check the chain.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Start the dev server |
| `npm run build` | Production build |
| `npm run lint` | ESLint |
| `npm run typecheck` | Generate route types and run `tsc --noEmit` |
| `npm test` | Unit tests (Vitest) |
| `RUN_DB_TESTS=1 DATABASE_URL=…/helios_test npm test` | Also run the Postgres integration suite. It **truncates every table**, so it refuses to run unless the database name ends in `_test` |
| `npm run db:migrate` | Create / apply Prisma migrations (dev) |
| `npm run db:seed` | Seed admin user, ATT&CK reference set, starter playbooks (idempotent) |
| `npm run db:studio` | Open Prisma Studio |

CI (`.github/workflows/ci.yml`) runs lint, typecheck, unit tests, migrations plus the integration suite against a Postgres service, and a production build.

## Project structure

```
src/
  app/
    (app)/                 # authenticated shell — one route per feature area, each with its Server Actions
      cases/[id]/          # unified case view (shared by every source, plus a source-specific panel)
    api/                   # Auth.js, audit export, threat-intel blocklist feed
    login/
  components/
    ui/                    # shadcn/ui primitives
    shared/                # badges, pagination, JSON/Markdown views
    cases/ investigations/ forensics/ governance/ playbooks/ threat-intel/ audit/ dashboard/ shell/
  lib/
    cases/                 # the shared case writer + lifecycle helpers
    siem/                  # adapters, 11 detectors, risk engine, correlation, 48 attack scenarios
    investigations/        # normalizer, entity graph, forensic rules, Claude agents, pipeline
    forensics/             # headers, body, HTML intel, attachment forensics, sandbox, scoring
    governance/            # aegis engines (identity, trust, policy, DLP, reasoning, sidecar, scenarios)
    threat-intel/          # IOC extraction, built-in intel, providers, shared cache
    playbooks/             # trigger matching, execution engine, starter playbooks
    mitre/                 # ATT&CK catalog + detection-coverage registry
    audit.ts               # hash-chained audit log
    session.ts             # requireUser / requireAdmin for Server Actions
prisma/
  schema.prisma            # the unified data model
  migrations/
  seed.ts
docs/                      # architecture and porting notes
legacy/components/         # original aegis / asip / desas / signal-fusion sources (reference only)
```

## Security notes

- **Server Actions:** each one authenticates. Org-wide or destructive operations are admin-only: playbook authoring, approving containment, and global purge.
- **Audit log:** appends serialize on a Postgres advisory lock so concurrent writers can't fork the chain. Cases and users referenced by audit entries can't be deleted, because nulling those references would rewrite hashed rows.
- **URL detonation:** fetches attacker URLs from the server. Every connection's resolved address is checked against private, loopback and link-local ranges at connect time, which also blocks DNS rebinding. JavaScript is not executed. Detonation needs direct outbound HTTP(S); it does not go through an HTTP proxy.
- **Model output:** rendered as Markdown with raw HTML disabled.
