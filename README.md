# HELIOS

**A unified security operations platform** — one Next.js application
consolidating four previously separate tools into a single product:

| Feature area | Ported from | What it does |
|---|---|---|
| Agent Governance | `aegis` | Zero-trust identity, trust scoring, DLP, and breach investigation for autonomous AI agents |
| Investigations | `asip` | Multi-agent (LangGraph) root-cause analysis over forensic telemetry |
| Email & File Forensics | `desas` | Header/body/attachment analysis and sandbox URL detonation for phishing triage |
| Cases & Alerts | `signal-fusion` | SIEM-style detection engine and alert correlation across MITRE ATT&CK |

Every module writes into one shared data model — a single `Case` /
`Detection` / `TimelineEntry` stream, one MITRE ATT&CK reference set, one
threat-intel cache, one hash-chained audit log — instead of four apps with
four separate schemas glued together behind one UI. See `legacy/components/`
for the original standalone sources each module is ported from, and
`docs/` (coming as modules land) for design notes.

## Stack

- **Framework**: Next.js 16 (App Router), React 19, TypeScript
- **UI**: Tailwind CSS 4, shadcn/ui primitives (set up manually under
  `src/components/ui` — the shadcn CLI's registry isn't reachable from this
  environment's network), Motion, ECharts, TanStack Table
- **Data**: TanStack Query (client), Prisma + PostgreSQL (server), Zustand
  (local UI state only)
- **Auth**: Auth.js (credentials provider + Prisma adapter)

## Getting started

### 1. Start Postgres (and Redis, for later background-job use)

```bash
docker compose up -d
```

(If Docker isn't available, any local Postgres 16 instance works — just
point `DATABASE_URL` at it.)

### 2. Configure environment

```bash
cp .env.example .env
# then fill in DATABASE_URL / AUTH_SECRET / provider keys as needed
```

Generate a real `AUTH_SECRET` with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

### 3. Install dependencies and set up the database

```bash
npm install
npm run db:migrate   # applies prisma/migrations
npm run db:seed      # creates an initial admin user (admin@helios.local)
```

### 4. Run the app

```bash
npm run dev
```

Visit `http://localhost:3000` and sign in with the seeded admin account
(override via `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` before seeding).

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Start the dev server |
| `npm run build` | Production build |
| `npm run lint` | ESLint |
| `npm run db:migrate` | Run Prisma migrations |
| `npm run db:studio` | Open Prisma Studio |
| `npm run db:seed` | Seed the initial admin user |
| `npm run test` | Run the test suite (Vitest) |

## Testing

`src/lib/**/*.test.ts` covers the ported business logic directly — all 11
Cases & Alerts detectors, the forensics engine's pure signal functions
(entropy, obfuscation, polyglot/OLE/XLM/PDF detection), the governance
pipeline (constitution, reasoning, DLP, policy, and the sidecar that chains
them), the investigations entity-graph builder, the playbook trigger
matcher, and the threat-intel mock-fallback paths. Most of these are pure
unit tests with no dependencies; `src/lib/audit.test.ts` is a real
integration test against Postgres (Prisma-backed code isn't meaningfully
testable with a mocked database) — it needs `DATABASE_URL` pointed at a
running instance, same as the app itself.

## Project structure

```
src/
  app/
    (app)/            # authenticated app shell — one route per feature area
    api/auth/          # Auth.js route handler
    login/
  components/
    ui/                # shadcn/ui primitives
    shell/              # sidebar, topbar, nav
    governance/          # Agent Governance feature components
    dashboard/            # Overview KPI tiles / charts
    providers/             # TanStack Query + session providers
  lib/
    governance/          # ported aegis engines (identity, trust, policy, DLP, reasoning, sidecar, scenarios)
    db.ts                 # Prisma client singleton
    auth.ts                # Auth.js config
    audit.ts                # shared hash-chained audit log
    nav.ts                   # feature-area nav config
    severity.ts               # shared severity → color/label mapping
prisma/
  schema.prisma           # the unified data model
legacy/
  components/                # original aegis / asip / desas / signal-fusion sources (reference only)
```

## Status

All 9 feature areas are ported and verified end-to-end against a live
Postgres instance (build, lint, and real data flowing through each
module — see individual commits for the specific verification each one
ran):

- **Overview** — cross-source KPI dashboard
- **Agent Governance** (from aegis) — identity, trust, policy, DLP,
  reasoning-drift detection, all 5 attack scenarios
- **Threat Intelligence** (from asip/desas/signal-fusion) — shared
  VirusTotal/AbuseIPDB lookup + cache, used by every other module
- **Cases & Alerts** (from signal-fusion) — all 11 detectors across 12
  MITRE tactics, ingestion pipeline, attack simulation
- **Investigations** (from asip) — the Triage → RCA → adversarial QA →
  Report swarm (a plain state machine, not LangGraph — see
  `src/lib/investigations/orchestrator.ts` for why) and the entity/
  process-graph builder rendered via Cytoscape.js
- **Email & File Forensics** (from desas) — full JS port: header/SPF/
  DKIM/DMARC analysis, body/URL scoring, attachment forensics (entropy,
  obfuscation, OLE streams, polyglots, XLM macros, PDF signals), and
  real Playwright-driven sandbox URL detonation
- **Response Playbooks** (from signal-fusion) — trigger matching,
  auto-execute and approval-gated execution, wired into the detection
  engine
- **MITRE ATT&CK Coverage** — aggregated across all four detection
  sources
- **Audit Log** — one hash-chained trail for every write action
  app-wide, with a one-click integrity check

Known gaps, disclosed rather than silently dropped (see the relevant
commit for each): DESAS's modern OOXML macro extraction (`.xlsm`/
`.docm` VBA source is compressed inside `vbaProject.bin` in MS-OVBA
format — legacy binary `.doc`/`.xls` OLE macros are unaffected),
signal-fusion's full 48-scenario simulation library (condensed to 16
curated ones covering the same 12 tactics), and desas's deeper 3-pillar
JS-behavioral exfiltration model in the sandbox (replaced with a
simpler password-field/redirect-chain/POST-request heuristic).
