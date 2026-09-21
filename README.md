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

Foundation and the Agent Governance module are complete and verified
end-to-end (build, lint, and a live run of all 5 governance attack
scenarios against Postgres). Threat Intelligence, Cases & Alerts,
Investigations, Email & File Forensics, and Response Playbooks / MITRE
Coverage / Audit Log are in progress — their routes currently show a
placeholder until each module lands.
