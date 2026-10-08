# HELIOS

**An AI-native, multi-tenant cybersecurity-as-a-service platform** — one
Next.js application that is both a unified SOC engine and the MSSP control
plane built on top of it. A platform owner provisions customer tenants,
each tenant subscribes to security services priced by which AI model tier
powers them, and the underlying detection/investigation/forensics/
governance engine (itself a merger of four previously separate tools)
operates every tenant's security with a small human staff in the loop for
exceptions, approvals, and delivered work like pentests.

| Feature area | Ported from | What it does |
|---|---|---|
| Agent Governance | `aegis` | Zero-trust identity, trust scoring, DLP, and breach investigation for autonomous AI agents |
| Investigations | `asip` | Multi-agent root-cause analysis over forensic telemetry |
| Email & File Forensics | `desas` | Header/body/attachment analysis and sandbox URL detonation for phishing triage |
| Cases & Alerts | `signal-fusion` | SIEM-style detection engine and alert correlation across MITRE ATT&CK |

Every module writes into one shared data model — a single `Case` /
`Detection` / `TimelineEntry` stream, one MITRE ATT&CK reference set, one
threat-intel cache, one hash-chained audit log — instead of four apps with
four separate schemas glued together behind one UI. See `legacy/components/`
for the original standalone sources each module is ported from.

## MSSP platform layer

Built on top of that engine, admin-provisioned (no public signup):

- **Multi-tenancy** — every `Case`/`Agent`/`IngestedEvent`/`Playbook`/
  `AuditLog` row is scoped to an `Organization`. Platform roles
  (`PLATFORM_OWNER`/`PLATFORM_ANALYST`) see every tenant; org roles
  (`ORG_ADMIN`/`ORG_ANALYST`/`ORG_VIEWER`) only ever see their own —
  enforced centrally by `src/lib/tenant.ts`'s `tenantWhere()`, spread into
  every query that touches tenant data (see `src/lib/tenant.test.ts` for
  the scoping-helper tests, and the commit history for the Playwright
  verification that one org's data never appears in another's views).
- **Admin-provisioned onboarding** — the platform owner creates each
  tenant and its first org-admin user from `/admin/organizations`, with a
  one-time generated password. There is no self-service signup.
- **Service catalog + billing** — `Plan` rows are priced per
  `ServiceType` × `AiTier` combination (`/admin/plans`); tenants subscribe,
  get real invoices, and a platform owner marks them paid
  (`/admin/organizations/[id]`, `/admin/billing`). No live payment
  processor is wired up — `Invoice.status` is advanced manually for now; a
  Stripe (or similar) webhook is a drop-in replacement for that one step
  later. Customers see their own plan, usage, and invoices at `/billing`,
  plus a "request a change" form that logs against their org and surfaces
  on the admin side — the entire customer-initiated billing workflow given
  there's no self-serve checkout yet.
- **AI model marketplace** — every org has an `AiTier`
  (`ESSENTIAL`/`PROFESSIONAL`/`ENTERPRISE`/`SELF_HOSTED`) set by the
  platform owner. `ESSENTIAL`/`PROFESSIONAL`/`ENTERPRISE` map to Claude
  Haiku/Sonnet/Opus respectively (`src/lib/investigations/llm.ts`'s
  `TIER_MODEL`) — reusing the existing Anthropic-first fallback chain
  rather than adding a second cloud vendor for no pricing benefit.
  `SELF_HOSTED` routes to the org's own Ollama endpoint
  (`Organization.selfHostedOllamaUrl`) and deliberately never falls
  through to a cloud provider. The investigation swarm
  (`runInvestigationSwarm`) picks up the calling org's tier automatically.
- **Pentest-as-a-service** — a request/scheduling workflow
  (`/pentest`), not automated exploitation. Customers submit targets +
  scope; platform staff schedule, start, and deliver findings, which
  creates a real `Case` (`sourceType: PENETRATION_TEST`) with one
  `Detection` per finding, shown inline on the request since there's no
  standalone case-detail route to link to.
- **Integrations** (`/integrations`) — a vendor-agnostic webhook
  ingestion framework, not per-vendor API clients. Any tool that can POST
  a webhook (most SIEMs/EDRs/cloud security tools can) points at a
  generated URL + secret; its events flow through the same
  normalize → ingest → detect pipeline every other module already uses.
  Real pull-based per-vendor connectors (e.g. "isolate a host via the
  CrowdStrike API") are deliberately **not** built — there are no vendor
  credentials in this environment to build or test them against. This is
  the extensible interface they would plug into later, not a simulation of
  having built them.

## Stack

- **Framework**: Next.js 16 (App Router), React 19, TypeScript
- **UI**: Tailwind CSS 4, shadcn/ui primitives (set up manually under
  `src/components/ui` — the shadcn CLI's registry isn't reachable from this
  environment's network), Motion, ECharts, TanStack Table
- **Data**: TanStack Query (client), Prisma + PostgreSQL (server), Zustand
  (local UI state only)
- **Auth**: Auth.js (credentials provider + Prisma adapter), role +
  tenant-aware session (`src/lib/tenant.ts`)

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
npm run db:seed      # creates the platform owner + a demo tenant
```

Seeding creates **two** accounts:

| Role | Email | Password | Env override |
|---|---|---|---|
| Platform owner (sees every tenant, `/admin/*`) | `admin@helios.local` | `helios-admin` | `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` |
| Demo tenant's org admin ("Acme Corp") | `admin@acme-demo.local` | `acme-admin` | `SEED_ORG_ADMIN_EMAIL` / `SEED_ORG_ADMIN_PASSWORD` |

Any pre-tenancy demo data already in the database gets backfilled onto the
demo tenant automatically, once, the first time you seed after migrating.

### 4. Run the app

```bash
npm run dev
```

Visit `http://localhost:3000` and sign in as either account above to see
the platform-owner view or a tenant's own view.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Start the dev server |
| `npm run build` | Production build |
| `npm run lint` | ESLint |
| `npm run db:migrate` | Run Prisma migrations |
| `npm run db:studio` | Open Prisma Studio |
| `npm run db:seed` | Seed the platform owner + demo tenant |
| `npm run test` | Run the test suite (Vitest) |

## Testing

`src/lib/**/*.test.ts` covers the ported business logic directly — all 11
Cases & Alerts detectors, the forensics engine's pure signal functions
(entropy, obfuscation, polyglot/OLE/XLM/PDF detection), the governance
pipeline (constitution, reasoning, DLP, policy, and the sidecar that chains
them), the investigations entity-graph builder, the playbook trigger
matcher, the threat-intel mock-fallback paths, the tenant-scoping helper,
the AI-tier → model mapping, and — as real Postgres integration tests
(Prisma-backed code isn't meaningfully testable with a mocked database) —
the audit hash chain, the pentest request state machine, and the
integrations webhook's auth boundary. These need `DATABASE_URL` pointed at
a running instance, same as the app itself.

## Project structure

```
src/
  app/
    (app)/              # authenticated app shell — one route per feature area
      admin/              # platform-owner-only: organizations, plans, billing
      billing/            # org-facing: plan, invoices, request-a-change
      pentest/            # request/scheduling workflow (role-aware view)
      integrations/        # org-facing webhook connector management
    api/
      auth/                 # Auth.js route handler
      integrations/[id]/ingest/  # the one generic webhook ingest endpoint
    login/
  components/
    ui/                # shadcn/ui primitives
    shell/              # sidebar, topbar, nav (role-aware)
    admin/               # organization/plan/billing admin UI
    billing/              # org-facing billing UI
    pentest/               # request/schedule/deliver-findings UI
    integrations/            # connector registration UI
    governance/                # Agent Governance feature components
    dashboard/                   # Overview KPI tiles / charts
    providers/                     # TanStack Query + session + tenant providers
  lib/
    governance/          # ported aegis engines (identity, trust, policy, DLP, reasoning, sidecar, scenarios)
    billing/               # service catalog, subscriptions, invoices
    pentest.ts               # pentest request state machine + findings delivery
    integrations/               # webhook registration + ingest handling
    tenant.ts                     # session/role/org-scoping helpers (requireSession, tenantWhere)
    tenant-scope.ts                 # the pure (next-auth-free) half of tenant.ts, for unit tests
    db.ts                             # Prisma client singleton
    auth.ts                            # Auth.js config
    audit.ts                            # shared hash-chained audit log
    nav.ts                                # role-aware feature-area nav config
    severity.ts                            # shared severity → color/label mapping
prisma/
  schema.prisma           # the unified + multi-tenant data model
legacy/
  components/                # original aegis / asip / desas / signal-fusion sources (reference only)
```

## Status

All 9 original feature areas, plus the full MSSP platform layer, are
built and verified end-to-end against a live Postgres instance (build,
lint, the full test suite, and real browser/HTTP verification of each new
flow — see individual commits for the specific verification each one ran):

- **Overview** — cross-source KPI dashboard, tenant-scoped
- **Agent Governance** (from aegis) — identity, trust, policy, DLP,
  reasoning-drift detection, all 5 attack scenarios
- **Threat Intelligence** (from asip/desas/signal-fusion) — shared
  VirusTotal/AbuseIPDB lookup + cache, used by every other module
- **Cases & Alerts** (from signal-fusion) — all 11 detectors across 12
  MITRE tactics, ingestion pipeline, attack simulation
- **Investigations** (from asip) — the Triage → RCA → adversarial QA →
  Report swarm (a plain state machine, not LangGraph — see
  `src/lib/investigations/orchestrator.ts` for why), now running on
  whichever AI tier the calling org is subscribed to
- **Email & File Forensics** (from desas) — full JS port: header/SPF/
  DKIM/DMARC analysis, body/URL scoring, attachment forensics, and real
  Playwright-driven sandbox URL detonation
- **Response Playbooks** (from signal-fusion) — trigger matching,
  auto-execute and approval-gated execution, scoped per tenant
- **MITRE ATT&CK Coverage** — aggregated across all four detection
  sources, tenant-scoped
- **Audit Log** — one hash-chained trail for every write action
  app-wide, with a one-click integrity check (its `AuditLog.case`
  relation now uses `onDelete: Restrict` rather than Prisma's implicit
  `SetNull` — a real bug where deleting a Case could silently corrupt an
  already-hashed audit entry, found and fixed while adding tests)
- **Admin (Organizations / Plan Catalog / Platform Billing)** — tenant
  provisioning, service × AI-tier pricing, cross-tenant invoices
- **Billing** (org-facing) — plan, usage, invoices, request-a-change
- **Pentest** — request/scheduling/findings-delivery workflow
- **Integrations** — vendor-agnostic webhook ingestion framework

Known gaps, disclosed rather than silently dropped:

- DESAS's modern OOXML macro extraction (`.xlsm`/`.docm` VBA source is
  compressed inside `vbaProject.bin` in MS-OVBA format — legacy binary
  `.doc`/`.xls` OLE macros are unaffected), signal-fusion's full
  48-scenario simulation library (condensed to 16 curated ones covering
  the same 12 tactics), and desas's deeper 3-pillar JS-behavioral
  exfiltration model in the sandbox (replaced with a simpler
  password-field/redirect-chain/POST-request heuristic).
- **No live payment processor.** Plans, subscriptions, and invoices are a
  real data model with a real UI; actually charging a card is a stubbed
  manual step (`setInvoiceStatus`) until a processor is wired up.
- **No per-vendor integration connectors.** The webhook ingestion
  framework is real and works today; pull-based API clients for specific
  products (CrowdStrike, Splunk, Wazuh, etc.) and vendor-specific response
  actions are future work that needs real vendor credentials to build
  against.
- **No self-service signup.** Every tenant is admin-provisioned by
  design (per the explicit product decision), not a limitation to lift
  later without a deliberate choice to do so.
