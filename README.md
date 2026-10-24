# HELIOS

**A managed detection & response (MDR) platform for a small security company.** It runs your SOC for many client organisations at once:
- client tools stream alerts into one case queue;
- AI agents do the first containment and initial analysis;
- your analysts do the primary analysis;
- a Build & Price configurator quotes the service.

| Area | What it does |
|---|---|
| **Clients & plans** | Each client (tenant) has a service plan that sets its SLA targets, the most autonomy its AI agents may take, and what it pays. Client users get their own portal: incidents, endpoints, approvals, AI consent. |
| **Roles** | 11 roles (platform admin, SOC manager, tier-1/2/3 analysts, threat hunter, detection engineer, auditor, account manager, client admin, client stakeholder). Navigation, queues and actions follow the role; analysts can be limited to security domains (endpoint, identity, email, network, cloud, AI agents). |
| **Tools & integrations** | Onboard each client's EDR, antivirus, MDM, email security, identity, firewall, SIEM, backup, ticketing and chat tools. Tools are assigned per role or per person. Vendor alerts arrive on a per-tool ingest URL and become cases; hosts become the endpoint inventory with the protection each tool provides. |
| **Cases & alerts** | One queue for every source, with: <ul><li>tier-1/2/3 escalation;</li><li>assignment, watchers, @mentions and internal or client-visible discussion;</li><li>SLA clocks from the client's plan;</li><li>notifications;</li><li>correlation of related alerts into one case.</li></ul> |
| **AI first responder** | On every new case an AI agent triages, explains its verdict with cited evidence, and proposes containment. A grounding check rejects targets the evidence doesn't contain. A deterministic policy (kill switch, client consent, per-agent autonomy, allow-list, confidence bar, critical-endpoint guard, rate limit) decides what runs, what waits for approval, and what is only suggested. Agent types and models are chosen per agent: Claude online today, local or offline models (Ollama, LM Studio, vLLM) when you're ready. |
| **Response actions** | Containment goes through the client's response connector: a signed webhook to your automation, a SOAR or the vendor's API. Without a connector, an action is left **to do by hand** and only counts once an analyst confirms they did it. Every action can be rolled back and is audited. |
| **Investigations, forensics, threat intel, playbooks, ATT&CK coverage, audit log** | Log investigations with an agent pipeline. Upload Windows `.evtx` logs straight from Event Viewer, Sysmon, EDR and SIEM exports (JSON, CSV, Excel `.xlsx`), or a ZIP of them. Email and file forensics. A shared indicator store with public threat feeds. Approval-gated playbooks. Detection coverage against ATT&CK. A hash-chained audit trail. |
| **Agent governance** | Govern the AI agents your clients run. Each agent asks `POST /api/governance/evaluate` before acting; constitution, reasoning-drift, DLP and policy checks decide; trust adapts; breaches revoke the agent and open a case. |
| **Build & Price** | Configure a client's stack across every protection layer and compare vendors and plans. Estimate monthly, annual, one-time, maintenance (AMC) and 3-year costs, with cloud-vs-local AI, margins and multi-currency, then save versioned quotes. |

### Real data only

HELIOS ships no sample clients, no invented prices and no fake intelligence.
- **Seeded:** only facts. These are vendors' published list prices (each with its source), Anthropic's published model prices, the MITRE ATT&CK reference set, the public threat-feed addresses (disabled until you enable them), starter playbooks and agent profiles.
- **Yours to enter:** your plans, rates, SLAs and exchange rates. The overview shows admins a setup checklist, and a quote that needs a price nobody has set says so and can't be saved.
- **Test data:** there's a separate, clearly labelled seed for testing (see below).

See [`docs/architecture.md`](docs/architecture.md) for how the pieces fit together, and [`docs/porting-notes.md`](docs/porting-notes.md) for the history of the original modules.

## Stack

- **Framework:** Next.js 16 (App Router, Server Actions, `after()` for background work), React 19, TypeScript.
- **UI:** Tailwind CSS 4 and shadcn/ui primitives, with light and dark themes. Charts use ECharts; process graphs use Cytoscape.
- **Data:** Prisma + PostgreSQL 16, TanStack Query.
- **Auth:** Auth.js credentials, with lockout after repeated failures. Every page and Server Action re-checks the session, the role's permissions and the client scope.
- **AI:** `@anthropic-ai/sdk` with structured outputs, plus any OpenAI-compatible local server.
- **Tests:** Vitest unit tests, plus a Postgres-backed integration suite.

## Getting started

```bash
docker compose up -d              # or any Postgres 16; point DATABASE_URL at it
cp .env.example .env              # set AUTH_SECRET (and HELIOS_ENCRYPTION_KEY in production)
npm install
npm run db:migrate                # applies prisma/migrations
npm run db:seed                   # first admin + reference facts (idempotent)
npm run dev
```

The seed creates the first admin, `admin@helios.local` by default. The password is `SEED_ADMIN_PASSWORD` if you set it; otherwise a random one is printed once.

Sign in, then work through the **Get HELIOS ready** checklist on the overview:
1. Define service plans and fill in the price book (Build & Price → Pricing setup).
2. Connect an AI provider (AI Agents).
3. Invite your team (Team & Roles).
4. Add clients (Clients).
5. Onboard their tools (Tools & Integrations).
6. Enable threat feeds (Threat Intelligence).

None of the environment integrations is required:

| Variable | Without it |
|---|---|
| `ANTHROPIC_API_KEY` | AI agents use a provider configured in the app (including local models), or the built-in deterministic engine |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | Reputation comes from enabled threat feeds and your own blocks only |
| `SLACK_WEBHOOK_URL` | Chat steps use the client's Slack or Teams integration; with neither, they're left to do by hand |
| `MXTOOLBOX_API_KEY` | Email forensics skips sender-domain diagnostics |

### Test data

```bash
npm run db:seed:test
```

This loads data for exercising the platform end to end:
- two test clients, two test plans, and test values for any unset price-book items;
- one account per role under the reserved `.test` domain;
- vendor alerts and attack telemetry from the fixtures in `src/lib/__tests__/fixtures`, pushed through the real ingest, detection and AI first-response pipeline;
- a governed test agent driven through the real governance gate.

Everything is labelled "Test ·". The command refuses to run with `NODE_ENV=production`. Use a separate database if you don't want test data next to real clients.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Start the dev server |
| `npm run build` | Production build |
| `npm run lint` | ESLint |
| `npm run typecheck` | Generate route types and run `tsc --noEmit` |
| `npm test` | Unit tests (Vitest) |
| `RUN_DB_TESTS=1 DATABASE_URL=…/helios_test npm test` | Also runs the Postgres integration suite. It **truncates every table**, so it refuses to run unless the database name ends in `_test` |
| `npm run db:migrate` | Create / apply Prisma migrations (dev) |
| `npm run db:seed` | First admin and reference facts (idempotent; never overwrites your prices) |
| `npm run db:seed:test` | Labelled test clients, accounts and alerts (never in production) |
| `npm run db:studio` | Open Prisma Studio |

CI (`.github/workflows/ci.yml`) runs:
- lint, typecheck and unit tests;
- migrations plus the integration suite against a Postgres service;
- a production build.

## Machine endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/ingest/<integrationId>` | Bearer ingest token (shown once at onboarding) | A client tool pushes alerts, telemetry or inventory in its own format |
| `POST /api/governance/evaluate` | Bearer agent token (shown once at identity issue) | A governed AI agent asks before acting |
| `GET /api/threat-intel/blocklist` | — | Plain-text blocklist for firewalls to pull |
| `GET /api/health` | — | Liveness and database check |

Response connectors receive `POST`s with an `x-helios-timestamp` header and an `x-helios-signature: sha256=<HMAC(secret, "<timestamp>.<body>")>` header.

## Security notes

- **Authorization:** every page and Server Action checks the session, the role's permission and the client scope. Out-of-scope records look like missing ones.
- **Secrets:** integration secrets and AI provider keys are stored encrypted with AES-256-GCM. Ingest and agent tokens are stored only as SHA-256 hashes.
- **AI containment:** it never acts on a target that isn't in the case evidence. Account actions and process kills always need a human. Clients can cap autonomy for their estate.
- **Audit log:** appends serialize on a Postgres advisory lock, so the chain can't fork. Records referenced by audit entries can't be deleted.
- **URL detonation:** connections are checked against private, loopback and link-local ranges at connect time. JavaScript is never executed.
- **Rendering:** model output is rendered as Markdown with raw HTML disabled.
