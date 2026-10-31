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
| **Log collection** | Logs are pushed to the ingest URL, pulled by HELIOS from vendor APIs (Entra ID sign-ins, audits and risk, Defender XDR, CrowdStrike, SentinelOne, Okta, Google Workspace, AWS CloudTrail, the Azure Activity Log, Google Cloud audit logs), or sent by the HELIOS forwarder, a signed Fluent Bit configuration for syslog, Windows event logs and files. Everything goes through a durable queue that takes clients in turn. Every event is stored once, in OCSF form, with where its addresses are (country, city and network, from a GeoIP database on the server), and unreadable records wait in a dead-letter queue to be replayed. A source that goes quiet opens a case, and a client can't go live while a source is dead. |
| **Approvals & alerts** | One inbox for everything waiting on someone's yes: held containment (approve or reject in place), playbooks, regulatory notices and rulebooks to sign. Each person picks which notifications also reach them by email, SMS or WhatsApp (Twilio, or a signed webhook to your own gateway), through a durable outbox with retries and an hourly cap. Client approver chains text and email approvers directly. |
| **Regulatory reporting** | India's CERT-In directions (report within 6 hours of noticing an incident of one of the 20 listed types) and the DPDP Rules' breach notices (the Data Protection Board and each person affected without delay, a detailed report to the Board within 72 hours). <ul><li>Rules propose the incident type from the case's techniques, detections and assets, and open the clock on their own at the client's severity threshold.</li><li>The SOC drafts from the case, the client approves in its portal (or staff record an approval given by phone), and the report is emailed to CERT-In with its PDF or the filing is recorded with its reference.</li><li>Reminders as each deadline nears and passes, follow-up updates, and an ISO/IEC 27001 Annex A evidence map built from the platform's own records.</li></ul> |
| **Cases & alerts** | One queue for every source, with: <ul><li>tier-1/2/3 escalation;</li><li>assignment, watchers, @mentions and internal or client-visible discussion;</li><li>SLA clocks from the client's plan;</li><li>notifications;</li><li>correlation of related alerts into one case.</li></ul> |
| **Detection engineering** | Import Sigma rules: each is compiled into a matcher over the client's events (anything it can't evaluate faithfully is refused with the reason), backtested against recent history, run in testing (matches counted, nothing opened) and then made live. Tune any detector or rule per client: switch it off there, leave out known-good hosts, accounts or processes, or set its severity, each with a reason, an optional expiry and a count of what it held back. |
| **Data retention** | Per-client log retention: searchable for a first period, then archived one day at a time (compressed and encrypted with the client's own key, hash-checked on every read) to S3 or a directory, and deleted when the retention ends. At least 180 days where CERT-In applies, a check that the database and archive are declared in India, case evidence kept with the case, and legal holds that stop deletion. Events are partitioned by month, so a month past everyone's retention is dropped whole. |
| **SOC operations** | A 24/7 on-call rota (primary and backup, generated rotations, cover for swaps and leave) with pages that escalate from the primary to the backup to the SOC managers until someone answers, by SMS, email and in the app, plus a handoff at each shift start. Runbooks that attach themselves to the cases they match and are worked as checklists (no true positive closed with a required step open). A weekly QA sample of what the AI did on its own, weighted toward high severity, new rules and critical assets, whose findings count against the AI on the autonomy ladder. A daily digest to each client and the SOC of what HELIOS did without asking. |
| **Contracts & billing** | Pilots with success criteria measured from the platform's own records (time to acknowledge, AI agreement, wrong containments, sources live) that convert into subscriptions. Contracts drafted from quotes, signed in the app by the client's admin, recording the AI autonomy agreed, the rulebook version in force, the liability cap for automated containment and the DPA. GST invoices drafted each billing period and numbered per financial year, with CGST/SGST or IGST by place of supply, plus payments, overdue reminders and renewals. |
| **AI first responder** | On every new case an AI agent triages, explains its verdict with cited evidence, and proposes containment. A grounding check rejects targets the evidence doesn't contain. Evidence is treated as attacker-controlled: text aimed at the AI is flagged and escaped, a fooled model can't downgrade a case, and anything proposed from steered evidence waits for a person. A deterministic policy (kill switch, plan, client consent, the client's rulebook, its autonomy ladder, per-agent autonomy, allow-list, confidence bar, critical-endpoint guard, model evaluation, rate limit) decides what runs, what waits for approval, and what is only suggested, and records which rule decided. An investigation agent works a case on its own with read-only tools (the client's telemetry, inventory, indicator reputation, related cases), cites what it looked at, and never reads attacker-written free text directly: a split-privilege extractor passes on only validated indicators. Agent types and models are chosen per agent: Claude on Anthropic's API or in the client's own AWS account (Amazon Bedrock), Azure OpenAI, or local and offline models (Ollama, LM Studio, vLLM), including an on-premises AI box (`deploy/edge-ai`). Agent instructions are prompt-cached, and cache use is priced into the spend figures. |
| **Response actions** | Containment goes through native connectors that call the vendor's API with the client's own credentials (Defender for Endpoint, Entra ID including password resets, Exchange Online message purges, CrowdStrike Falcon including file blocks, SentinelOne, Okta, Cloudflare), or through a signed webhook to your automation or SOAR. An action counts only once the vendor confirms it. Each connector can run in dry-run mode first. Repeated connector failures pause automation for that client, and IP blocks and account disables can be time-boxed. Without a connector, an action is left **to do by hand** and only counts once an analyst confirms they did it. Every action can be rolled back and is audited. |
| **Investigations** | Log investigations with an agent pipeline. Upload Windows `.evtx` logs straight from Event Viewer, Sysmon, EDR and SIEM exports (JSON, CSV, Excel `.xlsx`), or a ZIP of them, password-protected ones included. The report names the playbooks that fit. |
| **Email & file forensics** | Headers, links, attachments and verdicts for `.eml` / `.msg` or any file. Opens password-protected archives (the analyst's password, or one quoted in the message), recovers VBA macro source, reads QR codes and the text in images, and detonates links, through an egress proxy if there is one. |
| **Threat intel, playbooks, ATT&CK, attack graph, audit log** | A shared indicator store with public threat feeds. Approval-gated playbooks with recommendations that give their reasons. Detection coverage against ATT&CK, with detectors you can switch off. An attack graph that links cases sharing hosts, accounts and indicators, and flags attack chains across tactics. A hash-chained audit trail. |
| **Reports** | Volume, response times, SLA compliance, AI performance and analyst workload for any period or month, compared with the period before. Clients get their own. Every report, incident and quote downloads as a PDF. |
| **Agent governance** | Govern the AI agents your clients run. Each agent asks `POST /api/governance/evaluate` before acting; constitution, reasoning-drift, DLP and policy checks decide; trust adapts; breaches revoke the agent and open a case. |
| **Build & Price** | Configure a client's stack across every protection layer and compare vendors and plans. Estimate monthly, annual, one-time, maintenance (AMC) and 3-year costs, with cloud-vs-local AI, margins and multi-currency, then save versioned quotes. Endpoints can be counted by operating system. An **upgrade review** compares every tool in an existing setup (a saved quote, or a client's onboarded tools and inventory) with each alternative: what it adds or removes, whether it runs on the client's machines, and the price difference. A **stack advisor** suggests one tool per layer for a goal (best value, lowest cost, strongest protection); its rules are traceable, and an AI agent can choose among the candidates it priced. |
| **Whole attack surface** | Nine asset groups, not just laptops: user endpoints, mobile, servers and infrastructure, cloud and workloads, network and security devices, identity and access, IoT and OT, email and collaboration, and applications, APIs and developer systems. Each lists what it includes, its main risk, what to deploy, the telemetry to collect, what gets detected and how the SOC responds. Groups get P1–P3 priorities that move with the organization (OT and medical devices are P1 for a hospital or a factory, cloud for a cloud-first company). Quotes count every group and price monitoring per asset. The inventory files each asset under its group (firewall, PLC, cloud VM, repository…). A **solution designer** answers "design my cybersecurity solution": priorities, what to deploy per group (in place, suggested or a gap), the centralized detection-and-response architecture, and a phased rollout. |
| **Public website** | Visitors who aren't signed in see a home page about the service, built from your real catalog, plans and detection coverage, and a price estimator. The estimator has the same upgrade review and advisor, and a quote request that arrives as a draft quote. Costs and margins never leave the console; switch any part off under Settings → Public website. |
| **Client rulebooks** | Each client signs the rules HELIOS works under: assets never to isolate and crown jewels, accounts never to disable, which actions run automatically (from what severity), need approval or never happen, blast-radius limits and the two-person rule, business hours, maintenance windows and change freezes, an approver chain with timeouts, AI data handling, and CERT-In contacts. Rules only ever restrict; hard rules bind analysts too. Industry templates, a 30-day dry run, version diffs, client signature, allowlists with owners and expiry, and YAML import/export. |
| **AI per client** | Each client's rulebook decides which models may read its evidence (any, region-locked, on-premises only). Clients can bring their own key and pick a model per agent, and analysts can choose their own where allowed. Personal data is masked before cloud models see it. A monthly budget applies, and every AI run records why its model was chosen. |
| **Model evaluations** | Every model is scored on a labelled golden set (attacks, benign activity, look-alikes, and evidence with planted instructions) through the same pipeline first response uses. The investigation agent is also scored on scenarios whose telemetry and inventory are seeded for its tools, and judged on what it finds that the alert didn't show. A model a client or user picks only suggests until it passes for that agent; each scorecard shows case-by-case results. |
| **Shadow mode** | AI earns autonomy per client and per action: it observes silently first, and its decisions are scored against analysts' dispositions when cases close. Promotions need a clean record and the client's approval; a bad week or a critical mistake demotes automatically. |
| **Settings, API, app** | Company profile, environment (production or test), provider keys stored encrypted, forensics thresholds. A REST API with personal tokens for ticketing, SOAR and client portals. Installs as a desktop or mobile app. |

### Real data only

HELIOS ships no sample clients, no invented prices and no fake intelligence.
- **Seeded:** only facts. These are vendors' published list prices (each with its source), Anthropic's published model prices, the MITRE ATT&CK reference set, the public threat-feed addresses (disabled until you enable them), starter playbooks and agent profiles.
- **Yours to enter:** your plans, rates, SLAs and exchange rates. The overview shows admins a setup checklist, and a quote that needs a price nobody has set says so and can't be saved.
- **Test data:** there's a separate, clearly labelled seed for testing, and a database can be marked as a test environment (see below).

See [`docs/architecture.md`](docs/architecture.md) for how the pieces fit together, and [`docs/porting-notes.md`](docs/porting-notes.md) for the history of the original modules.

## Stack

- **Framework:** Next.js 16 (App Router, Server Actions, `after()` for background work), React 19, TypeScript.
- **UI:** Tailwind CSS 4 and shadcn/ui primitives, with light and dark themes. Charts use ECharts; process graphs use Cytoscape.
- **Data:** Prisma + PostgreSQL 16, TanStack Query.
- **Auth:** Auth.js credentials with optional or required two-step sign-in (authenticator app, recovery codes) and lockout after repeated failures, plus single sign-on for staff with any OpenID Connect provider. Every page and Server Action re-checks the session, the role's permissions and the client scope.
- **AI:** `@anthropic-ai/sdk` with structured outputs and prompt caching; `@anthropic-ai/bedrock-sdk` for Claude in Amazon Bedrock; Azure OpenAI and any OpenAI-compatible local server.
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

Sign in, fill in **Settings** (your company details, which go on quotes and reports), then work through the **Get HELIOS ready** checklist on the overview:
1. Define service plans and fill in the price book (Build & Price → Pricing setup).
2. Connect an AI provider (AI Agents).
3. Invite your team (Team & Roles).
4. Add clients (Clients).
5. Onboard their tools (Tools & Integrations).
6. Enable threat feeds (Threat Intelligence).

None of the integrations is required. Provider keys can be saved under **Settings** (stored encrypted, and preferred over the environment variable):

| Setting / variable | Without it |
|---|---|
| `ANTHROPIC_API_KEY` | AI agents use a provider configured in the app (including local models), or the built-in deterministic engine |
| VirusTotal / AbuseIPDB key (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) | Reputation comes from enabled threat feeds and your own blocks only |
| SOC Slack webhook (`SLACK_WEBHOOK_URL`) | Chat steps use the client's Slack or Teams integration; with neither, they're left to do by hand |
| MxToolbox key (`MXTOOLBOX_API_KEY`) | Email forensics skips sender-domain diagnostics |
| `DETONATION_PROXY` (else `HTTPS_PROXY` / `HTTP_PROXY`) | Link detonation connects directly |
| `HELIOS_GEOIP_CITY_DB`, `HELIOS_GEOIP_ASN_DB` (paths to MaxMind GeoLite2 or DB-IP Lite `.mmdb` files) | Events keep only the country their source names; impossible travel uses country centroids |

A client's own AI provider (an OpenAI-compatible or Azure endpoint its admin types in) is only called at a public https address. When HELIOS runs inside a client's network and that client's model is on a private address, set `HELIOS_ALLOW_PRIVATE_CLIENT_AI=1`. A platform Bedrock provider saved without credentials uses the server's own AWS identity (its IAM role, or `AWS_*`). For on-premises AI boxes that require mutual TLS (`deploy/edge-ai`), set `HELIOS_AI_CLIENT_CERT` and `HELIOS_AI_CLIENT_KEY` (and `HELIOS_AI_CA` for a box on its own CA).

The ingest workers (queue, pull collectors, source health) run in the web process. To run them on their own, set `HELIOS_INGEST_WORKER=external` on the web servers and run `npm run worker` (any number of them). `HELIOS_INGEST_MAX_PENDING` sets how many batches a client may have waiting (200).

### Test data

```bash
npm run db:seed:test
```

This loads data for exercising the platform end to end:
- two test clients, two test plans, and test values for any unset price-book items;
- one account per role under the reserved `.test` domain;
- vendor alerts and attack telemetry from the fixtures in `src/lib/__tests__/fixtures`, pushed through the real ingest, detection and AI first-response pipeline;
- a governed test agent driven through the real governance gate.

Everything is labelled "Test ·", and test clients are flagged: they're badged wherever they appear and left out of commercial figures. The command refuses to run with `NODE_ENV=production`. Use a separate database if you don't want test data next to real clients.

To use a whole database as a **test environment**, keeping what it already holds as test data:

```bash
npm run db:test-env
```

Records that belong to no client move to a "Test · Earlier sample data" client, every client is marked test, a test platform admin (`admin@helios.test`) is added, the test data above is loaded, and every page shows a test-environment banner. Switch back to production under Settings.

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
| `npm run db:test-env` | Make this database a test environment, keeping its records as test data |
| `npm run db:studio` | Open Prisma Studio |

CI (`.github/workflows/ci.yml`) runs:
- lint, typecheck and unit tests;
- migrations plus the integration suite against a Postgres service;
- a production build.

## Machine endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/ingest/<integrationId>` | Bearer ingest token (shown once at onboarding) | A client tool or the HELIOS forwarder pushes alerts, telemetry or inventory in its own format, plain or `Content-Encoding: gzip`; answered 202 with a batch id once queued (429 with Retry-After when the client's queue is full). Inventory rows can carry `assetClass` and `assetType` (e.g. `network`/`firewall`, `iot_ot`/`plc`) |
| `POST /api/governance/evaluate` | Bearer agent token (shown once at identity issue) | A governed AI agent asks before acting |
| `GET /api/threat-intel/blocklist` | — | Plain-text blocklist for firewalls to pull |
| `GET /api/health` | — | Liveness and database check |
| `/` (signed out), `/home`, `/estimate` | — | The public website and estimator. Its two Server Actions (AI suggestion, quote request) are rate-limited per visitor; AI answers share a daily budget |
| `/api/v1/…` | Bearer personal access token (API Tokens page) | REST API: cases (list, read, update, comment), indicator lookup, service metrics. The token acts as its owner, read-only unless created with write |

Response connectors receive `POST`s with an `x-helios-timestamp` header and an `x-helios-signature: sha256=<HMAC(secret, "<timestamp>.<body>")>` header.

## Security notes

- **Authorization:** every page and Server Action checks the session, the role's permission and the client scope. Out-of-scope records look like missing ones.
- **Secrets:** integration secrets, AI provider keys and the provider keys under Settings are stored encrypted with AES-256-GCM; each client's are sealed with its own data key, wrapped by a master key that AWS KMS can protect. Ingest, agent and API tokens are stored only as SHA-256 hashes.
- **Outgoing mail:** sent through your own SMTP server (`HELIOS_SMTP_URL` or Settings); attachments are in memory only, and the transport may not read files or fetch URLs.
- **Tenant isolation:** besides the application's filters, Postgres row-level policies keep client sessions and client API tokens to their own rows. Run the app as a non-superuser database role (or set `HELIOS_DB_TENANT_ROLE`).
- **Prompt injection:** evidence is spotlighted as untrusted data, scanned for text aimed at the AI, and steered cases go to a person. The scanner is pattern-based, so the policy, not the scanner, is what stops a fooled model.
- **AI containment:** it never acts on a target that isn't in the case evidence. Account actions and process kills always need a human. Clients can cap autonomy for their estate.
- **Audit log:** appends serialize on a Postgres advisory lock, so the chain can't fork. Records referenced by audit entries can't be deleted.
- **URL detonation:** connections are checked against private, loopback and link-local ranges at connect time. Through an egress proxy, every hop is vetted before it leaves, and internal-looking names are refused. JavaScript is never executed.
- **Untrusted files:** archives, Office containers, images and event logs are parsed with bounded reads (member and pixel limits, chain-length guards, OCR timeouts); nothing in them is executed.
- **Rendering:** model output is rendered as Markdown with raw HTML disabled.
- **Public estimator:** visitors get your prices only (no costs, margins, resale ratio or client counts). The server resets discounts, exchange rates and usage overrides on everything a visitor sends, and quote requests carry a honeypot field, a consent check and per-visitor and daily limits.
