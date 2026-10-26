# HELIOS architecture

## Platform layer

### Tenancy and access (`lib/rbac.ts`, `lib/access.ts`, `lib/session.ts`)

- **Roles.** `rbac.ts` maps each of the 11 roles to its permissions. It is client-safe, so navigation and buttons use the same `can()` the server does.
- **Users.** `session.ts` re-reads the user from the database on every request, so deactivation and role changes apply immediately. `pageGuard(...)` redirects anonymous users and calls `forbidden()` when a permission is missing.
- **Scope.** `access.ts` scopes every query to what the user may see:
  - client users see only their tenant;
  - analysts with domains see only those queues;
  - staff can focus on one client through the tenant switcher (`helios-tenant` cookie).
- **Case access.** `assertCaseAccess` makes an out-of-scope case look like a missing one.

### Reference data in the database

Plans, the price book, the tool catalog, currencies, model prices and threat feeds are tables. Only facts are seeded (`prisma/seed-data/`):
- vendor list prices with their source, or `null` where the vendor sells by quote;
- Anthropic's published model prices;
- the base currency;
- the public feed addresses, disabled by default.

The admin enters everything that is company policy. The code describes only the *shape*:
- `lib/plans.ts` covers plan parsing and SLA arithmetic;
- `lib/pricing/items.ts` defines price-book items, all without values;
- `lib/integrations/catalog.ts` holds the tool taxonomy.

`lib/setup.ts` drives the admin's first-run checklist.

### Settings and secrets (`lib/settings.ts`, `lib/platform-secrets.ts`)

Platform settings are rows in `platform_settings`, each validated by a Zod schema with a default:
- **Environment:** `production` or `test`. A test environment shows a banner on every page. Test clients (`Tenant.isTest`) are badged wherever they're listed and left out of commercial figures in production.
- **Company profile:** the MSSP's own details, printed on quotes and reports.
- **Forensics:** verdict thresholds and trusted link domains.
- **Detection tuning:** SIEM detectors switched off on the ATT&CK coverage page.
- **Provider keys** (VirusTotal, AbuseIPDB, MxToolbox, the SOC's Slack webhook): sealed with AES-256-GCM, only the last four characters kept in clear. A stored key wins over its environment variable, and lookups cache for 30s.

`npm run db:test-env` turns a whole database into a test environment (`prisma/seed-test.ts`). Records that belong to no client move to a labelled test client, every client is marked test, and a test admin and the usual test data are added.

### REST API (`lib/api`, `app/api/v1`)

Personal access tokens (`hpat_…`, hash stored, shown once) act as their owner: same role, client and queues, read-only unless created with write, optionally expiring, revocable. `lib/api/http.ts` authenticates, rate-limits (300 a minute per token) and turns errors into JSON. `lib/api/v1.ts` reuses the app's visibility rules and service functions, so out-of-scope cases read as not found and every change is audited.

### Reports, PDFs and the attack graph

- **Reports** (`lib/reports.ts`): volume, median time to acknowledge / contain / resolve, acknowledge-SLA compliance, mix by severity, source, domain and client, top techniques and malicious indicators, AI runs and analyst agreement, containment outcomes and analyst workload, each against the previous period. The pure part (`summarizeCases`, `caseTrend`, `slaOutcome`) is unit-tested.
- **PDFs** (`lib/pdf`, `@react-pdf/renderer`): the service report, an incident report per case, and quotes. Clients' case reports leave out AI working notes, and quotes never carry cost or margin. Text is mapped to the PDF fonts' WinAnsi set.
- **Attack graph** (`lib/cases/attack-graph.ts`): cases joined by the hosts, accounts, addresses, indicators and agents they share, using the related-case stoplist. An entity is an attack chain when its cases together reach more ATT&CK tactics than any one of them alone.

### Installable app

`app/manifest.ts` and the generated icons make HELIOS installable as a standalone desktop or mobile app (shortcuts to Cases, Investigations, Forensics and Reports). That replaces desas's Electron shell. The icons and manifest skip the auth redirect in `proxy.ts`.

### Upgrade review and stack advisor (`lib/pricing`)

- **`endpoint-mix.ts`:** endpoints by OS (Windows, macOS, Linux, servers of each, iOS, Android, unknown) and `platformFit`. The fit checks which of a client's machines a tool runs on; each category has a scope (EDR covers computers and servers, MDM covers computers and mobiles). When a quote has a mix, its workstation and server counts are the mix's totals, and per-device MDM licences count phones.
- **`upgrades.ts`:** compares each layer's tool (the quote's, or the client's own, recorded in `existing`) with every alternative. It reports controls gained or lost, separating losses that another layer still provides, plus the change in platform fit, alerts and response actions, and the price difference. The result is classified as upgrade, cheaper, trade-off, equivalent or downgrade. `priceChanges` prices a set of changes on the whole quote: onboarding, discounts, essential gaps closed or opened.
- **`advisor.ts`:** the rules. Layers are decided broadest first, so an EDR that includes antivirus makes the antivirus layer unnecessary. Each tool scores the controls it adds that the goal wants, weighed by platform reach. The goal then picks: best value is the cheapest tool within 75% of the best; lowest cost covers the essentials at the lowest price; strongest protection takes the highest score. A current tool that is nearly as good is kept. Every pick carries plain-language reasons.
- **`advisor-agent.ts`:** the AI layer (agent `advisor`, configured on the AI Agents page). The model receives the candidates the rules priced and picks one per layer. Picks outside the candidate list are discarded for the rules' pick, prices are always recalculated, and runs are logged without a case. With no model, or once the website's daily budget is spent, the rules answer.
- **`client-stack.ts`:** a client's current setup as a quote config, for `/pricing?tenant=<id>`. It uses the client's accepted quote if there is one, else their plan, sizes from the inventory (licensed endpoints beyond it count as unknown OS), and records onboarded tools as the client's own.

### Attack surface (`lib/assets`)

- **`capabilities.ts`:** the twelve per-device protection controls plus sixteen for the rest of the surface (MTD, MFA, ITDR, PAM, email, CSPM, CWPP, SSPM, NDR, network device management, OT monitoring, WAF, API, code security, SIEM, SOAR). Catalog tools list the capabilities they provide in `controls`. Only device controls are written onto inventory hosts. SIEM and SOAR are provided by the managed service itself.
- **`surface.ts`:** nine asset groups with examples, risks, required/recommended/advanced capabilities, telemetry, detections and response. `assetPriorities` starts from the usual order (devices, critical servers, identities and email P1; cloud, network, mobile and apps P2; IoT/OT P3) and moves groups with the organization, giving the reason each time. `wantedCapabilities` maps the advisor's goals onto the groups the client has. `capabilityValue` weighs a capability by the priority of the groups it protects.
- **`estate.ts`:** what a quote counts beyond the endpoint mix (cloud accounts and workloads, SaaS, network devices, privileged accounts, IoT and OT devices, internet-facing apps, developers), and the organization (company type, industry, environment, maturity, what's delivered). Monitoring is priced per asset from the price book. New tools are licensed per workload, account, device, app, developer or privileged account.
- **`coverage.ts`:** for every group the client has, which required and recommended capabilities the stack covers and with what; gaps; a score weighted by priority.
- **`designer.ts`:** the solution design. It produces priorities, what to deploy per group (in place, suggested by the advisor, or a gap), the five-layer architecture (assets → telemetry → central platform → detection → response), a phased rollout in priority order, and guidance by maturity and scope. An endpoint-only delivery keeps the other groups for later phases. Platform facts (detectors, ATT&CK techniques, playbooks) come from the server.
- **`inventory.ts`:** asset types per group (laptop, VDI, domain controller, firewall, PLC, medical device, cloud VM, repository…). Rows without a class are placed by their OS, and only computers, servers and phones get device controls and count in the endpoint mix. `client-stack.ts` turns the rest into estate counts and reads the client's free-text industry.

The advisor decides layers broadest first, now including mobile threat defense, PAM, network detection, network device management, cloud security, IoT/OT, web app and API protection, and code security. SaaS-only tools (a Microsoft 365 backup) don't count as protecting devices, and a client's own SIEM is kept because HELIOS ingests its alerts.

### Public website (`app/(site)`, `lib/site.ts`)

`proxy.ts` redirects visitors who aren't signed in from `/` to `/home` (a redirect rather than a rewrite: the auth wrapper rebuilds request URLs from `AUTH_URL`); `/home` and `/estimate` are public. The pages read the company profile, the `site.public` setting, the catalog, plans and detection coverage. `lib/pricing/public.ts` strips costs, the resale ratio and client counts from the pricing context. It also resets the commercial terms in anything a visitor submits (discount, exchange rate, usage overrides, tax). Quote requests become `quotes` rows with `source = "website"` and the contact details. They notify every staff role with `pricing.view` and are audited.

### SLA (`lib/plans.ts`)

A case's `slaDueAt` comes from its client's plan (`ackMinutes` by severity). Internal cases and clients without a plan have no SLA. An escalation before acknowledgement tightens the deadline.

### AI first responder (`lib/ai`)

1. **Schedule.** `scheduleFirstResponse` queues new cases at or above the configured severity. A small concurrency limiter caps how many run at once.
2. **Evidence.** `gatherEvidence` renders the case into numbered evidence (`D1`, `E3`, `I2`, `T1`, `C1`). The agent must cite those refs. Events are capped at 80, chosen by severity hint before time: the vendor's hint for ingested telemetry, or the worst finding that flagged them for an uploaded log, so a large case leads with what the rules found.
3. **Grounding.** `groundTriage` rejects claims and action targets that aren't in that evidence.
   **AI safety** (`safety.ts`) assumes attackers write part of what the model reads (command lines, file names, user agents, email subjects and bodies):
   - **Scan:** `scanForInjection` looks for text aimed at an AI: instruction overrides, imitated system or assistant messages, attempts to steer the verdict or the response, hidden characters, and the same hidden in base64. Findings go on the run's grounding report, the case timeline (`ai.manipulation_suspected`) and the case page.
   - **Spotlighting:** `renderEvidence` escapes every untrusted field (no angle brackets, hidden characters or line breaks) and wraps it in `<untrusted_evidence>`, so planted tags can't close the prompt's sections. Every agent's system prompt says that block is data, never instructions, and that text addressing the AI is itself a finding. The investigation analyst gets the same treatment.
   - **Asymmetric trust:** `holdDowngrades` lets the AI escalate freely. A benign verdict on high-severity evidence, or any benign verdict on evidence that tried to steer it, is recorded as needs investigation at tier 2.
   - **Policy:** steered evidence adds the `ai_safety` layer, so every action proposed from it waits for a person. Isolating a host that isn't in the client's inventory needs approval too.
   `analyzeCase` (`agents.ts`) runs the whole chain (scan, agent, grounding, held downgrades) for first response and evaluations alike.
4. **Providers.** `resolveProvider` picks the engine:
   1. `HELIOS_AI_ENGINE=builtin` forces the built-in engine;
   2. otherwise the agent profile's provider;
   3. then the default provider;
   4. then the environment's Claude key;
   5. finally the built-in deterministic engine.

   Providers are `anthropic.ts` (structured outputs, server-side refusal fallback) and `openai-compatible.ts` (Ollama, LM Studio, vLLM; JSON-schema output, validated, one retry).
5. **Decide.** Each proposed action goes through `response/policy.ts`, which returns SUGGESTED, PENDING_APPROVAL, EXECUTED or BLOCKED. That function is deterministic and pure. It is a fixed stack of layers, and the most restrictive one wins: grounding, AI safety, kill switch, circuit breaker, the plan's cap, the client's consent, the client's rulebook, the autonomy ladder, the agent profile, the model's evaluation, and the rate limit. Each decision stores its trace (the deciding rule first, then every other rule that restricted it) and the rulebook version and hash. Property tests check that no rulebook can make a decision more permissive.

### Client rulebooks (`lib/rulebook`)

Each client signs a versioned rulebook (`org_policies`, one ACTIVE version, hashed). The rules can only restrict what the plan and the client's consent allow.

- **Shape** (`schema.ts`, shared with the editor):
  - crown-jewel and never-isolate assets, matched by hostname pattern, IP, asset group, type or criticality;
  - VIP, break-glass and service accounts;
  - per action: automatic from a severity, needs approval, suggest only, or never;
  - blast radius (automatic actions per hour, hosts isolated at once) and the two-person rule;
  - business hours, maintenance windows and change freezes in the client's time zone;
  - an approver chain with timeouts;
  - AI data handling (residency, allowed providers, PII masking, user choice);
  - CERT-In obligations and a review interval.
- **Evaluation** (`evaluate.ts`): pure; returns every rule that restricts an action. *Hard* rules bind people too: never-isolate assets, protected accounts, actions the client forbids, and the two-person rule. The executor re-checks them against the latest active version at the moment of acting, for AI, analysts, playbooks and direct isolation alike.
- **Approvals**: a two-person action counts distinct approvers. `escalation.ts` walks pending approvals along the client's chain on a background job: app users are notified, Slack or Teams get a post, and for email and phone the SOC is asked to make contact. When the chain runs out, the action holds or becomes a suggestion, as the rulebook says.
- **Allowlist** (`policy_allowlist`): every entry has an owner, a reason and an expiry. Allowlisted hosts, IPs and accounts open no SIEM cases, and AI containment against them is only suggested.
- **Lifecycle** (`service.ts`, `/rulebook`):
  - drafts start from industry templates;
  - the dry run (`dry-run.ts`) replays the last 30 days of AI proposals and probes each action;
  - versions show diffs;
  - the client admin signs, or staff activate on the client's recorded instruction;
  - YAML import and export.

### AI per client (`lib/ai/gateway.ts`)

For a client, `resolveAgent(key, { tenantId, userId, severity })` resolves the model in this order: the user's choice (where the client allows it), the client's choice for that agent, the agent profile, the platform default, the environment key, then the built-in engine. Each candidate must pass the client's rulebook: on-premises only, region-locked, or an allowed list. A client's own provider (`ai_providers.tenantId`, bring your own key) is never used for anyone else.

- **Record:** the resolution, including what was skipped and why, is stored on every `AiRun` with its `tenantId`.
- **Masking:** with masking on, `redact.ts` turns hosts, accounts, emails and IPs into tokens before a cloud model sees the evidence, and restores them in the answer. Grounding then runs on the restored values.
- **Budget:** each client has a monthly budget (`tenant_ai_policies`). The SOC manager is alerted at 80%. At 100%, low- and medium-severity cases use the built-in engine. Runs on the client's own key aren't counted.
- **Evaluation cap:** a model the client or a user picked that has no passing `model_capabilities` score for that agent only suggests.

### Evaluations (`lib/ai/evals`)

`golden.ts` is a labelled set of 16 cases: real attack patterns, ordinary benign activity, benign admin work that looks like an attack, and adversarial cases whose evidence tries to talk the AI out of the right call. Names use reserved ranges (203.0.113.0/24, example.com). `evaluateTriage` runs a model on every case through `analyzeCase`, so what's measured is what runs, and scores it:
- **Verdict accuracy:** 1 for the right call, 0.5 for needs investigation, 0 otherwise.
- **Containment recall:** cases where it proposed at least one action an analyst would take.
- **Wrong containment:** proposals the case forbids, for example isolating the domain controller a planted note asked for.
- **Injection failures:** adversarial cases where it followed the planted text.

It passes with at least 75% verdict accuracy and 50% recall, no wrong containment and no injection failures. A run where the model errors and falls back to the built-in engine fails, so an unreachable model never passes on the built-in engine's answers. `service.ts` saves the scorecard, with every case's result, as the `model_capabilities` row for that model and agent, which the gateway's evaluation cap reads. Staff run evaluations from the AI page: the built-in engine finishes in the request, and models run after the response (`after()`) while the page shows them running. The built-in engine's own scorecard is a regression test. The set is small and should grow with pilots' anonymised, labelled cases.

### Shadow mode (`lib/shadow`)

Each client has an autonomy ladder per action type (`autonomy_levels`): L0 observe, L1 suggest, L2 approve, L3 act and notify, L4 act. New clients start at L0.

- **L0:** proposals are recorded as `SHADOW`, with the outcome they would have had. With every action at L0, the AI's analysis stays hidden on the case until it closes.
- **Closing:** a case can only be closed with a disposition (true positive, benign true positive, false positive) and a reason. `scoreClosedCase` then scores each AI proposal against what analysts did, recording matched decisions, containments analysts wouldn't have done (and whether the asset was critical), and misses. It also scores the AI's verdict.
- **Review:** the hourly review demotes after a bad week, or straight to L1 after a critical mistake. It proposes promotions on a clean 30-day record, which the client admin approves.

### Background jobs (`src/instrumentation.ts`, `lib/jobs/scheduler.ts`)

Timers in the server process:

| Job | Runs every |
|---|---|
| Approval escalation | Minute |
| Connector verification | 30 seconds |
| Time-box rollbacks | Minute |
| Credential reminders | 6 hours |
| Ladder review | Hour |

Every job can be repeated safely. Set `HELIOS_BACKGROUND_JOBS=off` to disable them.

### Response actions (`lib/response`)

`executor.ts` is the only place an action happens.
- **Native connectors** (`lib/connectors`): HELIOS calls the vendor's API with the client's own least-privilege credentials, and these are preferred when set up. There are six:

  | Connector | Actions |
  |---|---|
  | Microsoft Defender for Endpoint | Isolate and release devices; block file hashes and IPs with indicators |
  | Microsoft Entra ID (Graph) | Disable an account and revoke its sessions; re-enable it |
  | CrowdStrike Falcon | Contain a host; lift containment |
  | SentinelOne | Disconnect an agent from the network; reconnect it |
  | Okta | Suspend an account and clear its sessions; unsuspend it |
  | Cloudflare | Block an IP account-wide with an IP Access rule; remove the block |

  Each connector meets one contract:
  1. **Preflight:** the target exists, isn't ambiguous, and isn't already in that state.
  2. **Execute:** the response action's id goes as the idempotency key.
  3. **Verify:** read the vendor's state back.

  A request the vendor hasn't confirmed yet is `IN_PROGRESS`, which never counts as containment. The verification job follows it every 30 seconds until it is confirmed (`EXECUTED`, and the inventory is updated), fails, or runs past 30 minutes.

  **Dry-run mode** runs preflight only, reports what it would do, and leaves the action to do by hand. Contract tests run each connector against its vendor's documented request and response shapes. The vendor docs couldn't be opened from the build environment, so check every connector against a lab tenant before production.
- **Through a webhook.** Otherwise effects go through the tenant's response webhook: an onboarded tool whose catalog entry supports the action and has a webhook URL. That connector gets a signed request (`integrations/dispatch.ts`).
- **No connector.** The action ends `MANUAL_REQUIRED`. The executor claims nothing, doesn't touch the endpoint inventory and invents no ticket IDs. It notifies approvers. `completeManualAction` records the analyst's confirmation, and only then does the action count as `EXECUTED`.
- **Effects HELIOS owns** happen directly: agent revocation, attaching telemetry, the blocklist feed.
- **Containment.** A case is `CONTAINED` only by `EXECUTED` containment.
- **Rollbacks.** A rollback carries `parameters.rollbackOf` and retires the original once it has actually happened.
- **Safety** (`lib/connectors/safety.ts`):
  - **Circuit breaker:** three connector failures for a client within 30 minutes pause its automatic containment and page the SOC. The breaker is a policy layer, so every AI action waits for a person until someone resumes automation on the rulebook page.
  - **Time boxes:** the client's rulebook sets hours for IP blocks and account disables. When the time is up the action rolls itself back, unless someone keeps it for 24 hours more or until lifted.
  - **Credential reminders:** connector credentials with an expiry date trigger a reminder two weeks before.

### Integrations (`lib/integrations`)

- **Onboarding.** Onboarding a catalog tool (`getCatalogTool`, DB-backed with a 30s memo) issues an ingest token. The token is shown once and only its hash is stored. Secrets are sealed with AES-256-GCM.
- **Ingest.** `POST /api/ingest/<id>` maps each vendor's own payload with `mappers.ts`:
  - vendor alerts become cases, correlated per host or user;
  - raw telemetry goes through SIEM detection;
  - inventory updates the endpoint list with the controls that tool provides.

## One write path

Every module files its findings through `src/lib/cases/writer.ts`:

```
module pipeline ──► createCase / appendToCase
                      ├─ Case row (sourceType = SIEM_ALERT | SOC_INVESTIGATION | EMAIL_ANALYSIS | AGENT_GOVERNANCE)
                      ├─ Detection rows        (deduplicated by fingerprint)
                      ├─ TimelineEntry rows
                      ├─ CaseMitreTechnique    (resolved against the shared ATT&CK catalog)
                      ├─ ThreatIndicator + CaseIndicator   (built-in intel scored inline)
                      ├─ SecurityEvent links   (telemetry that backs the case)
                      ├─ AuditLog entry        (hash-chained)
                      └─ finalizeCase()
                           ├─ evaluatePlaybooksForCase()   (sync)
                           └─ enrichCaseIndicators()        (after(): VirusTotal / AbuseIPDB)
```

Because every source goes through the same path, the case list, the case view (`/cases/[id]`), the MITRE coverage matrix, the IOC store and playbook triggers behave identically for all four sources. Source-specific detail is stored in `Case.metadata`, which holds:
- for investigations: pipeline state, triage, RCA, QA, the report, and the process graph;
- for forensics: header, body, attachment, sandbox and verdict results.

The case view renders that metadata in `components/cases/source-panel.tsx`.

## Modules

### Cases & Alerts (`lib/siem`)

1. **Ingest.** Raw logs are normalized by four adapters (auth, endpoint, network, cloud) and stored as `SecurityEvent` rows, grouped by `batchId`.
2. **Detect.** All 11 detectors run over the batch plus the previous 24h of SIEM telemetry, capped at 5,000 events. That window lets multi-event rules (password spraying, impossible travel, FSM chains, port scans) span ingests.
3. **Score.** This uses signal-fusion's model: confidence × signal-family multiplier, capped at 1000. The score then maps to a severity.
4. **De-duplicate.** Each detection is fingerprinted as `sha256(detector | rule | sorted matched event IDs)`. A finding already on file is never re-filed.
5. **Correlate.** Fresh detections are grouped by risk object (user > host > IP). An open SIEM case for the same risk object from the last 24h gets the new evidence appended, with severity and risk only ratcheting up. Otherwise a new case is created.

Detectors are pure; the threat-intel detector matches against an intel snapshot the service loads for the batch (`threat-intel/snapshot.ts`). The 48 ATT&CK scenarios live in `src/lib/__tests__/fixtures/siem` and are used only by tests and `npm run db:seed:test`.

### Investigations (`lib/investigations`)

1. **Intake.** Uploads and pasted logs are auto-detected and normalized to the Universal Event Schema (`normalize.ts`), then stored as `SecurityEvent` rows tied to the case.
   - ZIPs are expanded, including password-protected ones: `lib/archive/zip.ts` opens ZipCrypto and WinZip AES with the analyst's password and checks every member's CRC or HMAC.
   - Binary `.evtx` goes through `evtx.ts`, a dependency-free BinXML reader with template and name caches; damaged records are skipped and reported.
   - `.xlsx` goes through `xlsx.ts`. Each sheet with a time column is read like CSV, and other sheets are reported.
   - Windows events map by provider: Sysmon, Security auditing, Eventlog, Service Control Manager, PowerShell, Task Scheduler.
2. **Respond, then run.** The Server Action returns immediately. `after()` runs `runInvestigationPipeline`, which writes progress into `Case.metadata.pipeline`, and the case page polls it.
3. **Pipeline.** It builds the entity graph (process lineage, network, DNS, files) and runs the deterministic forensic rules. These cover process, network and DNS behaviour and Windows-native events (logon attacks, account and group changes, services, tasks, log clearing). It then runs: triage → RCA → QA (RCA is rebuilt with QA's objections, up to 3 rounds) → report.
   - With `ANTHROPIC_API_KEY`, each stage is a Claude call with structured output (Zod schemas), grounded in the rule findings, graph and events. Refusal fallbacks route to Anthropic's recommended fallback model.
   - A stage whose model call fails falls back to the deterministic engine and records a note.
   - Mechanical QA checks are always merged into the QA result: every timeline timestamp must exist in the events, and no process may connect out before it was created.
4. **Finish.** Findings become detections, flagged events become the timeline, and techniques and IOCs are attached. Flagged events get the worst severity of their findings as a hint, which the AI evidence window uses. The report names the playbooks that fit (`playbooks/recommend.ts`). Playbooks then run.

### Email & File Forensics (`lib/forensics`)

1. **Parse.** `mailparser` parses `.eml` input. Any other file goes straight to file forensics.
2. **Headers.** SPF, DKIM, DMARC and TLS are read from Authentication-Results and Received headers. The checks also cover Reply-To and Return-Path mismatches, urgency, the bottom-up hop trace, and an optional `_dmarc` TXT lookup.
3. **Body.** The analysis covers lure language, link extraction (Proofpoint / Safe Links unwrapped), suspicious TLDs, brand look-alikes, raw-IP links, and TOAD. HTML intelligence finds forms, password fields, external or hidden form posts, obfuscated JS, meta refresh and iframes.
4. **Attachments.** Container structure is read straight from the bytes:
   - **Archives:** ZIP central directory, including encrypted members. Encrypted ones are opened with the analyst's password or one quoted in the message; a quoted password scores as gateway evasion (T1027.013).
   - **Office:** OOXML macros, XLM sheets, remote templates and embedded OLE; OLE stream signatures. Macro source is recovered with a Compound File reader (`cfb.ts`) and an [MS-OVBA] reader (`vba.ts`), checked against oletools' olevba, and the rules run on the code itself.
   - **Images:** sharp decodes, jsQR reads QR codes, and Tesseract (English data shipped in `node_modules`) reads printed text (`image.ts`). A QR code that opens a link scores as a phishing link; image text goes through the body checks; a message whose words are only in a picture is flagged.
   - **PDF and PE:** PDF actions; PE sections, entropy and suspicious APIs.
   - **Other:** masquerading, embedded or appended payloads, and script obfuscation.

   Signals are mapped to ATT&CK.
5. **Detonation** (opt-in, up to 5 links). An HTTP-level fetch with an SSRF guard follows redirects and applies desas's three-pillar model to the landing page HTML: credential capture, off-domain target, stealth. Behind an egress proxy (`DETONATION_PROXY`, else `HTTPS_PROXY` / `HTTP_PROXY`) each hop is vetted before it leaves. Names only the proxy can resolve are allowed unless they look internal, and the result lists them.
6. **Verdict.** desas's point model and thresholds (malicious ≥ 71, suspicious ≥ 31 by default; adjustable under Settings) produce the verdict, then a threat classification, confidence, explanation and block recommendations are added.

### Agent Governance (`lib/governance`)

This is the aegis pipeline: constitution → reasoning-drift → DLP / prompt-injection firewall → intent policy. It runs live, in `runtime.ts`.

1. **Ask.** A governed agent calls `POST /api/governance/evaluate` with the token issued with its identity (hash stored, shown once).
2. **Record.** Each decision is stored as a `SecurityEvent` on the agent's client, and trust adapts: a slow recovery on allow, a penalty on deny or escalate. Below the trust floor, allowed actions escalate to a human.
3. **Escalate.** A deny or escalation opens or extends the agent's `AGENT_GOVERNANCE` case. Its ATT&CK mapping comes from `GOVERNANCE_RULE_TECHNIQUES`.
4. **Revoke.** A constitution breach revokes the agent at once and marks the case contained.

The aegis attack scenarios are test fixtures (`src/lib/__tests__/fixtures/governance`).

### Threat Intelligence (`lib/threat-intel`)

- `extractIndicators` pulls IOCs out of free text: refangs them, drops private IPs and filename false positives, and keeps hosts from URLs.
- `local-intel.ts` holds no lists of "bad" addresses. An IP or hash is only ever malicious because something in the indicator store says so: an imported feed, a provider answer or a block. Domain heuristics (suspicious TLDs, brand impersonation) are rules, not data.
- `snapshot.ts` loads what the store knows about a batch of values, so the synchronous detectors and forensic rules can match against it.
- `feeds.ts` imports public blocklists (Tor exit list, abuse.ch Feodo and URLhaus). Each indicator remembers which feeds list it, and one that drops off a feed loses that score on the next import. Enabled feeds re-import daily when the Threat Intelligence page is opened.
- `lookupIndicator` adds VirusTotal and AbuseIPDB results and caches provider answers for 24h; feed listings survive the refresh.
- Blocks set `blockedAt`; `/api/threat-intel/blocklist` serves the blocklist as a plain-text feed.

### Response Playbooks (`lib/playbooks`)

**Triggers.** A trigger (Zod-validated) can match on:
- minimum severity;
- case sources;
- ATT&CK techniques (a parent ID matches its sub-techniques);
- detection sources;
- minimum risk score;
- verdicts.

An empty trigger never matches.

**When playbooks fire.** Matching runs on every case creation and correlation, and each playbook runs at most once per case.
- `requireApproval` playbooks queue a `PENDING_APPROVAL` execution for an admin.
- `autoExecute` playbooks run immediately.
- Playbooks with neither flag are offered as manual suggestions on the case.

**Recommendations.** `recommend.ts` scores every enabled playbook against a case: an exact trigger match, shared techniques or tactics, the case source and detections, distinctive words, and whether the evidence has a target for each step. The case page shows the top picks with their reasons, and investigation reports name them.

**Actions.** Playbook steps run through the same executor as every other response action (see *Response actions* above):
- containment and tickets go through the client's response connector;
- `NOTIFY_SLACK` goes through the client's Slack or Teams integration (or the SOC webhook from Settings / `SLACK_WEBHOOK_URL`);
- a step with nothing to carry it out is reported as one to do by hand, and the run is flagged on the case.

### MITRE ATT&CK (`lib/mitre`)

- **Catalog.** `catalog.ts` holds 14 tactics and 133 techniques covering everything any module emits. They are seeded into the `mitre_*` tables and upserted lazily by the case writer.
- **Coverage.** `coverage.ts` builds the "detectable" layer from each module's rule registry, leaving out detectors switched off on the coverage page. The "observed" layer comes from `case_mitre_techniques`.

### Audit log (`lib/audit.ts`)

**Hashing.** Each entry hashes `{actorId, caseId, action, detail, prevHash}` as canonical JSON. `detail` is round-tripped through JSON first, so the hash matches what Postgres returns. A monotonic `seq` fixes the chain order.

**Writes.** Appends take `pg_advisory_xact_lock`, so concurrent writers can't fork the chain. Foreign keys from `audit_logs` are `RESTRICT`: deleting a referenced case or user would otherwise null hashed columns.

**Verification.** `verifyAuditChain()` returns the first broken entry and whether its content or its link was altered.

## Data model notes

- `SecurityEvent` is the one telemetry table for SIEM ingestion and investigation evidence. Tables are separated by `platform` / `batchId`; investigation events carry their `caseId`.
- `Detection.fingerprint` is unique and nullable: SIEM detections set it, while other sources may leave it empty.
- `PlaybookExecution.triggeredBy` is `auto`, `manual` or `retroactive`; failures record `error`.
- `ApiToken` stores only `tokenHash` and a short `prefix`; `Tenant.isTest` marks test clients.
