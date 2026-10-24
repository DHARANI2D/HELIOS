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

### SLA (`lib/plans.ts`)

A case's `slaDueAt` comes from its client's plan (`ackMinutes` by severity). Internal cases and clients without a plan have no SLA. An escalation before acknowledgement tightens the deadline.

### AI first responder (`lib/ai`)

1. **Schedule.** `scheduleFirstResponse` queues new cases at or above the configured severity. A small concurrency limiter caps how many run at once.
2. **Evidence.** `gatherEvidence` renders the case into numbered evidence (`D1`, `E3`, `I2`, `T1`, `C1`). The agent must cite those refs. Events are capped at 80, chosen by severity hint before time: the vendor's hint for ingested telemetry, or the worst finding that flagged them for an uploaded log, so a large case leads with what the rules found.
3. **Grounding.** `groundTriage` rejects claims and action targets that aren't in that evidence.
4. **Providers.** `resolveProvider` picks the engine:
   1. `HELIOS_AI_ENGINE=builtin` forces the built-in engine;
   2. otherwise the agent profile's provider;
   3. then the default provider;
   4. then the environment's Claude key;
   5. finally the built-in deterministic engine.

   Providers are `anthropic.ts` (structured outputs, server-side refusal fallback) and `openai-compatible.ts` (Ollama, LM Studio, vLLM; JSON-schema output, validated, one retry).
5. **Decide.** Each proposed action goes through `response/policy.ts`, which returns SUGGESTED, PENDING_APPROVAL, EXECUTED or BLOCKED. That function is deterministic and pure.

### Response actions (`lib/response`)

`executor.ts` is the only place an action happens.
- **Through a connector.** Effects on client systems go through the tenant's response connector: an onboarded tool whose catalog entry supports the action and has a webhook URL. That connector gets a signed request (`integrations/dispatch.ts`).
- **No connector.** The action ends `MANUAL_REQUIRED`. The executor claims nothing, doesn't touch the endpoint inventory and invents no ticket IDs. It notifies approvers. `completeManualAction` records the analyst's confirmation, and only then does the action count as `EXECUTED`.
- **Effects HELIOS owns** happen directly: agent revocation, attaching telemetry, the blocklist feed.
- **Containment.** A case is `CONTAINED` only by `EXECUTED` containment.
- **Rollbacks.** A rollback carries `parameters.rollbackOf` and retires the original once it has actually happened.

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
   - ZIPs are expanded.
   - Binary `.evtx` goes through `evtx.ts`, a dependency-free BinXML reader with template and name caches; damaged records are skipped and reported.
   - `.xlsx` goes through `xlsx.ts`. Each sheet with a time column is read like CSV, and other sheets are reported.
   - Windows events map by provider: Sysmon, Security auditing, Eventlog, Service Control Manager, PowerShell, Task Scheduler.
2. **Respond, then run.** The Server Action returns immediately. `after()` runs `runInvestigationPipeline`, which writes progress into `Case.metadata.pipeline`, and the case page polls it.
3. **Pipeline.** It builds the entity graph (process lineage, network, DNS, files) and runs the deterministic forensic rules. These cover process, network and DNS behaviour and Windows-native events (logon attacks, account and group changes, services, tasks, log clearing). It then runs: triage → RCA → QA (RCA is rebuilt with QA's objections, up to 3 rounds) → report.
   - With `ANTHROPIC_API_KEY`, each stage is a Claude call with structured output (Zod schemas), grounded in the rule findings, graph and events. Refusal fallbacks route to Anthropic's recommended fallback model.
   - A stage whose model call fails falls back to the deterministic engine and records a note.
   - Mechanical QA checks are always merged into the QA result: every timeline timestamp must exist in the events, and no process may connect out before it was created.
4. **Finish.** Findings become detections, flagged events become the timeline, and techniques and IOCs are attached. Playbooks then run.

### Email & File Forensics (`lib/forensics`)

1. **Parse.** `mailparser` parses `.eml` input. Any other file goes straight to file forensics.
2. **Headers.** SPF, DKIM, DMARC and TLS are read from Authentication-Results and Received headers. The checks also cover Reply-To and Return-Path mismatches, urgency, the bottom-up hop trace, and an optional `_dmarc` TXT lookup.
3. **Body.** The analysis covers lure language, link extraction (Proofpoint / Safe Links unwrapped), suspicious TLDs, brand look-alikes, raw-IP links, and TOAD. HTML intelligence finds forms, password fields, external or hidden form posts, obfuscated JS, meta refresh and iframes.
4. **Attachments.** Container structure is read straight from the bytes:
   - **Archives:** ZIP central directory, including encrypted members.
   - **Office:** OOXML macros, XLM sheets, remote templates and embedded OLE; OLE stream signatures.
   - **PDF and PE:** PDF actions; PE sections, entropy and suspicious APIs.
   - **Other:** masquerading, embedded or appended payloads, and script obfuscation.

   Signals are mapped to ATT&CK.
5. **Detonation** (opt-in, up to 5 links). An HTTP-level fetch with an SSRF guard follows redirects and applies desas's three-pillar model to the landing page HTML: credential capture, off-domain target, stealth.
6. **Verdict.** desas's point model and thresholds (malicious ≥ 71, suspicious ≥ 31) produce the verdict, then a threat classification, confidence, explanation and block recommendations are added.

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

**Actions.** Playbook steps run through the same executor as every other response action (see *Response actions* above):
- containment and tickets go through the client's response connector;
- `NOTIFY_SLACK` goes through the client's Slack or Teams integration (or `SLACK_WEBHOOK_URL`);
- a step with nothing to carry it out is reported as one to do by hand, and the run is flagged on the case.

### MITRE ATT&CK (`lib/mitre`)

- **Catalog.** `catalog.ts` holds 14 tactics and 131 techniques covering everything any module emits. They are seeded into the `mitre_*` tables and upserted lazily by the case writer.
- **Coverage.** `coverage.ts` builds the "detectable" layer from each module's rule registry. The "observed" layer comes from `case_mitre_techniques`.

### Audit log (`lib/audit.ts`)

**Hashing.** Each entry hashes `{actorId, caseId, action, detail, prevHash}` as canonical JSON. `detail` is round-tripped through JSON first, so the hash matches what Postgres returns. A monotonic `seq` fixes the chain order.

**Writes.** Appends take `pg_advisory_xact_lock`, so concurrent writers can't fork the chain. Foreign keys from `audit_logs` are `RESTRICT`: deleting a referenced case or user would otherwise null hashed columns.

**Verification.** `verifyAuditChain()` returns the first broken entry and whether its content or its link was altered.

## Data model notes

- `SecurityEvent` is the one telemetry table for SIEM ingestion and investigation evidence. Tables are separated by `platform` / `batchId`; investigation events carry their `caseId`.
- `Detection.fingerprint` is unique and nullable: SIEM detections set it, while other sources may leave it empty.
- `PlaybookExecution.triggeredBy` is `auto`, `manual` or `retroactive`; failures record `error`.
