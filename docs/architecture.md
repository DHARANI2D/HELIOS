# HELIOS architecture

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

The 48 attack scenarios (`lib/siem/scenarios`) are replayed through exactly this path.

### Investigations (`lib/investigations`)

1. **Intake.** Uploads (ZIPs expanded) and pasted logs are auto-detected and normalized to the Universal Event Schema (`normalize.ts`). They are stored as `SecurityEvent` rows tied to the case.
2. **Respond, then run.** The Server Action returns immediately. `after()` runs `runInvestigationPipeline`, which writes progress into `Case.metadata.pipeline`, and the case page polls it.
3. **Pipeline.** It builds the entity graph (process lineage, network, DNS, files) and runs 20 deterministic forensic rules. It then runs: triage → RCA → QA (RCA is rebuilt with QA's objections, up to 3 rounds) → report.
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

This is the aegis pipeline: constitution → reasoning-drift → DLP / prompt-injection firewall → intent policy. Scenario runs create agents and are filed as cases mapped to ATT&CK. Critical violations auto-revoke the agent. High-severity ones that weren't auto-revoked trigger the approval-gated *Revoke misbehaving AI agent* playbook.

### Threat Intelligence (`lib/threat-intel`)

- `extractIndicators` pulls IOCs out of free text: refangs them, drops private IPs and filename false positives, and keeps hosts from URLs.
- `recordIndicator` stores built-in intel only, so it is safe on hot paths.
- `lookupIndicator` adds VirusTotal and AbuseIPDB results and caches provider answers for 24h. Local-only results stay stale so a later lookup retries.
- The `BLOCK_IP` playbook action and manual blocking set `blockedAt`. `/api/threat-intel/blocklist` serves the blocklist as a plain-text feed.

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

**Actions with a real effect inside HELIOS:**
- `BLOCK_IP`: adds the case's IPs to the blocklist.
- `REVOKE_AGENT` / `RESTORE_AGENT`: changes the AI agent's status.
- `COLLECT_LOGS`: attaches related telemetry to the case.
- `NOTIFY_SLACK`: posts to `SLACK_WEBHOOK_URL` when it is set.

**Simulated actions.** There's no EDR or ticketing integration, so `ISOLATE_HOST`, `KILL_PROCESS` and `CREATE_TICKET` are recorded as simulated, and the UI labels them that way.

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
