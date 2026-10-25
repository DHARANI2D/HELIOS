# Porting notes

What changed relative to each legacy app in `legacy/components/`. It records bugs fixed on the way, deliberate behaviour changes, and anything not carried over.

## signal-fusion → Cases & Alerts

**Ported:**
- the 4 adapters;
- all 11 detectors;
- the enterprise risk model;
- the playbook engine (generalized to every case source);
- threat-intel services (merged into the shared module);
- all 48 attack scenarios, now as test fixtures (`src/lib/__tests__/fixtures/siem`), not an in-app simulator.

**Fixed:**
- **Duplicate alerts.** signal-fusion re-ran every detector over the *entire* event table on each ingest and filed one alert per detection, so findings were re-filed every run. HELIOS uses a 24h window, fingerprint de-duplication, and risk-object correlation into cases.
- **Dropped scenario IPs.** `NetworkAdapter` only read `src_ip` / `dst_ip`, but the attack scenarios use `source_ip` / `dest_ip`, so their network IPs were silently dropped. Both spellings are accepted now.
- **Unenforced FSM window.** The FSM chain detector declared `maxChainTimeGapMs` but never enforced it. It now resets after 30 minutes.
- **Scheduler false positives.** The persistence rule matched the substring `"at "`, which fires on `cat`, `format`, and so on. It now requires the `at HH:MM` command shape.
- **Event-log rule tightened.** The defense-evasion rule `wevtutil` + `cl` substring now requires the `cl` / `clear-log` verb.
- **Threat intel on destinations.** The threat-intel detector only checked source IPs, so outbound beacons to known C2 were missed. It now also checks destinations. It matches against the shared indicator store (imported feeds, provider answers, blocks); signal-fusion's hardcoded "known bad" IPs were dropped as invented data.
- **Biased shuffle.** Random scenario selection used `sort(() => 0.5 - Math.random())`, which is biased. It is now Fisher–Yates.
- **Stale timestamps.** Scenario timestamps were computed at module load. They are now computed per run.
- **Impossible travel distances.** Impossible travel assumed a flat 1000 km between any two locations. It now uses country centroids, with 1000 km as the fallback.

**Changed:**
- **No hardcoded intel:** the built-in blocklist and Tor range are gone. The Tor Project exit list and the abuse.ch feeds are importable threat feeds instead.
- **OSINT rule:** `github.com` was removed from the OSINT list because it's routine developer traffic.

**Rebuilt on the unified data:**
- **Attack graph.** signal-fusion wrote a node and an edge row per alert on every build and called any two alerts on one user a chain. The Attack Graph page computes the graph from cases on demand (hosts, accounts, addresses, indicators and AI agents they share, generic accounts and noisy indicators left out). An entity counts as a chain only when its cases together reach more ATT&CK tactics than any one of them alone.
- **Analytics and metrics → Reports.** signal-fusion's MTTD was `createdAt − startTime` of the alert itself and its MTTR was `updatedAt − createdAt` of anything marked resolved. Reports uses medians of acknowledge, contain and resolve times, acknowledge-SLA compliance against each client's plan, and compares with the previous period. There is a PDF version and a client-facing view.
- **Settings UI.** signal-fusion's settings were an in-memory object that nothing read (`anomalySensitivity`, `emailAlerts`, …) plus a "reset everything" button. HELIOS's Settings page stores real configuration in the database: environment, company profile, provider keys (sealed), forensics thresholds and trusted domains. Detector on/off lives on the ATT&CK coverage page.
- **Express API → REST API v1.** The Express server had no authentication. `/api/v1` uses personal access tokens that act as their owner, read-only unless created with write, with the app's visibility rules and audit trail.

**Not ported:** the in-app attack simulation and "reset all data" endpoints (the scenarios are test fixtures).

## asip → Investigations

**Ported:**
- the normalizer and the Sysmon, CrowdStrike, Wazuh, Google SecOps, Splunk and generic parsers;
- the entity graph;
- the triage / RCA / QA / report agents and the QA loop (≤ 3 rounds).

**Changed:**
- **Plain code instead of LangGraph.** The orchestration is plain TypeScript; the graph is a fixed loop.
- **Claude via the official SDK.** Agents call Claude through the official SDK with structured outputs, replacing hand-rolled `urllib` calls and string-stripped JSON.
- **No canned mock.** asip's no-key mode returned one canned story ("invoice.docx → powershell → 185.220.101.5") for *every* input. HELIOS replaces it with a deterministic engine: 20 forensic rules plus an evidence-derived triage, RCA, QA and report.
- **Grounded agents.** The rule findings now ground the agents.
- **Mechanical QA.** QA always includes mechanical checks: every timestamp exists, and there is no connection before process creation.
- **Per-stage fallback.** A failed model call degrades only that stage to the deterministic engine instead of failing the investigation.
- **ZIP intake.** ZIP bundles are expanded one level, with a per-member size cap against zip bombs. Encrypted or unknown binary members are reported back rather than skipped.
- **EVTX without python-evtx.** `.evtx` files are read by a TypeScript BinXML parser (`evtx.ts`). It was checked record-for-record against python-evtx on Security, System, Application and Sysmon logs, and agreed on every record python-evtx read. It also recovers records in chunks a stale ("dirty") file header doesn't count, which python-evtx misses. Damaged records are skipped and reported.
- **Beyond Sysmon.** Windows Security, Eventlog, Service Control Manager, PowerShell and Task Scheduler events map to UES types. New rules cover password guessing and spraying (plus a success afterwards), account creation, privileged group changes, RDP from the internet, suspicious service installs, scheduled tasks and log clearing from the native events.
- **XLSX intake.** Excel workbooks are read directly (`xlsx.ts`): shared and inline strings, date-formatted cells as ISO times, booleans. Each sheet with a time column is investigated like CSV.

- **Encrypted archives.** asip prompted for archive passwords. Investigations take an archive password, and `lib/archive/zip.ts` opens ZipCrypto and WinZip AES (128-256 bit). A wrong password is detected by CRC or HMAC rather than producing garbage. Tested on archives made by Info-ZIP and pyzipper.
- **Playbook RAG → playbook recommendations.** asip embedded runbook text and retrieved passages by vector similarity. `playbooks/recommend.ts` scores the playbooks actually configured in HELIOS against the case (trigger match, shared techniques or tactics, source, detections, words, whether the evidence has a target for each step) and states its reasons. The investigation report names the ones that fit, and the model is told never to name one that isn't listed.

**Not ported:**
- **asip's OpenAI and Ollama clients.** Local models are supported platform-wide instead, through the OpenAI-compatible provider.

**Replaced:**
- **Qdrant incident memory → related-case memory.** asip embedded past incidents into Qdrant and retrieved "similar" ones by vector distance, which analysts couldn't audit. HELIOS links prior cases that share concrete evidence (`src/lib/cases/related.ts`): IOCs (weighted up when malicious), hosts and accounts, the same AI agent, with ATT&CK overlap only reinforcing an evidence match. Generic accounts (`SYSTEM`, `root`, …) and indicators seen in more than 50 cases are ignored. Every match lists its reasons; the RCA stage (Claude or deterministic) cites the overlap as context, not evidence, and the case page shows a *Related cases* card.

## desas → Email & File Forensics

**Ported:**
- header, body and HTML intelligence;
- attachment forensics;
- the 3-pillar exfiltration model;
- the scoring rules and thresholds;
- threat classification and verdict explanation.

**Changed:**
- **No Python native stack.** olefile, oletools, pefile and pdfminer are replaced by reading container structures directly from the bytes:
  - the ZIP central directory, which also lists encrypted members;
  - OOXML parts;
  - OLE stream names;
  - PDF tags;
  - the PE header and section table.
- **Macro source is recovered.** A Compound File reader and an [MS-OVBA] reader (dir stream, module offsets, decompression) extract the VBA code from .doc/.xls and from vbaProject.bin in OOXML. The extracted code matches oletools' olevba byte for byte on a Word-saved project. The rules run on the code; the old keyword scan of the compressed container is only a fallback. (Legacy .ppt keeps its project inside a PowerPoint record stream and isn't covered.)
- **Polyglot check tightened.** The legacy check matched 2-byte signatures such as `MZ` and `BM` anywhere in a file, which flags almost every binary. It now looks for an embedded DOS stub, payloads appended after an image EOF, and executables masquerading under a document extension.
- **New checks:** remote template injection, macros inside non-macro extensions, disk-image attachments, and raw-IP links.
- **HTTP-level sandbox.** The Selenium browser sandbox is replaced by HTTP-level detonation with an SSRF guard: no JavaScript execution, no screenshots, no form interaction. Pillars are judged from the landing page's HTML.

- **`.msg` (Outlook) parsing** uses `@kenjiuno/msgreader` instead of `extract-msg`. Transport headers are used when the message carries them; otherwise sender, recipients, sent time and bodies come from the MAPI properties. Messages attached inside a message (`.msg` embedded items or `message/rfc822` parts) are analyzed one level deep: their attachments, links and reasons count towards the outer verdict.
- **MxToolbox** runs only with a key (Settings, or `MXTOOLBOX_API_KEY`). It feeds a separate *Sender infrastructure* score component (+5 per failed check) instead of being folded into header analysis.
- **Sender IP reputation** is looked up through the shared threat-intel providers when they are configured (+20 above 0.5, +10 above 0.1).

- **OCR and QR codes.** desas OCR'd images with pytesseract. HELIOS uses Tesseract (WASM, English data shipped in `node_modules`, so nothing is downloaded at run time), plus jsQR for QR codes, which desas didn't read. A QR link scores like a phishing link and becomes a detonation candidate.
- **PDF reports.** desas's report export is replaced by PDF incident reports for every case (investigation and forensics results included), service reports and quotes.
- **Electron shell → installable web app.** A web app manifest and icons let HELIOS install as a standalone desktop or mobile app from Chrome, Edge or Safari, with no second codebase to keep patched.
- **Detonation behind a proxy.** Detonation follows `DETONATION_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY`, vetting each hop's host before it leaves (desas's Selenium sandbox used the system proxy without checks).

## aegis → Agent Governance

This was ported in an earlier change. Since then:
- **Live gate instead of scenarios.** aegis's sidecar is now a real endpoint, `POST /api/governance/evaluate`, authenticated with a per-agent token. Its five attack scenarios became test fixtures.
- **Shared case writer.** Decisions go through the shared case writer, so they get ATT&CK mappings (DLP → T1567, constitution breaches → T1078 / T1485 / T1562 / T1552), playbooks and the shared audit path.
- **Breaches.** A constitution breach revokes the agent.
- **Action authentication.** All governance Server Actions authenticate; global purge is admin-only.

## Cross-cutting fixes found along the way

- **Audit chain fork.** Two concurrent writers could read the same tail and fork the chain, and `createdAt` ties made the verification order ambiguous. Fixed with an advisory lock plus a `seq` column; existing rows are backfilled in `createdAt` order.
- **Audit hash mismatches.** Audit `detail` was hashed before JSON round-tripping, so any entry containing a `Date` or an `undefined` field failed verification.
- **Audit rows rewritten on delete.** `audit_logs` foreign keys were `ON DELETE SET NULL`: deleting a case or user rewrote hashed audit rows and broke the chain. They are now `RESTRICT`.
- **Seed script.** `npm run db:seed` ran `tsx` directly, so `.env` was never loaded and the README's setup flow failed. It now goes through `prisma db seed`.
- **Server Action auth.** Governance Server Actions had no authentication check.
