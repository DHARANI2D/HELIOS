# Porting notes

What changed relative to each legacy app in `legacy/components/`. It records bugs fixed on the way, deliberate behaviour changes, and anything not carried over.

## signal-fusion → Cases & Alerts

**Ported:**
- the 4 adapters;
- all 11 detectors;
- the enterprise risk model;
- the playbook engine (generalized to every case source);
- threat-intel services (merged into the shared module);
- all 48 attack scenarios.

**Fixed:**
- **Duplicate alerts.** signal-fusion re-ran every detector over the *entire* event table on each ingest and filed one alert per detection, so findings were re-filed every run. HELIOS uses a 24h window, fingerprint de-duplication, and risk-object correlation into cases.
- **Dropped scenario IPs.** `NetworkAdapter` only read `src_ip` / `dst_ip`, but the attack scenarios use `source_ip` / `dest_ip`, so their network IPs were silently dropped. Both spellings are accepted now.
- **Unenforced FSM window.** The FSM chain detector declared `maxChainTimeGapMs` but never enforced it. It now resets after 30 minutes.
- **Scheduler false positives.** The persistence rule matched the substring `"at "`, which fires on `cat`, `format`, and so on. It now requires the `at HH:MM` command shape.
- **Event-log rule tightened.** The defense-evasion rule `wevtutil` + `cl` substring now requires the `cl` / `clear-log` verb.
- **Threat intel on destinations.** The threat-intel detector only checked source IPs, so outbound beacons to known C2 were missed. It now also checks destinations and uses the shared built-in intel, which includes the Tor exit range.
- **Biased shuffle.** Random scenario selection used `sort(() => 0.5 - Math.random())`, which is biased. It is now Fisher–Yates.
- **Stale timestamps.** Scenario timestamps were computed at module load. They are now computed per run.
- **Impossible travel distances.** Impossible travel assumed a flat 1000 km between any two locations. It now uses country centroids, with 1000 km as the fallback.

**Changed:**
- **OSINT rule:** `github.com` was removed from the OSINT list because it's routine developer traffic.

**Not ported:**
- the attack-graph, analytics and metrics pages;
- the settings UI;
- the standalone Express API.

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
- **ZIP intake.** ZIP bundles are expanded one level, and encrypted or binary members are reported back rather than skipped.

**Not ported:**
- **Binary EVTX parsing** (needed python-evtx); export Sysmon as XML or JSON instead.
- **XLSX intake.**
- **Encrypted-archive password prompts.**
- **The OpenAI and Ollama providers.** Claude is the supported model provider.
- **Qdrant incident memory and playbook RAG.** Related context comes from the shared case store instead.

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
- **Macro source is keyword-scanned.** It isn't decompressed (MS-OVBA), and the reasons say so.
- **Polyglot check tightened.** The legacy check matched 2-byte signatures such as `MZ` and `BM` anywhere in a file, which flags almost every binary. It now looks for an embedded DOS stub, payloads appended after an image EOF, and executables masquerading under a document extension.
- **New checks:** remote template injection, macros inside non-macro extensions, disk-image attachments, and raw-IP links.
- **HTTP-level sandbox.** The Selenium browser sandbox is replaced by HTTP-level detonation with an SSRF guard: no JavaScript execution, no screenshots, no form interaction. Pillars are judged from the landing page's HTML.

**Not ported:**
- `.msg` (Outlook) parsing;
- OCR of image attachments;
- MxToolbox lookups;
- PDF report generation;
- the Electron desktop shell.

## aegis → Agent Governance

This was ported in an earlier change. In this pass:
- **Shared case writer.** Scenario runs now go through it, so they get ATT&CK mappings (data exfiltration → T1567, etc.), indicators, playbooks and the shared audit path.
- **Action authentication.** All governance Server Actions authenticate; global purge is admin-only.

## Cross-cutting fixes found along the way

- **Audit chain fork.** Two concurrent writers could read the same tail and fork the chain, and `createdAt` ties made the verification order ambiguous. Fixed with an advisory lock plus a `seq` column; existing rows are backfilled in `createdAt` order.
- **Audit hash mismatches.** Audit `detail` was hashed before JSON round-tripping, so any entry containing a `Date` or an `undefined` field failed verification.
- **Audit rows rewritten on delete.** `audit_logs` foreign keys were `ON DELETE SET NULL`: deleting a case or user rewrote hashed audit rows and broke the chain. They are now `RESTRICT`.
- **Seed script.** `npm run db:seed` ran `tsx` directly, so `.env` was never loaded and the README's setup flow failed. It now goes through `prisma db seed`.
- **Server Action auth.** Governance Server Actions had no authentication check.
