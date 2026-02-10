# 📄 Confluence: DESAS Platform Documentation & User Guide

| Project | DESAS (Dynamic Email Sandbox Analysis System) |
| :--- | :--- |
| **Document Status** | � Final Review |
| **Owner** | SOC Architecture Team |
| **Target Audience** | Tier 1/2/3 SOC Analysts, Threat Hunters |

---

## � Table of Contents
1.  [Overview](#overview)
2.  [Email Analysis Pipeline (The "Full Analysis" Module)](#email-analysis-pipeline)
    *   [Input Handling](#input-handling)
    *   [Forensic Intelligence Layers](#forensic-intelligence)
    *   [Sandbox Detonation](#sandbox-detonation)
3.  [Forensic Toolkit (Standalone Utilities)](#forensic-toolkit)
    *   [Deep File & Malware Analysis](#deep-file-analysis)
    *   [Network & Intelligence Tools](#network-intelligence)
4.  [Reporting & Evidence Preservation](#reporting)
5.  [Administration (Settings & Whitelist)](#administration)
6.  [Technical Reference (APIs & MITRE)](#technical-reference)

---

## 1. Overview <a name="overview"></a>
DESAS is a "Clean Room" forensic workstation for email investigation. It automates the extraction and analysis of emails, providing deep visibility into hidden payloads, risky headers, and malicious web behaviors.

---

## 2. Email Analysis Pipeline <a name="email-analysis-pipeline"></a>
### 2.1 Input Handling <a name="input-handling"></a>
Analysts can ingest emails via **Drag & Drop** or file selection:
*   **Supported Formats**: `.eml` (Standard MIME) and `.msg` (Outlook Compound File).
*   **Integrity**: The system calculates SHA-256 hashes for all ingested emails and attachments immediately upon upload.

### 2.2 Forensic Intelligence Layers <a name="forensic-intelligence"></a>
The page is divided into specialized investigation cards:

#### A. Global Verdict & Scoring
*   **Verdict**: Malicious (Red), Suspicious (Orange), or Benign (Green).
*   **Score (0-100)**: A weighted calculation based on header failures, VT hits, and sandbox behaviors.

#### B. Header Forensics
*   **Authentication**: Real-time status of **SPF, DKIM, and DMARC**.
*   **Routing Audit**: Counts the number of MTAs (Hops) in the `Received` headers. A hop count of 1 for external email often triggers a spoofing alert.
*   **Sender Reputation**: Pulls geo-location and ISP data for the originating IP address.

#### C. Body & URL Analysis
*   **Internal Link Audit**: Lists every unique URL found in the text and HTML parts.
*   **VirusTotal (VT) Integration**:
    *   Each URL is cross-referenced with VirusTotal.
    *   **VT Redirect**: Click the "VT" icon next to any URL to instantly navigate to the official VirusTotal summary page for that specific artifact.

#### D. Attachment Extraction
*   Identifies risky extensions (`.exe`, `.scr`, `.xlsm`).
*   Calculates entropy to detect packed or encrypted payloads.

### 2.3 Sandbox Detonation <a name="sandbox-detonation"></a>
The **Smart Sandbox** is the core of the dynamic analysis:
*   **Execution**: URLs are opened in a dedicated, isolated Playwright instance.
*   **Evidence Collection**: Automatically takes screenshots of the page (important for credential harvesting detection).
*   **Behavioral Tracking**: Monitors the DOM for "Suspicious Forms" (e.g., a Microsoft Login form on a non-Microsoft domain).

---

## 3. Forensic Toolkit <a name="forensic-toolkit"></a>
Used for investigating standalone artifacts without a full email context.

### 3.1 Deep File & Malware Analysis <a name="deep-file-analysis"></a>
The toolkit provides **Advanced Forensic Detections**:

| Feature | Detailed Capability | Rationale |
| :--- | :--- | :--- |
| **Polyglot Check** | Detects mismatched signatures (e.g., a file that is both PDF and ZIP). | Used for EDR/Sandbox bypass. |
| **XLM Macro Scan** | Heuristic scan for legacy Excel 4.0 macros (`EXEC`, `REGISTER`, `CALL`). | High-risk stealth technique. |
| **OLE Stream Audit** | Scans OLE files for suspicious streams like `ObjectPool` or `MBDG`. | Detects embedded exploits. |
| **Appended Data** | Checks for data (PowerShell/Shellcode) hidden after Image EOF markers. | Common in "Image-based" malware. |
| **Image OCR** | Pulls text and URLs from PNG/JPG/BMP files automatically. | Identifies "bit.ly" links in screenshots. |
| **Office Extraction** | Full text reconstruction from **DOCX** and **XLSX**. | View content safely without opening Office. |
| **Audit Path** | Preserves and displays the original filename of the analysis target. | Maintains a clear forensic chain. |

### 3.2 Network & Intelligence Tools <a name="network-intelligence"></a>
*   **Domain Intelligence**: Standalone MX record lookup and domain reputation audit.
*   **URL Sandbox**: Manual detonation of any URL for on-demand screenshotting.

---

## 4. Reporting & Evidence <a name="reporting"></a>
*   **PDF Generation**: Click **"Download PDF Report"** in the top navigation.
*   **Contents**: Includes the calculated risk score, verdict summary, table of all extracted URLs, and a dedicated section for visual Evidence (screenshots taken during sandboxing).

---

## 5. Administration <a name="administration"></a>
### 5.1 Settings Module
This is where the analyst configures the engine's external brain:
*   **VirusTotal API**: Required for URL and attachment reputation scoring.
*   **MxToolbox API**: Used for official DNS and MX validation.
*   **Storage**: API keys are encrypted and stored in the application's local configuration.

### 5.2 Dynamic Whitelisting
*   **Purpose**: To reduce noise for internal or known-safe infrastructure.
*   **Workflow**: Use the Whitelist tab in Settings to add domains. Any domain on this list is automatically skipped during scoring (vetted as Benign).

---

## 6. Technical Reference <a name="technical-reference"></a>
### 6.1 Integrated APIs
*   **VirusTotal**: Malware reputation.
*   **MxToolbox**: DNS/Email security validation.
*   **IP-API**: Sender IP geolocation.
*   **Playwright**: Browser sandboxing.

### 6.2 MITRE ATT&CK Mapping
Detections are automatically tagged with the following techniques:
*   **T1027**: Obfuscated Files/Information.
*   **T1204**: User Execution (Malicious Files).
*   **T1566**: Phishing (Links/Attachments).
*   **T1497**: Evasion/Anti-Sandbox.

---
*End of Documentation*
