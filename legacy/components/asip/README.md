# 🛡️ ASIP: Autonomous Security Investigation Platform

<div align="center">

### Enterprise-Grade Multi-Agent Security Operations & GraphRAG Platform

Transform cybersecurity alerts and telemetry into evidence-backed investigations using Multi-Agent AI Swarms, GraphRAG, Threat Intelligence, Investigation Memory, and Autonomous Reasoning.

---

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green.svg?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-JS%20Frontend-61DAFB.svg?style=for-the-badge&logo=react)](https://react.dev/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Agent%20Orchestrator-purple.svg?style=for-the-badge)](https://www.langchain.com/langgraph)
[![SQLite / Postgres](https://img.shields.io/badge/SQL-Engine-blue.svg?style=for-the-badge&logo=sqlite)](https://sqlite.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapping-darkgreen.svg?style=for-the-badge)](https://attack.mitre.org/)

</div>

---

## 🚀 Vision

ASIP is not a chatbot. 

ASIP is an **autonomous investigation operating system** designed to think and operate like a senior Security Operations Center (SOC) analyst, threat hunter, and incident responder simultaneously. It processes security telemetry (EVTX, logs, CSVs, JSON), maps IOCs, queries Threat Intelligence, runs dynamic correlation processes, and performs adversarial validation before rendering containment recommendations and technical incident reports.

---

## 🖼️ Analyst Portal Showcase & Visual Walkthrough

The **ASIP Analyst Portal** provides a premium, responsive glassmorphism UI for investigating incoming threats. Below is a detailed visual guide of the core features:

### 1. Ingest Queue & Event Stream Preview
The ingestion system allows analysts to upload forensic archives (ZIP, 7z), specify severity parameters, or paste raw JSON telemetry. Raw telemetry is mapped deterministically to a **Universal Event Schema (UES)**.
*   **Queue Panel (Left)**: Displays ongoing and completed investigations, their status (e.g., pending, running, completed, failed, or awaiting password), event counts, and timestamp logs.
*   **Log Stream View (Right)**: Shows a paginated list of normalized telemetry events. Analysts can filter through events using the search bar, inspecting attributes such as Event Type, Process Name, commandline strings, destination IPs, and destination ports.

![Ingest and Log Preview](assets/demo_loaded_logs.png)

---

### 2. Swarm Root Cause Analysis (RCA) & MITRE ATT&CK Mapping
The reasoning core of the AI Swarm translates raw data into executive-level and technical summaries.
*   **Root Cause Thesis**: A detailed explanation of the threat delivery vector, execution chains, command & control beaconing, and dropper persistence metrics.
*   **Reconstructed Forensic Timeline**: Combines and orders events chronologically across files, processes, and network socket creations, mapping them to exact Sysmon/Windows Event IDs (e.g., Sysmon Event ID 1 for Process Create, Event ID 3 for Network Connect).
*   **MITRE ATT&CK Techniques**: Displays technique cards representing tactic categories (Initial Access, Execution, Command and Control) mapped directly to active evidence with confidence scores.

![RCA and MITRE Mapping](assets/mitre_mapping_rca.png)

---

### 3. Forensic Process Tree Visualization
Processes, network sockets, and file writes are plotted onto an interactive, node-link graph mapping out process lineage:
*   **Process Nodes (Teal)**: Represent processes with attributes like PID, command-line arguments, host, and executing user.
*   **Network Targets (Blue)**: Show outbound TCP/UDP destination IPs and ports connected to by execution threads.
*   **Dropped Files (Green)**: Highlight new binary creations, indicating file paths and SHA256 hashes.
*   **Directed Edges**: Graph linkages showing parent-child process actions (`SPAWNED`), network sockets (`CONNECTED_TO`), and dropper file actions (`CREATED` / `LOADED`).

![Forensic Process Tree](assets/forensic_process_tree_view.png)

---

### 4. Response & Containment Playbooks
The platform writes automated mitigation instructions divided into logical remediation phases:
*   **Phase 1: Immediate Containment**: Critical actions designed to halt malware spreading immediately. Features interactive containment checkboxes such as host isolation rules (dropping network segments at EDR layers), user session revocations, and firewall proxy blocks.
*   **Phase 2: Short-Term Sweeps & Threat Hunting**: Secondary containment tactics, including indicators to sweep active directories for malicious run keys and phishing attachment hashes.

![Mitigation Playbook](assets/response_playbook_view.png)

---

## 🏗️ Advanced System Architecture

The platform separates ingestion, analytical reasoning, memory caching, and presentation layers to maintain low latency and high consistency.

```mermaid
graph TD
    %% Ingestion Layer
    subgraph Ingestion
        A[Forensic Uploads: ZIP, 7Z, EVTX, CSV, JSON] --> B[Intake Gateway & Decryptor]
        B --> C[Universal Log Normalizer]
    end

    %% Data Layer
    subgraph Storage [Data & Correlation Layer]
        C --> D[(PostgreSQL / SQLite Fallback)]
        D --> E[Entity Graph Builder]
    end

    %% AI reasoning loop
    subgraph Swarm [LangGraph AI Swarm Orchestrator]
        F[1. Triage & Classify Agent] --> G[2. Correlation & RCA Agent]
        G --> H[3. Adversarial QA Agent]
        H -->|Validation Fails| G
        H -->|Validated| I[4. Playbook & Report Writer]
    end

    %% Memory and Intelligence
    subgraph Intelligence [Enrichment & Memory Store]
        J[Threat Intel APIs: VirusTotal / AbuseIPDB]
        K[Qdrant Semantic Memory]
    end

    %% Interconnections
    D -->|Telemetry Streams| Swarm
    E -->|Attack Process Trees| Swarm
    Swarm <-->|Indicators & Hashes| J
    Swarm <-->|Incident Playbook RAG| K
    I -->|Final Reports & Graphs| L[Analyst Portal React UI]
```

### Flow Breakdown:
1. **Intake Gateway**: Supports recursive archive extraction and prompts the analyst if encrypted files require a password.
2. **Universal Normalizer**: Maps multi-source vendor structures (CrowdStrike, Windows Sysmon, Splunk, Wazuh) into a standard relational schema.
3. **LangGraph Swarm**: Coordinates reasoning. An Adversarial QA Agent validates every statement in the RCA against the raw DB events to prevent model hallucinations.
4. **Graph & Semantic Memory**: Connects execution trees and updates a semantic vector cache (Qdrant) with incident metadata for past investigation recalls.

### 🤖 Multi-Agent Swarm Execution Flow

The sequence diagram below displays the execution logic, tracing information flow and context handover across the autonomous swarming agents:

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Analyst / Webhook
    participant Gateway as Intake Gateway
    participant DB as SQLite / Postgres DB
    participant Graph as Entity Graph Builder
    participant Triage as Triage Agent
    participant RCA as Correlation & RCA Agent
    participant QA as Adversarial QA Agent
    participant Report as Report & Playbook Agent

    Analyst->>Gateway: Upload Forensic Logs / Telemetry
    Gateway->>Gateway: Extract recursively & Parse logs
    Gateway->>DB: Ingest normalized events (UES)
    
    Analyst->>Triage: Trigger Swarm Analysis
    DB-->>Triage: Fetch alert & normalized logs
    Triage->>Triage: Classify alert & map initial MITRE Tactics
    Triage->>RCA: Pass classified alert & telemetry context

    Graph-->>RCA: Load Process Tree & Network connections
    RCA->>RCA: Correlate processes, track parent-child, reconstruct timeline
    RCA->>QA: Pass reconstructed Root Cause Thesis & Timeline

    DB-->>QA: Fetch raw database events for assertions
    QA->>QA: Verify assertions against raw database IDs
    alt Verification Fails (Hallucination detected)
        QA-->>RCA: Send validation error & revision instructions
        RCA->>RCA: Recorrelate details and rewrite thesis
        RCA->>QA: Resubmit thesis
    end
    QA->>Report: Approve and pass verified thesis

    Report->>Report: Format containment playbook, mitigation rules & Sigma detections
    Report->>DB: Save incident reports, timeline, and MITRE maps
    Report-->>Analyst: Present technical briefings on Analyst Portal React UI
```

---

## ⚡ Core Capabilities

*   **Multi-Agent Orchestration**: LangGraph state machine coordinating specialized agents for triage, process correlation, QA verification, and playbook writing.
*   **Database Autonomy**: Out-of-the-box local SQLite fallback (`asip.db` via `aiosqlite`) when PostgreSQL services are offline.
*   **Offline Demo Mode**: Instantly simulate complete forensic investigations, pre-populating mock configurations, events, IOCs, timelines, and MITRE maps with zero API keys or external models.
*   **Adversarial QA**: Programmatic citation matching ensuring every claim in the report corresponds to validated log database entries.
*   **Threat Intel Integration**: Dynamic VT and AbuseIPDB indicator scoring.

---

## ⚙️ Configuration & Environment

The platform reads settings dynamically from a `.env` file or in-memory updates:

| Environment Variable | Description | Default |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy Connection URL | `postgresql+asyncpg://asip:asip@localhost/asip` |
| `REDIS_URL` | Caching & Task Broker URL | `redis://localhost:6379` |
| `EMBEDDING_PROVIDER` | Embeddings Engine | `mock` (Optional: `openai`, `ollama`) |
| `OLLAMA_BASE_URL` | Local Model Host | `http://localhost:11434` |
| `LOCAL_MODEL` | Offloaded Offline LLM | `qwen2.5:14b` |
| `CLOUD_MODEL` | Enterprise Reasoning LLM | `claude-3-5-sonnet-20241022` |

---

## 🚀 Quickstart Guide

### Prerequisite Setup

Ensure Python 3.11+ and Node.js 18+ are installed.

```bash
# Clone the repository
git clone https://github.com/DHARANI2D/helios-asip.git
cd helios-asip
```

### 1. Run the Backend Server
```bash
# Set up Python virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend (starts on http://localhost:8000)
# Automatically initializes schema on local SQLite fallback if Postgres is down
python -m asip.api.main
```

### 2. Run the Frontend Dev Server
```bash
cd frontend

# Install Node dependencies
npm install

# Run frontend (starts on http://localhost:5173)
npm run dev
```

### 3. Launch Offline Demo
1. Open `http://localhost:5173` in your browser.
2. Click **Demo Mode** in the top header.
3. The platform will automatically load simulated API configurations, instantiate mock telemetry events inside the DB, and render a complete investigation in the analyst portal!
