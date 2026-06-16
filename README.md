# 🛡️ Autonomous Security Investigation Platform (ASIP)

### AI-Powered Autonomous Security Operations & Investigation Platform
*Transform alerts into evidence-backed investigations using Multi-Agent AI Swarms, GraphRAG, Threat Intelligence, Investigation Memory, and Autonomous Reasoning.*

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green?style=for-the-badge&logo=fastapi)
![LangGraph](https://img.shields.io/badge/LangGraph-Agent%20Orchestration-purple?style=for-the-badge&logo=chainlink)
![Neo4j](https://img.shields.io/badge/Neo4j-GraphRAG-blue?style=for-the-badge&logo=neo4j)
![Qdrant](https://img.shields.io/badge/Qdrant-Vector%20Database-orange?style=for-the-badge)
![OpenSearch](https://img.shields.io/badge/OpenSearch-Search-red?style=for-the-badge&logo=opensearch)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-darkgreen?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker)

</div>

---

## 🚀 Vision

**ASIP is not a chatbot.**

ASIP is an autonomous investigation operating system designed to think and operate like a senior SOC analyst, threat hunter, incident responder, malware analyst, and detection engineer simultaneously.

Instead of simply summarizing alerts, ASIP:
*   Collects evidence and parses telemetry deterministically
*   Correlates logs across endpoints, firewalls, and mailboxes
*   Extracts and decodes obfuscated indicators of compromise (IOCs)
*   Maps raw events to MITRE ATT&CK techniques
*   Reconstructs forensic timelines chronologically
*   Determines root cause vectors through Chain-of-Thought (CoT) reasoning
*   Validates findings through an Adversarial QA agent
*   Generates actionable, prioritized containment recommendations
*   Recalls past cases via semantic investigation memory

---

## 🎯 Why ASIP Exists

Modern Security Operations Centers (SOC) face crippling operational overhead:

| Challenge | Impact | ASIP Solution |
| :--- | :--- | :--- |
| **Alert Fatigue** | Analysts overwhelmed by thousands of daily alerts. | **Autonomous Triage**: Instant analysis of incoming webhooks. |
| **Tool Fragmentation** | Data spread across SIEM, EDR, Cloud, Email, and Identity. | **Universal Event Schema (UES)**: Consolidates diverse telemetry. |
| **Manual Investigations** | Hours spent manually querying process paths. | **Graph Correlation**: Automated parent-child process mapping. |
| **Knowledge Silos** | Historical investigation reports are rarely reused. | **Incident Memory**: Auto-indexes reports for future recall. |

---

## ⚡ Core Capabilities & Integrations

### Ingestion Matrix
*   **SIEM**: Splunk, Google SecOps, Microsoft Sentinel, Elastic Security
*   **EDR/XDR**: CrowdStrike Falcon, Microsoft Defender, SentinelOne, Wazuh
*   **Cloud Platforms**: AWS CloudTrail, Azure Monitor, GCP Cloud Logging
*   **Identity & Collaboration**: Active Directory, Okta, Microsoft 365, Google Workspace

### Supported File Formats
*   ✅ **Structured Data**: CSV, XLSX, JSON, XML
*   ✅ **System Logs**: raw `.log`, `.txt` Syslog
*   ✅ **Forensics**: Windows Event Binary (`.evtx`), Packet Capture (`.pcap`)
*   ✅ **Archives**: `.zip`, `.7z`, `.tar` (including recursively nested & password-encrypted zip files)

---

## 🤖 AI Swarm Architecture

ASIP organizes the investigation workflow into four consolidated cognitive nodes within a LangGraph state machine, preventing context drift:

```
                  ┌─────────────────────────────────────────┐
                  │          Ingestion & Normalizer         │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │          1. Triage & Extraction         │
                  │          - Contextualizes Alert         │
                  │          - Extracts raw IOC details     │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │       2. Correlation & RCA Agent        │
                  │       - Rebuilds Process Trees          │
                  │       - Queries Playbook & Incident RAG │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
             ┌─────────────────────────────────────────┐
             │         3. Adversarial QA Agent         │
             │         - Verifies database citations   │
             └────────────────────┬────────────────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  │ Does it pass validation?      │
                  └──────┬─────────────────┬──────┘
                         │ No              │ Yes
                         ▼                 ▼
             ┌───────────────────────┐ ┌─────────────────────────┐
             │ Loop back to RCA node │ │ 4. Reporting Agent      │
             │ to correct analysis   │ │ - Compiles Markdown     │
             └───────────────────────┘ │   Summary & Playbook    │
                                       └─────────────────────────┘
```

---

## 🕸️ GraphRAG & Inmemory Memory Layer

ASIP combines traditional vector retrieval with graph-native intelligence:

*   **Vector RAG**: Indexing of MITRE ATT&CK mitigation manuals and internal enterprise playbooks into Qdrant vector databases.
*   **GraphRAG**: Contextualizes entity relationships:
    `[User] ──(Logon)──► [Host] ──(Spawned)──► [Process] ──(Connected)──► [C2 IP]`
*   **Investigation Memory**: Completed markdown reports and threat trees are stored inside the vector index. New alerts check memory for semantic overlap, instantly surfacing similar historical vectors (e.g., *"Same Tor C2 beacon was investigated 90 days ago on server04"*).

---

## 📁 Project Structure

```
Helios/
├── requirements.txt            # Python backend requirements
├── docker-compose.yml          # Container configuration (Postgres, Redis, Qdrant)
├── asip/                       # Core backend package
│   ├── core/
│   │   ├── config.py           # Settings and credentials manager
│   │   ├── database.py         # DB engines session factory
│   │   └── models.py           # Database and UES tables
│   ├── intake/
│   │   ├── gateway.py          # Recursive archive handler (zip/7z password prompt)
│   │   ├── normalizer.py       # Format routing coordinator
│   │   └── parsers/            # Platform-specific parsers (EVTX, CSV, JSON)
│   ├── graph/
│   │   └── entity_graph.py     # NetworkX execution chain tree builder
│   ├── enrichment/
│   │   └── manager.py          # VirusTotal & AbuseIPDB enrichment manager
│   ├── rag/
│   │   ├── vector_store.py     # Vector indexing (Qdrant & shared mock cache)
│   │   ├── playbook_rag.py     # Indices for ATT&CK & playbooks
│   │   └── incident_memory.py  # Incident indexing & semantic lookup
│   ├── agents/
│   │   ├── orchestrator.py     # LangGraph Swarm State Machine
│   │   ├── triage_agent.py     # Triage node
│   │   ├── rca_agent.py        # Analysis reasoning node
│   │   ├── qa_agent.py         # Verification check node
│   │   └── report_agent.py     # Report writing node
│   ├── api/
│   │   ├── main.py             # App initialization and startup lifespans
│   │   └── routes/
│   │       ├── investigate.py  # Standard forensic file ingestions
│   │       └── webhooks.py     # SIEM Alert webhook endpoints
│   └── models/
│       └── llm_clients.py      # LLM API Client router with mock fallbacks
└── frontend/                   # React web client dashboard
```

---

## ⚙️ Installation & Setup

### 1. Prerequisites
*   **Python**: `>= 3.10`
*   **Node.js**: `>= 18.0`
*   **Ollama (Optional for fully offline air-gapped runs)**: Standard installer configured with `qwen2.5:14b` or `llama3.3`.

### 2. Configure Settings
Create a `.env` file in the root project folder:
```env
PROJECT_NAME="ASIP Swarm"
DATABASE_URL="sqlite+aiosqlite:///asip.db"

# API Keys (Optional. If missing, safe fallback mock logic executes)
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."

# Local Models
OLLAMA_BASE_URL="http://localhost:11434"
LOCAL_MODEL="qwen2.5:14b"
CLOUD_MODEL="claude-3-5-sonnet-20241022"

# RAG & Webhook settings
EMBEDDING_PROVIDER="mock"  # Options: mock, openai, ollama
QDRANT_HOST="localhost"
QDRANT_PORT=6333
```

### 3. Start Backend Server
```bash
# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run FastAPI with reload enabled
uvicorn asip.api.main:app --host 0.0.0.0 --port 8000 --reload
```
*   Backend documentation page is hosted at: [http://localhost:8000/docs](http://localhost:8000/docs)

### 4. Build and Run Web Client
```bash
cd frontend
npm install
npm run dev
```
*   Web portal runs at: [http://localhost:5173/](http://localhost:5173/)

---

## 📡 Webhook Integration Specifications

Enterprise alerts can be directed straight to `/api/v1/webhooks/alerts`. The system automatically normalizes severities and initiates asynchronous swarms.

*   **Endpoint**: `POST http://localhost:8000/api/v1/webhooks/alerts`
*   **Example Splunk Alert Inbound Payload**:
    ```json
    {
      "search_name": "Suspicious PowerShell Execution Rule",
      "result": {
        "ComputerName": "server01.domain.local",
        "CommandLine": "powershell.exe -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp..."
      }
    }
    ```

---

## 🧪 Verification & Testing

Verify that all ingestion normalizers, NetworkX process correlation, and Vector RAG incident lookups compile and execute successfully using these verification command sets:

```bash
# Activate virtual environment
source .venv/bin/activate

# Test 1: Ingestion, Decryption, UES Normalization and NetworkX Graphing
python /Users/dharanidharan/.gemini/antigravity-ide/brain/8f65266a-cf06-4b0e-afdf-3801699145f3/scratch/test_pipeline.py

# Test 2: Playbook RAG, Webhook parsing, Swarm Orchestration, and Incident Memory Lookup
python /Users/dharanidharan/.gemini/antigravity-ide/brain/8f65266a-cf06-4b0e-afdf-3801699145f3/scratch/test_rag_webhooks.py
```

---

## 🛣️ Development Roadmap

*   **Phase 1**: Core Engine & Archive Handling (Ingestion normalizers and decryption gateway).
*   **Phase 2**: Forensics Correlation (NetworkX process mapping and threat intelligence manager).
*   **Phase 3**: Swarm Orchestration (Consolidated 4-agent LangGraph state machine).
*   **Phase 4**: Vector Knowledge Bases (Playbook and ATT&CK indexings, Incident memory, webhooks).
*   **Phase 5**: Autonomous SOC Operations (Sigma rule compilers, SOAR response containment connectors).

---

## 📜 License & Copyright

**Enterprise License**  
Copyright © ASIP. All rights reserved.
