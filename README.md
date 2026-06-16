# 🛡️ ASIP

# Autonomous Security Investigation Platform

<div align="center">

### AI-Powered Autonomous Security Operations & Investigation Platform

Transform alerts into evidence-backed investigations using Multi-Agent AI, GraphRAG, Threat Intelligence, Investigation Memory, and Autonomous Reasoning.

---

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![LangGraph](https://img.shields.io/badge/LangGraph-Agent%20Orchestration-purple)
![Neo4j](https://img.shields.io/badge/Neo4j-GraphRAG-blue)
![Qdrant](https://img.shields.io/badge/Qdrant-Vector%20Database-orange)
![OpenSearch](https://img.shields.io/badge/OpenSearch-Search-red)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-darkgreen)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Enterprise-blue)

</div>

---

# 🚀 Vision

ASIP is not a chatbot.

ASIP is an autonomous investigation operating system designed to think and operate like a senior SOC analyst, threat hunter, incident responder, malware analyst, and detection engineer simultaneously.

Instead of simply summarizing alerts, ASIP:

* Collects evidence
* Correlates telemetry
* Extracts IOCs
* Maps MITRE ATT&CK techniques
* Reconstructs attack timelines
* Determines root cause
* Validates findings through adversarial QA
* Generates containment recommendations
* Learns from previous investigations
* Builds attack graphs
* Creates detection content
* Supports automated response workflows

---

# 🎯 Why ASIP Exists

Modern SOC teams face:

| Challenge                    | Impact                                                            |
| ---------------------------- | ----------------------------------------------------------------- |
| Alert Fatigue                | Analysts overwhelmed by thousands of alerts                       |
| Tool Fragmentation           | Data spread across SIEM, EDR, Cloud, Email and Identity platforms |
| Manual Investigations        | Hours spent correlating telemetry                                 |
| Knowledge Silos              | Historical investigations not reused                              |
| Talent Shortage              | Limited senior analysts                                           |
| Threat Intelligence Overload | Too much data, not enough context                                 |

ASIP addresses these challenges through autonomous investigation workflows and AI-driven reasoning.

---

# ⚡ Core Capabilities

## Autonomous Investigation

✓ Alert Understanding

✓ Root Cause Analysis

✓ IOC Extraction

✓ Threat Intelligence Enrichment

✓ Timeline Reconstruction

✓ MITRE ATT&CK Mapping

✓ Attack Chain Generation

✓ Threat Hunting

✓ Detection Engineering

✓ Incident Reporting

✓ Response Recommendations

✓ Investigation Memory

---

## Multi-Source Ingestion

### SIEM

* Splunk
* Google SecOps
* Microsoft Sentinel
* IBM QRadar
* Elastic Security

### EDR/XDR

* CrowdStrike Falcon
* Microsoft Defender
* SentinelOne
* Wazuh

### Cloud Platforms

* AWS
* Azure
* GCP

### Identity Platforms

* Active Directory
* Microsoft Entra ID
* Okta

### Email Platforms

* Microsoft 365
* Google Workspace

---

# 📁 Supported File Types

| Type | Status |
| ---- | ------ |
| CSV  | ✅      |
| XLSX | ✅      |
| JSON | ✅      |
| TXT  | ✅      |
| LOG  | ✅      |
| EVTX | ✅      |
| XML  | ✅      |
| ZIP  | ✅      |
| 7Z   | ✅      |
| TAR  | ✅      |
| PCAP | ✅      |
| PDF  | ✅      |
| DOCX | ✅      |

---

# 🧠 AI Investigation Swarm

ASIP uses specialized AI agents coordinated through LangGraph workflows.

| Agent                       | Purpose                  |
| --------------------------- | ------------------------ |
| Investigation Director      | Workflow orchestration   |
| Intake Agent                | File ingestion           |
| Parsing Agent               | Log normalization        |
| Alert Understanding Agent   | Alert classification     |
| IOC Agent                   | IOC extraction           |
| Threat Intelligence Agent   | IOC enrichment           |
| Correlation Agent           | Event correlation        |
| Root Cause Agent            | Root cause analysis      |
| MITRE Agent                 | ATT&CK mapping           |
| Timeline Agent              | Timeline reconstruction  |
| Attack Chain Agent          | Kill chain generation    |
| Threat Hunting Agent        | Historical investigation |
| Detection Engineering Agent | Sigma/KQL generation     |
| QA Validation Agent         | Evidence verification    |
| Report Agent                | Executive reporting      |
| Recommendation Agent        | Response guidance        |

---

# 🏗 High-Level Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                       Analyst Portal                         │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                 Investigation Director Agent                │
└──────────────────────────────┬───────────────────────────────┘
                               │
           ┌───────────────────┴───────────────────┐
           ▼                                       ▼

┌───────────────────────┐           ┌─────────────────────────┐
│ Investigation Swarm   │           │ Intelligence Layer      │
│                       │           │                         │
│ IOC Agent             │           │ GraphRAG               │
│ RCA Agent             │           │ Incident Memory        │
│ Timeline Agent        │           │ Threat Intelligence    │
│ MITRE Agent           │           │ Playbooks              │
│ QA Agent              │           │ MITRE ATT&CK           │
└───────────────────────┘           └─────────────────────────┘

           └───────────────────┬───────────────────┘
                               │
                               ▼

┌──────────────────────────────────────────────────────────────┐
│                         Data Layer                           │
│ PostgreSQL • Neo4j • Qdrant • OpenSearch • Redis • MinIO    │
└──────────────────────────────────────────────────────────────┘

                               ▲
                               │

┌──────────────────────────────────────────────────────────────┐
│                      Ingestion Layer                         │
│ Splunk • CrowdStrike • Wazuh • Sentinel • APIs • Uploads    │
└──────────────────────────────────────────────────────────────┘
```

---

# 🔍 Investigation Lifecycle

```text
Alert
  ↓
Normalization
  ↓
IOC Extraction
  ↓
Threat Intelligence
  ↓
Correlation
  ↓
Timeline Reconstruction
  ↓
Root Cause Analysis
  ↓
MITRE ATT&CK Mapping
  ↓
Attack Graph Generation
  ↓
Adversarial Validation
  ↓
Containment Recommendations
  ↓
Executive & Technical Reports
```

---

# 🕸 GraphRAG & Investigation Memory

ASIP combines traditional RAG with graph-native intelligence.

## Vector RAG

Stores:

* MITRE ATT&CK
* Threat Reports
* Playbooks
* Detection Rules
* Response Procedures

## GraphRAG

Represents relationships between:

```text
User
 ↓
Host
 ↓
Process
 ↓
File
 ↓
Hash
 ↓
Threat Actor
```

## Investigation Memory

Stores:

* Previous Incidents
* Historical IOCs
* RCA Reports
* Analyst Feedback
* Threat Hunting Results

Enabling cross-incident correlation and historical context retrieval.

---

# 🤖 Hybrid AI Architecture

ASIP supports cloud, hybrid, and fully air-gapped deployments.

## Cloud

* OpenAI
* Anthropic
* Gemini

## Hybrid

* Qwen
* OpenAI
* Claude

## Air-Gapped

* Qwen
* Llama
* Ollama

Model routing automatically selects the optimal model based on:

* Task complexity
* Data sensitivity
* Context size
* Cost optimization

---

# 🛡 Security Controls

* Multi-Tenant Isolation
* Role-Based Access Control
* Audit Logging
* Encryption At Rest
* Encryption In Transit
* Secrets Management
* Air-Gapped Deployment Support
* SOC2 Ready Architecture
* Enterprise SSO Integration


---

# 🚀 Deployment Modes

## SaaS

Cloud-native deployment using managed services.

## Hybrid

Sensitive data processed locally while advanced reasoning uses cloud models.

## Air-Gapped

Fully offline deployment for government, defense, and critical infrastructure environments.

---

# 🛣 Roadmap

### Phase 1

Alert Triage & Investigation

### Phase 2

Threat Intelligence & MITRE Mapping

### Phase 3

GraphRAG & Investigation Memory

### Phase 4

Threat Hunting & Detection Engineering

### Phase 5

Autonomous SOC Operations

### Phase 6

Self-Learning Security Operations Platform

---

# 📜 License

Enterprise License

Copyright © ASIP
