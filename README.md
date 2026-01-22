# DESAS — Dynamic Email Sandbox Analysis System

![Status](https://img.shields.io/badge/Status-Analyst--Ready-green)
![Security](https://img.shields.io/badge/Security-Isolated--Sandbox-red)
![Architecture](https://img.shields.io/badge/Platform-Proxmox%20VM-blue)

DESAS is a specialized workstation designed for SOC analysts to safely investigate and detonate suspicious emails. It provides a controlled sandbox environment to observe real-world malicious behavior and generate actionable, block-ready intelligence.

## 🚀 Key Features
- **Isolated Detonation**: Run suspicious URLs in a secure, ephemeral browser context.
- **Runtime DOM Monitoring**: Detect "hidden" phishing forms injected via JavaScript after initial page load.
- **Network Traffic Analysis**: Monitor redirect chains and external POST requests.
- **Explainable Scoring**: Deterministic, rule-based verdicts mapped to MITRE ATT&CK.
- **Block-Ready Intelligence**: Instantly copy-pasteable URLs, domains, and hashes for your security controls.

## 📂 Documentation Suite
For a deep dive into the project, please refer to the following guidebooks:

| Document | Audience | Purpose |
|----------|----------|---------|
| [**DESIGN.md**](./DESIGN.md) | Security Architects | Technical architecture, component diagrams, and isolation principles. |
| [**SUMMARY.md**](./SUMMARY.md) | SOC Managers | High-level value proposition and strategic fit within security operations. |
| [**WALKTHROUGH.md**](./WALKTHROUGH.md) | Analysts | Step-by-step demo script for investigating a stealth phishing email. |
| [**ARCH_REVIEW.md**](./ARCH_REVIEW.md) | Review Panels | Preparation for technical reviews and common architectural questions. |

## 🛠 Project Components
- **Backend**: FastAPI (Python)
- **Sandbox**: Playwright with Headless Chromium
- **Isolation**: Proxmox Virtualization
- **Reporting**: JSON/Markdown evidence reports

## 🛡 Security Isolation
DESAS is designed to run in a dedicated Proxmox VM with:
- No internal network access.
- Controlled internet egress.
- Disposable snapshots (reset after every run).

---
*DESAS: From "Suspicious" to "Confirmed" in 2 minutes.*
