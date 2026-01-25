# DESAS — Dynamic Email Sandbox Analysis System

![Status](https://img.shields.io/badge/Status-Analyst--Ready-green)
![Security](https://img.shields.io/badge/Security-Isolated--Sandbox-red)
![Desktop](https://img.shields.io/badge/Platform-Electron--Desktop-orange)
![Reports](https://img.shields.io/badge/Reports-Professional%20PDF-blue)

DESAS is a specialized workstation designed for SOC analysts to safely investigate and detonate suspicious emails. It provides a controlled playground to observe malicious behavior, analyze headers, and generate actionable intelligence—now available as a standalone desktop application with professional reporting.

## 🚀 Key Features
- **Professional PDF Reporting**: Instantly generate forensic-grade PDF reports including email screenshots, VirusTotal reputation, and Sandbox evidence.
- **Isolated Detonation**: Run suspicious URLs in a secure, ephemeral browser context with Playwright.
- **API Quota Tracking**: Real-time visibility into VirusTotal and MxToolbox API token usage directly in the sidebar.
- **Forensic Toolkit**: Dedicated standalone tools for rapid domain intelligence and attachment scrutiny.
- **Header Analysis**: Automated parsing of SPF, DKIM, and DMARC records to detect spoofing and impersonation.
- **Whitelist Management**: Integrated domain whitelisting to filter known-safe infrastructure.

## 🖥 Desktop Application
DESAS is a robust **Electron-based Desktop Application**.
- **Integrated Backend**: Seamlessly spawns the Python FastAPI analysis engine on startup.
- **Visual Evidence**: Automated capturing of email body and sandbox screenshots for forensic reporting.
- **Custom Branding**: Professional shield-themed identity for SOC environments.

## 📂 Directory Structure
```
DESAS/
├── app/                # Core Application Logic
│   ├── analyzer/       # Email & Header Parsing Modules
│   ├── core/           # Schemas, Config, Whitelist Management
│   ├── sandbox/        # Playwright Detonation logic
│   ├── templates/      # Electron/Web UI (HTML/CSS/JS)
│   └── static/         # Generated evidence (screenshots)
├── icon.png            # Application Icon
├── main.js             # Electron Main Process
├── package.json        # Node dependencies & Build Config
├── requirements.txt    # Python dependencies
└── docs/               # Advanced documentation suite
```

## 🛠 Tech Stack
- **Frontend**: Electron (Vanilla CSS & JS for high-performance UI)
- **Backend API**: FastAPI (Python 3.10+)
- **Detonation**: Playwright (Headless Chromium)
- **Reporting**: ReportLab (Professional PDF Generation)
- **Intelligence**: VirusTotal API, MxToolbox API, IP-API

## 📂 Documentation Suite
| Document | Purpose |
|----------|---------|
| [**DESIGN.md**](./DESIGN.md) | Technical architecture and isolation principles. |
| [**SUMMARY.md**](./SUMMARY.md) | Strategic fit within security operations. |
| [**WALKTHROUGH.md**](./WALKTHROUGH.md) | Step-by-step forensic demo scenario. |
| [**WINDOWS_BUILD_GUIDE.md**](./WINDOWS_BUILD_GUIDE.md) | Instructions for building the `.exe` installer. |

---
*DESAS: Transforming suspicious emails into actionable forensic intelligence.*
