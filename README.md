# DESAS — Dynamic Email Sandbox Analysis System

![DESAS Banner](./banner.png)

![Status](https://img.shields.io/badge/Status-Production--Ready-green)
![Security](https://img.shields.io/badge/Security-Isolated--Sandbox-red)
![Platform](https://img.shields.io/badge/Platform-Electron--Desktop-orange)
![Reports](https://img.shields.io/badge/Reports-Professional%20PDF-blue)

**DESAS** is a specialized forensic workstation designed for SOC analysts to safely investigate and detonate suspicious emails. It provides a controlled environment to observe malicious behavior, analyze headers, extract intelligence, and generate professional forensic reports—all within a standalone desktop application.

---

## 🚀 Key Features

### 📄 Professional PDF Reporting
- **Forensic-Grade Reports**: Instantly generate comprehensive PDF reports with email screenshots, VirusTotal reputation data, MxToolbox diagnostics, and sandbox behavioral evidence
- **Visual Evidence**: Automated capturing of email body and sandbox screenshots for legal and compliance documentation
- **Detailed Metadata**: Complete email headers including Subject, Sender, Recipient, Date/Time, and authentication results

### 🔍 Advanced Threat Intelligence
- **VirusTotal Integration**: Real-time domain/URL reputation checks with malicious hit counts and domain age analysis
- **MxToolbox Diagnostics**: Automated SPF, DKIM, DMARC, MX, and Blacklist verification for sender authentication
- **IP Reputation**: Infrastructure abuse scoring and geolocation tracking
- **API Quota Tracking**: Live visibility into VirusTotal and MxToolbox token usage directly in the sidebar

### 🧪 Isolated Sandbox Detonation
- **Headless Browser**: Secure URL detonation using Playwright with Chromium
- **Behavioral Analysis**: Real-time DOM mutation tracking, form detection, and JavaScript execution monitoring
- **Screenshot Evidence**: Automated visual capture of each redirect hop and final landing page
- **Network Forensics**: Complete request logging with domain extraction and exfiltration detection

### 🛠 Forensic Toolkit
- **Domain Intelligence**: Standalone tool for rapid VirusTotal lookups with whitelist integration
- **Attachment Scrutiny**: Dedicated analysis for suspicious files with safe extraction
- **Header Parser**: Standalone SPF/DKIM/DMARC validation and hop visualization
- **Whitelist Management**: Centralized domain whitelisting with dynamic override capabilities

---

## 🖥 Desktop Application

DESAS is built as a robust **Electron-based Desktop Application** for seamless analyst workflows:

- ✅ **Integrated Backend**: Automatically spawns Python FastAPI analysis engine on startup
- ✅ **Cross-Platform**: Optimized for Windows and macOS environments
- ✅ **Professional Branding**: Custom shield-themed icon and premium UI design
- ✅ **Offline Capable**: Core analysis works without internet (except external API calls)

---

## 📂 Project Structure

```
DESAS/
├── app/                      # Core Application Logic
│   ├── analyzer/             # Email Parsing & Intelligence Modules
│   │   ├── eml_parser.py     # .eml file parser
│   │   ├── msg_parser.py     # Outlook .msg parser
│   │   ├── headers.py        # SPF/DKIM/DMARC analysis
│   │   ├── body.py           # URL extraction & VirusTotal checks
│   │   ├── attachments.py    # File type detection & risk scoring
│   │   ├── mxtoolbox.py      # MxToolbox API integration
│   │   └── reputation.py     # IP intelligence (IP-API)
│   ├── core/                 # Configuration & Data Models
│   │   ├── schemas.py        # Pydantic models for API responses
│   │   ├── config.py         # Environment & API key management
│   │   ├── whitelist_manager.py  # Dynamic whitelist operations
│   │   └── scoring.py        # Verdict calculation logic
│   ├── sandbox/              # Detonation Engine
│   │   └── browser.py        # Playwright-based URL sandbox
│   ├── api/                  # FastAPI Endpoints
│   │   └── endpoints.py      # Analysis & reporting routes
│   ├── templates/            # Electron UI (HTML/CSS/JS)
│   │   ├── index.html        # Main analysis interface
│   │   └── settings.html     # Configuration panel
│   └── static/               # Generated Evidence (screenshots, hops)
├── docs/                     # Documentation Suite
│   ├── DESIGN.md             # Technical architecture
│   ├── SUMMARY.md            # Strategic overview
│   ├── WALKTHROUGH.md        # Demo scenario
│   ├── ARCH_REVIEW.md        # Review preparation
│   └── WINDOWS_BUILD_GUIDE.md # Build instructions
├── samples/                  # Test Email Samples
├── build_assets/             # Build Configuration
│   ├── backend.spec          # PyInstaller spec
│   └── run_server.py         # Standalone server launcher
├── icon.png                  # Application Icon
├── main.js                   # Electron Main Process
├── package.json              # Node.js Dependencies & Build Config
├── requirements.txt          # Python Dependencies
├── .env.example              # Environment Template
├── .gitignore                # Git Exclusions
└── README.md                 # This File
```

---

## 🛠 Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Frontend** | Electron + Vanilla CSS/JS | High-performance desktop UI |
| **Backend** | FastAPI (Python 3.10+) | RESTful analysis API |
| **Detonation** | Playwright (Chromium) | Headless browser sandbox |
| **Reporting** | ReportLab | Professional PDF generation |
| **Intelligence** | VirusTotal API, MxToolbox API, IP-API | Threat reputation & validation |
| **Parsing** | `extract_msg`, `email` (stdlib) | Email format support (.eml, .msg) |
| **Packaging** | PyInstaller, Electron-Builder | Standalone executables |

---

## � Quick Start

### Prerequisites
- **Python 3.10+** with pip
- **Node.js 18+** with npm
- **Playwright** browsers installed

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd DESAS
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

3. **Install Node.js dependencies**
   ```bash
   npm install
   ```

4. **Configure API keys**
   ```bash
   cp .env.example .env
   # Edit .env and add your VirusTotal and MxToolbox API keys
   ```

5. **Run the application**
   ```bash
   npm start
   ```

---

## 📖 Documentation

| Document | Audience | Description |
|----------|----------|-------------|
| [**DESIGN.md**](./docs/DESIGN.md) | Security Architects | Technical architecture, component diagrams, and isolation principles |
| [**SUMMARY.md**](./docs/SUMMARY.md) | SOC Managers | High-level value proposition and strategic fit |
| [**WALKTHROUGH.md**](./docs/WALKTHROUGH.md) | Analysts | Step-by-step forensic investigation demo |
| [**WINDOWS_BUILD_GUIDE.md**](./docs/WINDOWS_BUILD_GUIDE.md) | Developers | Instructions for building Windows `.exe` installer |
| [**ARCH_REVIEW.md**](./docs/ARCH_REVIEW.md) | Review Panels | Preparation for technical reviews and Q&A |

---

## 🛡 Security & Isolation

DESAS is designed to run in a **dedicated, isolated environment**:

- ✅ **No Internal Network Access**: Prevents lateral movement to corporate infrastructure
- ✅ **Controlled Egress**: Monitored internet access for detonation and API calls only
- ✅ **Disposable Contexts**: Every sandbox session is ephemeral to prevent cross-contamination
- ✅ **API Key Protection**: Sensitive credentials stored in `.env` (excluded from version control)

---

## 🎯 Use Cases

1. **Phishing Investigation**: Analyze suspicious emails with automated header validation and URL detonation
2. **Incident Response**: Generate forensic PDF reports with visual evidence for legal/compliance teams
3. **Threat Hunting**: Bulk domain/URL reputation checks using the Forensic Toolkit
4. **Security Awareness**: Demonstrate real-world phishing techniques in a safe environment

---

## 📝 License

This project is proprietary software developed for SOC operations.

---

**DESAS**: *Transforming suspicious emails into actionable forensic intelligence.*
