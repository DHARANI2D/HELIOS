# Prep: Architectural Review Q&A

This document prepares the DESAS team for technical and architectural review panels.

## 1. Security & Isolation

**Q: Why use a Proxmox VM instead of a simple container on the analyst's machine?**
*A: Proxmox provides true kernel-level isolation and hardware virtualization. If a zero-day exploit targets the browser/OS, the Proxmox hypervisor provides a much stronger security boundary than a shared-kernel container. It also allows for clean, reliable state resets via snapshots.*

**Q: How do you prevent a malicious email from pivoting into the corporate network?**
*A: The DESAS VM environment is configured with "Default Deny" egress rules. It has no network route to internal corporate VLANs. Internet egress is strictly controlled and monitored.*

## 2. Technical Decisions

**Q: Why use a rule-based scoring engine instead of Machine Learning (ML)?**
*A: In a SOC environment, "Explainability" is more valuable than "Prediction." An analyst needs to know *exactly* which behavior (e.g., an injected password field) caused the flag. ML models often act as black boxes, which can lead to "Alert Fatigue" or lack of confidence in the results.*

**Q: Why Playwright/Headless Chromium instead of a traditional sandbox?**
*A: Traditional sandboxes are often detected by modern phishing pages that check for virtualization artifacts. Playwright/Chromium allows for more realistic browser behavior and better interception of runtime DOM changes, which is where modern stealth phishing resides.*

## 3. Operational Fit

**Q: Is DESAS intended to replace an Email Security Gateway (SEG)?**
*A: No. DESAS is an investigation tool, not a volume scanner. It is used when a SEG identifies an email as "Suspicious" but "Inconclusive," allowing a human analyst to perform a safe, high-fidelity deep dive.*

**Q: How do you handle "Evase URL" techniques like geolocation blocking?**
*A: DESAS currently focuses on behavior once the page loads. Future iterations will include the ability to use rotating clean-IP proxies to mirror different geographic regions if an analyst suspects geolocation-based evasion.*

## 4. Maintenance & Scalability

**Q: How do you keep the scoring engine updated as new threats emerge?**
*A: The scoring engine uses a modular YAML-based rule system. New indicators can be added by analysts without needing to rewrite core application code, allowing the tool to evolve alongside the threat landscape.*
