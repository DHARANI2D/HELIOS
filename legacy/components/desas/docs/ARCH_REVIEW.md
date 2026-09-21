# Prep: Architectural Review Q&A

This document prepares the DESAS team for technical and architectural review panels.

## 1. Security & Isolation

**Note:** The items below describe the *recommended deployment posture* for DESAS, not built-in application behavior. As of the current codebase, `sandbox/browser.py` runs Selenium + headless Chrome as a local process on whatever machine hosts DESAS — there is no VM provisioning, snapshot/rollback, or egress-filtering logic in the app itself. Achieving the isolation described below requires the operator to deploy DESAS inside a hardened VM/VLAN; it is not something the software does automatically today.

**Q: Why run the sandbox inside a Proxmox VM instead of directly on the analyst's machine?**
*A: Proxmox provides true kernel-level isolation and hardware virtualization. If a zero-day exploit targets the browser/OS during detonation, the Proxmox hypervisor provides a much stronger security boundary than running headless Chrome as an unsandboxed process on the analyst's primary workstation. It also allows for clean, reliable state resets via snapshots. This is an operational deployment recommendation — the application does not manage the VM itself.*

**Q: How do you prevent a malicious email from pivoting into the corporate network?**
*A: This depends entirely on how DESAS is deployed. The recommendation is a "Default Deny" egress VM/VLAN with no route to internal corporate networks. The application itself does not configure or enforce network egress rules — that is the responsibility of the host environment.*

## 2. Technical Decisions

**Q: Why use a rule-based scoring engine instead of Machine Learning (ML)?**
*A: In a SOC environment, "Explainability" is more valuable than "Prediction." An analyst needs to know *exactly* which behavior (e.g., an injected password field) caused the flag. ML models often act as black boxes, which can lead to "Alert Fatigue" or lack of confidence in the results.*

**Q: Why Selenium/Headless Chrome instead of a traditional sandbox?**
*A: Traditional sandboxes are often detected by modern phishing pages that check for virtualization artifacts. A real Chrome instance driven via Selenium allows for more realistic browser behavior and better interception of runtime DOM changes (via CDP performance logs), which is where modern stealth phishing resides.*

## 3. Operational Fit

**Q: Is DESAS intended to replace an Email Security Gateway (SEG)?**
*A: No. DESAS is an investigation tool, not a volume scanner. It is used when a SEG identifies an email as "Suspicious" but "Inconclusive," allowing a human analyst to perform a safe, high-fidelity deep dive.*

**Q: How do you handle "Evase URL" techniques like geolocation blocking?**
*A: DESAS currently focuses on behavior once the page loads. Future iterations will include the ability to use rotating clean-IP proxies to mirror different geographic regions if an analyst suspects geolocation-based evasion.*

## 4. Maintenance & Scalability

**Q: How do you keep the scoring engine updated as new threats emerge?**
*A: The scoring engine uses a modular YAML-based rule system. New indicators can be added by analysts without needing to rewrite core application code, allowing the tool to evolve alongside the threat landscape.*
