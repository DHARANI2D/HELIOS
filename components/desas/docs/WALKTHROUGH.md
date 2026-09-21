# Demo Walkthrough: Investigating a Stealth Phishing Email

This guide walks through a typical analyst investigation using DESAS.

## Scenario
An analyst receives an alert for a suspicious email from a high-profile target. The email contains a link that passes initial gateway checks but looks suspicious due to the sender's tone.

## Step 1: Ingestion
1. **Save the email**: The analyst saves the suspicious email as a `.eml` file.
2. **Upload to DESAS**: Open the DESAS dashboard and upload the file.
   - *Observation*: Note how DESAS immediately extracts headers and identifies the primary URL.

## Step 2: Static Analysis
1. **Review extraction**: Point out the "Expanded URLs" section. 
2. **Note flags**: DESAS highlights that a URL shortener (e.g., Bitly) was used.
   - *Draft Verdict*: "Suspicious - Investigation Required."

## Step 3: Dynamic Detonation
1. **Start Analysis**: Click the "Run Dynamic Analysis" button.
2. **The Sandbox in Action**: Explain that DESAS is now opening a headless browser, following redirects, and waiting for the page to render.
3. **Behavior Capture**:
   - *Network*: Show the redirect chain that leads to a realistic-looking "Microsoft 365" login page hosted on a hijacked WordPress site.
   - *DOM Mutation*: Show the flag where DESAS detected a password input field being injected via JavaScript 5 seconds after page load.

## Step 4: Final Verdict & Response
1. **The Report**: Show the "High Risk" verdict.
2. **Evidence**: Point to the "Why it is Dangerous" section, which clearly lists the injected login form and the external POST request.
3. **Response**: 
   - Copy the malicious URL and destination IP from the "Block Recommendations" section.
   - Paste these into the corporate email gateway and web proxy blocklists.
   - Reset the DESAS sandbox with one click.

## Conclusion
In under 2 minutes, the analyst transformed a "vague suspicion" into "confirmed credential harvesting" with full evidence for the incident report.
