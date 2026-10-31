import type { RunbookInput } from "@/lib/runbooks/match";

// Starter runbooks: common incident types, written as checklists an analyst
// works through. A SOC adds them from the Runbooks page and edits them to
// its own practice; nothing is installed without someone choosing to.

export const RUNBOOK_TEMPLATES: RunbookInput[] = [
  {
    title: "Phishing email",
    description: "A reported or detected phishing message: confirm it, find every copy, remove them, and deal with anyone who clicked.",
    match: { sources: [], techniques: ["T1566"], keywords: ["phish"], minSeverity: null },
    steps: [
      { id: "confirm", title: "Confirm the verdict", detail: "Check the sender, authentication results (SPF, DKIM, DMARC), links and attachments in the forensic report.", required: true },
      { id: "scope", title: "Find every recipient", detail: "Search the mail logs for the same sender, subject, link or attachment hash.", required: true },
      { id: "purge", title: "Remove the message from every mailbox", detail: "Record how many copies were removed.", required: true },
      { id: "block", title: "Block the sender and the indicators", detail: "Sender address or domain at the mail gateway; links and file hashes at the proxy and EDR.", required: false },
      { id: "clicked", title: "Deal with anyone who clicked or opened it", detail: "Check their sign-ins since; if credentials may have been entered, reset the password and revoke sessions.", required: true },
      { id: "rules", title: "Check the affected mailboxes for new rules", detail: "Inbox rules or forwarding created after the message arrived are a sign of a takeover.", required: false },
      { id: "tell", title: "Tell the recipients and the client contact", detail: "What happened, what was done, and what to look out for.", required: false },
    ],
  },
  {
    title: "Compromised account",
    description: "Sign-ins or activity the account owner didn't do: cut the attacker off, then find out what they did.",
    match: { sources: [], techniques: ["T1078", "T1110", "T1098", "T1621"], keywords: ["compromised account", "impossible travel", "account takeover"], minSeverity: null },
    steps: [
      { id: "owner", title: "Check with the owner, out of band", detail: "By phone or in person, not by email to the account. Was the activity theirs?", required: true },
      { id: "sessions", title: "Revoke sessions and refresh tokens", detail: "So the attacker's existing sign-ins stop working.", required: true },
      { id: "password", title: "Reset the password", detail: "For a privileged account, also rotate any secrets it could read.", required: true },
      { id: "mfa", title: "Review recently registered sign-in methods", detail: "Remove any MFA method or device the owner doesn't recognise.", required: true },
      { id: "persistence", title: "Look for what the attacker left behind", detail: "Mailbox rules, forwarding, app consents (OAuth grants), new devices, new admin roles.", required: false },
      { id: "activity", title: "Review what the account did while compromised", detail: "Sign-ins, files read or shared, mail sent, admin changes.", required: false },
      { id: "sources", title: "Check the attacker's IP addresses against other accounts", detail: "Block them if they aren't shared infrastructure.", required: false },
    ],
  },
  {
    title: "Malware on an endpoint",
    description: "Malicious code ran on a host: contain it, keep the evidence, find how it got in and where else it is.",
    match: { sources: [], techniques: ["T1204", "T1059", "T1547", "T1053", "T1055"], keywords: ["malware", "trojan", "malicious file", "backdoor"], minSeverity: null },
    steps: [
      { id: "isolate", title: "Isolate the host if the malware is active", detail: "Or if it touches a critical system; follow the client's rulebook for protected assets.", required: true },
      { id: "evidence", title: "Collect evidence before cleaning", detail: "The file and its hash, the process tree, persistence, network connections, a triage package from the EDR.", required: true },
      { id: "entry", title: "Find the way in and the first run", detail: "Email attachment, download, removable media or an exploit.", required: false },
      { id: "hunt", title: "Search every host for the same indicators", detail: "File hash and name, and the network destinations it used.", required: true },
      { id: "clean", title: "Remove it, or reimage", detail: "Reimage if it ran with administrator rights or you can't be sure it's gone.", required: false },
      { id: "creds", title: "Reset credentials used on the host while it was infected", detail: "", required: false },
      { id: "release", title: "Release isolation after a clean scan and the client's agreement", detail: "", required: false },
    ],
  },
  {
    title: "Ransomware",
    description: "Files being encrypted or a ransom note: stop the spread first, protect the backups, keep the evidence, and start the regulatory clock.",
    match: { sources: [], techniques: ["T1486", "T1490"], keywords: ["ransom"], minSeverity: null },
    steps: [
      { id: "isolate", title: "Isolate the affected hosts from the network", detail: "Don't power them off: memory may hold the key or the attacker's tools.", required: true },
      { id: "call", title: "Call the client's incident contact now", detail: "By phone; agree who decides on shutting down systems.", required: true },
      { id: "spread", title: "Stop the spread", detail: "Disable the accounts the attacker used; block SMB and RDP between segments if it's moving laterally.", required: true },
      { id: "backups", title: "Protect the backups", detail: "Confirm they're offline or immutable, and stop jobs that would overwrite good copies with encrypted files.", required: true },
      { id: "identify", title: "Identify the strain", detail: "From the ransom note and file extension; check No More Ransom for a decryptor.", required: false },
      { id: "evidence", title: "Preserve evidence", detail: "The ransom note, encrypted samples, and logs from domain controllers, EDR and firewalls.", required: false },
      { id: "certin", title: "Report to CERT-In within 6 hours", detail: "Ransomware is a malicious code attack under the CERT-In directions; work the report HELIOS opened on the Compliance page.", required: true },
      { id: "pay", title: "No contact with the attacker without the client's leadership and legal advice", detail: "", required: false },
    ],
  },
  {
    title: "Data exfiltration",
    description: "Data leaving to somewhere it shouldn't: find what left, stop it, keep the logs, and decide on notifications.",
    match: { sources: [], techniques: ["T1041", "T1048", "T1567", "T1020"], keywords: ["exfiltration", "data leak", "data breach"], minSeverity: null },
    steps: [
      { id: "what", title: "Identify what left", detail: "Which data, how much, from which system and account, to where.", required: true },
      { id: "block", title: "Block the destination and the path", detail: "Domain, IP or cloud storage account; the account or host doing the transfer.", required: true },
      { id: "preserve", title: "Preserve the logs for the window", detail: "Proxy, firewall, DLP and cloud audit logs.", required: true },
      { id: "personal", title: "Decide with the client whether personal data was involved", detail: "If it was, start the DPDP breach workflow (the Board and the people affected).", required: true },
      { id: "others", title: "Look for other hosts or accounts talking to the same destination", detail: "", required: false },
      { id: "certin", title: "Record the timeline for CERT-In", detail: "Data breach and data leak are reportable within 6 hours.", required: false },
    ],
  },
];
