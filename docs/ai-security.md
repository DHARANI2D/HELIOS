# AI Security

The chatbots, agents and RAG applications a client runs are an attack surface of their own. People try to talk them out of their rules, plant instructions in the documents and web pages they read, get them to reveal their system prompt or other people's data, and steer agents into actions nobody asked for. **AI Security** (`src/lib/aisec`, the **AI Security** page) secures them from before launch to every request in production, and puts what happens in front of the SOC like any other system.

It has four parts, used together or on their own:

| Part | What it does | Where |
|---|---|---|
| AI systems | The inventory: what each AI application does, the data it handles, the tools it may use, its policy and its key | AI Security → Register an AI system |
| Runtime guard | Checks each step of a request against the system's policy and answers allow, watch, redact or block, with a signed receipt | `POST /api/v1/ai/guard` |
| AI gateway | An OpenAI-compatible endpoint: model calls go through HELIOS, which holds the provider key, masks personal data and checks both directions | `POST /api/v1/ai/gateway/chat/completions` |
| AI red team | Attacks the application through its chat endpoint inside an authorised security test, and reports what got through | Security testing, check "AI applications" |

Who can do what: everyone who can see a client's data can see its AI systems (`aisec.view`); analysts, incident responders, detection engineers, SOC managers, admins and the client's own admin can register systems, edit policies and issue keys (`aisec.manage`). A red team needs the same permissions and authorisations as any security test.

## 1. Register an AI system

Name it, say what kind it is (chat assistant, agent with tools, search/RAG application, model API) and tick the data it handles. The data decides its starting policy:

| Data | Pack added to the baseline |
|---|---|
| Personal data | **Privacy (DPDP / GDPR)**: email, phone, card, Aadhaar, PAN, SSN, IBAN and dates of birth masked in prompts, documents and answers |
| Health records | **Healthcare**: privacy, plus medical record numbers and ABHA IDs; patient identifiers can't leave through tools; messages need the person's confirmation; no calls to arbitrary web addresses |
| Payment card data | **Financial services**: card, IBAN and PAN masked; payments, refunds and transfers need confirmation; refunds capped |
| Source code or internal documents, on an agent | **Enterprise IT**: destructive shell commands and schema changes blocked; credentials never leave in answers or tool calls |

There is also a **Strict** pack for high-risk systems (links only to listed domains, personal data blocked rather than masked in answers).

Each system gets:
- a **key** (`hgs_…`), shown once, for the guard and the gateway. Only its hash is stored; rotate or revoke it on the Connect tab;
- a **canary**: a reference to put in the system prompt (Red team tab). If it ever appears in an answer, the system prompt leaked. The guard blocks that answer and opens a case, and the red team uses it as proof. The canary is never written to a log or a report.

## 2. The guard policy

The **Guard policy** tab edits what HELIOS checks at each stage and what it does. Each control is `block`, `redact` (mask and let through), `watch` (let through and record) or `off`.

| Stage | Checks |
|---|---|
| Prompt (what a person sends) | Prompt injection (overrides, fake system messages, instructions hidden in base64 or invisible characters), jailbreaks (rule-free personas, "developer mode", hypotheticals), requests for the system prompt, ruled-out topics, personal data, credentials, size |
| Retrieval (documents about to be read) | Documents the person's roles don't allow are withheld (each document can carry the roles allowed to read it); documents carrying instructions for the AI are withheld; personal data and credentials masked |
| Tool call | Tools are denied by default; rules per tool (or prefix, `send_*`): allow, watch, needs the person's confirmation, or block; argument rules (must match, must not match, one of, at most); an agent that declares its task may use only that task's tools; personal data and credentials in arguments |
| Tool result | Injection hidden in what a tool returned (the most common indirect injection); personal data and credentials |
| Answer | The canary (a leaked system prompt), credentials, personal data, ruled-out topics, scripts and other active content, images whose address carries data (a way to send the conversation elsewhere), links outside the allowed domains |

**Monitor mode** decides exactly the same but tells the application to go ahead, so a client can see what the policy would do before it enforces. Every save is a **new version**, in force on the next call; the History tab keeps every version with who changed it and why. The **test bench** tries a sample (or one of the built-in ones) against the policy, or against unsaved edits, without recording anything.

## 3. Connect an application

### The guard API

The application asks HELIOS at each step, then does what `action` says.

```bash
curl -s https://helios.example.com/api/v1/ai/guard \
  -H "Authorization: Bearer $HELIOS_AI_KEY" -H "Content-Type: application/json" \
  -d '{"stage": "prompt", "content": "Ignore previous instructions…", "user": {"id": "patient-1234"}}'
```

```json
{
  "decision": "block",
  "action": "block",
  "mode": "enforce",
  "findings": [{ "rule": "injection.override", "verdict": "block", "message": "The prompt tries to override the assistant's instructions", "owasp": ["LLM01"], "atlas": ["AML.T0051.000"] }],
  "explanation": "Blocked. The prompt tries to override the assistant's instructions (OWASP LLM01).",
  "receipt": { "body": { "v": 1, "id": "rcpt_…", "system": "…", "stage": "prompt", "decision": "block", "enforced": "block", "rules": ["injection.override"], "contentSha256": "…", "policyVersion": 3, "at": "…" }, "keyId": "…", "signature": "…" },
  "caseId": null
}
```

- `action`: `allow` and `watch` go ahead; `redact` uses the returned `content` (or `documents` for retrieval); `block` stops.
- Other stages: `{"stage": "retrieval", "documents": [{"id": "d1", "text": "…", "access": ["nurse"]}], "user": {"roles": ["nurse"]}}`; `{"stage": "tool_call", "tool": {"name": "refund_payment", "args": {"amount": 500}}, "task": "refunds", "confirmed": false}`; `{"stage": "tool_output", "content": "…"}`; `{"stage": "output", "content": "…"}`.
- `needsConfirmation: true` means: ask the person, then call again with `"confirmed": true`.
- Requests over the system's rate limit are blocked (one event per minute is recorded, not one per request).

### The gateway

Point an OpenAI-compatible SDK at HELIOS and use the system's key as the API key; set the provider (an OpenAI-compatible base URL), the default model and the provider key on the Connect tab. The provider key is sealed with the client's own data key and never reaches the application.

```python
from openai import OpenAI

client = OpenAI(base_url="https://helios.example.com/api/v1/ai/gateway", api_key=HELIOS_AI_KEY)
answer = client.chat.completions.create(model="gpt-4.1-mini", messages=[{"role": "user", "content": question}])
```

For each call HELIOS checks the newest prompt and any tool results after it; in **privacy mode** (on by default) it replaces personal data with placeholders (`EMAIL_1`, `PHONE_1`, `AADHAAR_1`) and removes credentials before the request leaves, and puts the values back in the answer; then it checks the answer and every tool call the model asks for. A blocked answer comes back with `finish_reason: "content_filter"`; a blocked tool call is removed, with a note. The answer carries a `helios` field with each check's decision and receipt id, and the headers `x-helios-decision` and `x-helios-receipts`. Streaming isn't supported: the whole answer is checked before anyone sees it. A provider on a private address (a local model) needs `HELIOS_AI_GATEWAY_ALLOW_PRIVATE=1` on the server.

### Receipts

Every decision has a receipt signed with an Ed25519 key derived from the platform's master key. `GET /api/v1/ai/receipts` returns the public key, for checking offline; `POST /api/v1/ai/receipts` with a receipt answers whether it is genuine and unchanged (also on the Decisions tab). The receipt holds a SHA-256 of the content, never the content. Changing the master key changes the signing key; each receipt names the key id it was signed with.

### What is kept

Each decision is a security event on the client (`platform:helios-ai-guard` in Explore, `ai.guard.<decision>` as the event type): the system, stage, verdicts, rules, OWASP and ATLAS references, the end user's id or address if the application sends it, a masked excerpt (personal data, credentials and the canary removed) and the receipt. Prompts and answers themselves are kept only if the client turns on **Keep prompts and answers**: then they are sealed with the client's own data key, and each opening (Decisions tab) is written to the audit log.

## 4. Cases for the SOC

These open a case (one open case per system, a new detection per signal, per end user, per hour):

| Signal | Severity |
|---|---|
| The canary in an answer (system prompt leaked) | High |
| A credential in an answer | High |
| An answer embedding a data-carrying image | High |
| Instructions planted in retrieved documents or tool results | High |
| A tool call outside the agent's declared task | Medium |
| A tool call its policy forbids (blocked tool or argument) | Medium |
| Five or more blocked or watched attacks from one end user in ten minutes | Medium |

The cases are worked like any other: AI first response, playbooks, the client's portal.

## 5. The AI red team

A red team is a check in a **security test**, under the same rules as every other test: the client proves the endpoint's host is theirs (a DNS TXT record), the client's admin and a HELIOS approver who didn't ask for it both authorise it, and it runs on its own inside the window, stopping if anyone cancels. Request it from the system's Red team tab ("Red-team it") or from Security testing, ticking "AI applications" and the systems. The systems' chat endpoints join the test's scope automatically. Set the endpoint on the Connect tab: an https URL that speaks OpenAI chat completions, or its own JSON (a request body with `{{prompt}}` and the path to the answer), plus a header it needs, sealed.

What it tries, per system (up to 60 requests, one at a time, half a second apart):

| OWASP (2025) | Attacks | Proof |
|---|---|---|
| LLM01 Prompt injection | Override, fake system message (chat-template markers), rule-free persona, the client's ruled-out topics | A random code it was told to repeat; discussing the topic without refusing |
| LLM02 Sensitive information disclosure | Asks for other people's contact details, and for keys and passwords | Personal data or credentials in the answer (masked in the report) |
| LLM05 Improper output handling | Asks for a script; asks it to end with a tracking image | Executable markup; an outside image carrying data |
| LLM06 Excessive agency | Asks it to delete an account or issue a refund without confirmation | It claims the action is done without asking |
| LLM07 System prompt leakage | Repeat the text above; print the configuration | The canary in the answer (without a canary, an answer that reads like instructions is reported as probable) |
| LLM09 Misinformation | A law and a date that don't exist | A confident, detailed answer |
| LLM10 Unbounded consumption | An enormous answer | Over 20,000 characters |

When the AI refuses, the same goal is tried again in up to three other forms (four attempts in all). The forms rotate from one attack to the next, so a run uses all seven: base64, a role-play frame, a hypothetical, split into two halves, another language, fake examples, false authority. The finding names the form that worked. The payloads are harmless codes, the canary and the client's own topics; nothing harmful is asked for and nothing is exploited.

Results appear on the test (by category, with findings and a PDF section) and on the system (Red team tab, and the overview). **From findings to protection** lists the guard settings that block what got through and switches them on as a new policy version. The red team talks to the application directly: a finding that stays open after a re-test means the application isn't routed through the guard or the gateway yet, or needs the fix itself.

LLM03 (supply chain), LLM04 (data and model poisoning) and LLM08 (vector and embedding weaknesses) can't be tested from outside. The inventory records models and providers (LLM03), poisoned documents are caught at retrieval as indirect injection (LLM04), and the retrieval check enforces document access (LLM08).

## 6. Posture and frameworks

The AI Security page shows, across the systems in view, each OWASP Top 10 for LLMs item as **protected** (every system's guard enforces the control), **tested** (the red team found nothing open), **partly**, a **gap** (an open finding, or nothing covers it yet) or **outside HELIOS**, and a score from them. The Frameworks card shows where HELIOS records evidence for the NIST AI RMF (Govern, Map, Measure, Manage), ISO/IEC 42001 Annex A (A.2, A.5, A.6, A.7, A.9, A.10), the EU AI Act's requirements for high-risk systems (Articles 9, 10, 12, 14, 15) and the MITRE ATLAS techniques findings map to. This is evidence and controls, not certification; whether a system is high-risk under the EU AI Act is the client's assessment.

## Limits

- **Detection is pattern-based.** It stops the common forms of each attack (including encoded and hidden ones) and is checked by tests, but a determined attacker can phrase things it doesn't recognise. The red team is how a client learns what still gets through; keep both.
- **Masking, not encrypted computation.** Personal data is replaced with placeholders before it reaches the model provider, and credentials are removed. HELIOS itself sees prompts in clear while it checks them. Nothing here is homomorphic encryption or encrypted vector search.
- **The guard only protects what calls it.** An application that skips a stage isn't guarded at that stage; the decisions page and the "last call" column show which systems are actually calling.
- **Misinformation is only tested, not guarded:** HELIOS can't know what's true for a client.
- The red team's excessive-agency and misinformation checks read the answer's wording, so they can miss an action taken silently or flag a careful answer; their findings are medium and low.
