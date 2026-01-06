# AEGIS: Complete System Explanation (From Scratch)

## 🎯 What is AEGIS?

**AEGIS** = **AI Enforcement & Governance Infrastructure System**

Think of AEGIS as a **security checkpoint** that sits between your AI agents and the resources they want to access. Just like airport security checks passengers before they board a plane, AEGIS checks every action an AI agent wants to take before allowing it.

---

## 🏗️ The Big Picture: How AEGIS Works

### The Flow (Step by Step)

```
1. AI Agent wants to do something
   ↓
2. Agent asks AEGIS: "Can I do this?"
   ↓
3. AEGIS checks:
   - Is this action allowed? (Policy)
   - Do I trust this agent? (Trust Score)
   - Does the reasoning make sense? (Logic Check)
   - Is this suspicious behavior? (Anomaly Detection)
   ↓
4. AEGIS decides: ALLOW or DENY
   ↓
5. AEGIS logs everything (Audit Trail)
   ↓
6. If ALLOW: Agent performs action
   If DENY: Agent is blocked + trust score drops
```

### Real-World Example

**Scenario**: Customer support AI wants to send an email

```
Agent: "I want to SEND_EMAIL to customer@example.com"
AEGIS: "Let me check..."
  ✓ Policy says: Email sending is allowed
  ✓ Trust score: 100% (good standing)
  ✓ Reasoning: "Responding to support ticket" (makes sense)
  ✓ Behavior: Normal pattern
AEGIS: "ALLOW - Go ahead"
Agent: Sends email successfully
AEGIS: Logs the action for audit
```

**Scenario**: Same AI tries something suspicious

```
Agent: "I want to SEND_EXTERNAL_REQUEST to https://attacker.com"
AEGIS: "Let me check..."
  ✗ Policy says: External requests are DENIED
  ✗ Destination: Not in whitelist
  ✗ Reasoning: Doesn't match agent's purpose
AEGIS: "DENY - Blocked!"
Agent: Cannot perform action
AEGIS: Logs denial + reduces trust score 100% → 70%
```

---

## 📁 System Architecture: Where Everything Lives

### Backend (Python/FastAPI)

```
backend/
├── src/aegis/
│   ├── db.py                    # Database models (WHERE data is stored)
│   ├── api/
│   │   ├── main.py              # Main application (WHAT runs the server)
│   │   └── routers/
│   │       ├── identity.py      # Agent identity management
│   │       ├── governance.py    # Purge, reset, trust management
│   │       ├── audit.py         # Audit log retrieval
│   │       ├── scenarios.py     # Security test scenarios
│   │       └── investigation.py # Breach investigation (NEW!)
│   ├── governance/
│   │   ├── policy.py            # Policy evaluation (WHY actions are allowed/denied)
│   │   └── trust.py             # Trust score calculation
│   ├── audit/
│   │   └── ledger.py            # Tamper-proof logging
│   └── simulator/
│       └── scenarios.py         # Attack simulation definitions
```

### Frontend (React/Vite)

```
frontend/
├── src/
│   ├── App.jsx                  # Main application (WHAT user sees)
│   └── components/
│       ├── ControlCenter.jsx    # Dashboard overview
│       ├── IdentityRegistry.jsx # Issue/manage agent IDs
│       ├── WorkloadNodes.jsx    # View agent status (NOW CLICKABLE!)
│       ├── AuditArchives.jsx    # View logs
│       ├── SimulatorOrchestrator.jsx  # Run attack scenarios
│       └── InvestigationModal.jsx     # Breach details (NEW!)
```

---

## 🔍 Deep Dive: Each Component Explained

### 1. Database Models (`db.py`)

**WHAT**: Defines the structure of data we store  
**WHERE**: `backend/src/aegis/db.py`  
**WHY**: Need persistent storage for agents, logs, investigations

#### Agent Model
```python
class Agent(SQLModel, table=True):
    id: str                    # Unique identifier (e.g., "customer-bot-01")
    public_key: str            # Cryptographic identity
    trust: float = 100.0       # Trust score (0-100%)
    status: str = "Active"     # Active, REVOKED, etc.
    level: int = 10            # Access level (0-10)
    mode: str = "FULL_ACCESS"  # FULL_ACCESS, ISOLATED, etc.
```

**HOW it's used**:
- When you issue a new agent ID → Creates new Agent record
- When global purge happens → Updates all agents to REVOKED
- When checking permissions → Reads trust score and level

#### BreachInvestigation Model (NEW!)
```python
class BreachInvestigation(SQLModel, table=True):
    agent_id: str              # Which agent was breached
    breach_type: str           # Type of attack detected
    severity: str              # CRITICAL, HIGH, MEDIUM
    detection_mechanism: str   # How we caught it
    evidence: str              # JSON with all proof
    status: str                # UNDER_INVESTIGATION, CONFIRMED, etc.
```

**HOW it's used**:
- When global purge executes → Creates investigation for each agent
- When you click revoked agent → Fetches investigation details
- When you restore agent → Updates investigation status

---

### 2. API Endpoints (Routers)

**WHAT**: HTTP endpoints that frontend calls  
**WHERE**: `backend/src/aegis/api/routers/`  
**WHY**: Frontend needs to communicate with backend

#### Identity Router (`identity.py`)

**Endpoint**: `POST /identity/issue?ai_id=agent-name`  
**WHAT it does**: Creates a new AI agent identity  
**HOW**:
```python
1. Receives agent ID from frontend
2. Generates cryptographic key pair
3. Creates Agent record in database
4. Returns success/failure
```

**WHY**: Every AI agent needs a verified identity before it can do anything

---

#### Governance Router (`governance.py`)

**Endpoint**: `POST /governance/purge`  
**WHAT it does**: Emergency lockdown - revokes ALL agents  
**HOW**:
```python
1. Gets all agents from database
2. For each agent:
   a. Creates BreachInvestigation record (NEW!)
   b. Sets status = "REVOKED"
   c. Sets trust = 0.0
   d. Sets level = 0 (L0 Isolation)
3. Saves everything to database
4. Returns lockdown confirmation
```

**WHY**: In case of security breach, need to immediately stop all AI agents

---

#### Investigation Router (`investigation.py`) - NEW!

**Endpoint**: `GET /agents/{agent_id}/investigation`  
**WHAT it does**: Gets breach investigation details  
**HOW**:
```python
1. Receives agent ID
2. Queries BreachInvestigation table
3. Parses evidence JSON
4. Returns formatted investigation report
```

**WHY**: Users need to understand WHY an agent was revoked

**Endpoint**: `POST /agents/{agent_id}/restore`  
**WHAT it does**: Restores a revoked agent  
**HOW**:
```python
1. Receives agent ID
2. Updates agent: status="Active", trust=100.0, level=10
3. Updates investigation: status="RESTORED"
4. Saves to database
```

**WHY**: If investigation shows false positive, need to restore agent

---

### 3. Frontend Components

#### WorkloadNodes.jsx (Enhanced!)

**WHAT**: Displays all AI agents and their status  
**WHERE**: `frontend/src/components/WorkloadNodes.jsx`  
**WHY**: Users need to see which agents are running and their health

**HOW it works**:
```javascript
1. Fetches agents from API: GET /agents
2. For each agent, displays:
   - Agent ID
   - Trust score (colored: green=good, red=bad)
   - Status (Active, REVOKED)
   - Access level
3. If agent is REVOKED:
   - Makes card clickable
   - Shows "Click to view investigation" hint
4. When clicked:
   - Calls GET /agents/{id}/investigation
   - Opens InvestigationModal with details
```

**NEW BEHAVIOR**:
- **Before**: Just showed red indicators
- **After**: Clickable → Opens investigation modal

---

#### InvestigationModal.jsx - NEW!

**WHAT**: Modal showing why an agent was revoked  
**WHERE**: `frontend/src/components/InvestigationModal.jsx`  
**WHY**: Users need detailed forensic information

**WHAT it shows**:
```
┌─────────────────────────────────────┐
│ 🛡️ Breach Investigation            │
│ Agent ID: customer-bot-01           │
├─────────────────────────────────────┤
│ CRITICAL SEVERITY                   │
│ Status: UNDER_INVESTIGATION         │
├─────────────────────────────────────┤
│ Breach Type:                        │
│ GLOBAL_SECURITY_INCIDENT            │
│                                     │
│ How Detected:                       │
│ ✓ Manual intervention               │
│ ✓ System-wide threat assessment     │
│                                     │
│ Event Timeline:                     │
│ 🕐 09:47 - Global purge initiated   │
│                                     │
│ Previous State:                     │
│ Trust: 100% | Status: Active        │
│                                     │
│ RECOMMENDED ACTION:                 │
│ Keep revoked. Issue new identity.   │
├─────────────────────────────────────┤
│ [Restore Agent] [Confirm Breach]    │
└─────────────────────────────────────┘
```

**Actions**:
- **Restore Agent**: Calls `POST /agents/{id}/restore`
- **Confirm Breach**: Calls `POST /agents/{id}/confirm-breach`

---

## 🔄 Complete User Journey

### Scenario: Testing the System

**Step 1: Issue Agent Identity**
```
User → Identity Registry → "Issue New ID"
Frontend → POST /identity/issue?ai_id=test-bot
Backend → Creates Agent(id="test-bot", trust=100.0, status="Active")
Database → Stores agent record
Frontend → Shows success notification
```

**Step 2: Execute Global Purge**
```
User → Simulator Orchestrator → "Global Purge"
Frontend → Shows confirmation modal
User → Clicks "Execute Purge"
Frontend → POST /governance/purge
Backend → For each agent:
  1. Creates BreachInvestigation(
       agent_id="test-bot",
       breach_type="GLOBAL_SECURITY_INCIDENT",
       severity="CRITICAL",
       evidence={
         "previous_trust": 100.0,
         "previous_status": "Active",
         "detection_methods": ["Manual intervention"],
         "timeline": [{"event": "Global purge", "timestamp": ...}]
       }
     )
  2. Updates Agent(trust=0.0, status="REVOKED", level=0)
Database → Saves both records
Frontend → Refreshes data
```

**Step 3: View Investigation**
```
User → Workload Nodes → Clicks revoked agent (red card)
Frontend → GET /agents/test-bot/investigation
Backend → Queries BreachInvestigation table
Backend → Returns investigation details
Frontend → Opens InvestigationModal
User → Sees:
  - Why revoked (Global security incident)
  - How detected (Manual intervention)
  - Evidence timeline
  - Recommended action
```

**Step 4: Restore Agent**
```
User → Investigation Modal → "Restore Agent"
Frontend → Shows confirmation dialog
User → Confirms
Frontend → POST /agents/test-bot/restore
Backend → Updates Agent(trust=100.0, status="Active", level=10)
Backend → Updates BreachInvestigation(status="RESTORED")
Database → Saves changes
Frontend → Refreshes page
User → Sees agent is now Active with 100% trust
```

---

## 🎯 Why Each Design Decision

### Why Trust Scores?
**Problem**: How do we know if an AI is behaving properly?  
**Solution**: Trust score that degrades with bad behavior  
**Benefit**: Progressive isolation instead of immediate ban

### Why Breach Investigations?
**Problem**: Users don't know WHY agents were revoked  
**Solution**: Detailed forensic records with evidence  
**Benefit**: Informed decisions about restore vs. keep revoked

### Why Clickable Revoked Agents?
**Problem**: Static red indicators aren't actionable  
**Solution**: Make them interactive with investigation details  
**Benefit**: Users can investigate and take action immediately

### Why Pattern-Based Detection?
**Problem**: Can't access actual sensitive data  
**Solution**: Detect threats by intent patterns, not content  
**Benefit**: Privacy-preserving security

### Why Audit Logs?
**Problem**: Need compliance and forensics  
**Solution**: Tamper-proof cryptographic audit trail  
**Benefit**: Full accountability and replay capability

---

## 🔧 Technical Implementation Details

### Database Flow
```
SQLite Database (aegis.db)
├── agent table
│   └── Stores: id, trust, status, level, mode
├── breachinvestigation table (NEW!)
│   └── Stores: agent_id, breach_type, severity, evidence
├── auditlog table
│   └── Stores: intent, decision, reason, hashes
└── globalstats table
    └── Stores: interventions, pending_reviews
```

### API Communication
```
Frontend (React)          Backend (FastAPI)
    │                          │
    ├─ GET /agents ──────────→ │ Query database
    │                          │ Return agent list
    │ ←─────────────────────── │
    │                          │
    ├─ POST /governance/purge → │ Update all agents
    │                          │ Create investigations
    │ ←─────────────────────── │ Return success
    │                          │
    ├─ GET /agents/{id}/investigation → │ Query investigation
    │                          │ Parse evidence
    │ ←─────────────────────── │ Return details
```

### State Management
```
Frontend State:
- agents[] - List of all agents
- selectedAgent - Currently viewing agent
- investigation - Investigation details
- showModal - Modal visibility

Backend State:
- Database (persistent)
- In-memory cache (for performance)
- Session management
```

---

## 🎓 Key Concepts Explained

### 1. Zero-Trust Architecture
**What**: Never trust, always verify  
**How**: Every action requires explicit permission check  
**Why**: AI agents can be compromised at any time

### 2. Progressive Isolation
**What**: Gradually reduce access as trust drops  
**How**: Trust score → Access level mapping  
**Why**: Gives agents chance to recover from minor issues

### 3. Intent-Based Security
**What**: Block based on what agent wants to do, not data content  
**How**: Pattern matching on action types  
**Why**: Works without seeing sensitive data

### 4. Forensic Accountability
**What**: Complete audit trail of all decisions  
**How**: Cryptographic hash chain  
**Why**: Compliance and incident investigation

---

## 🚀 Summary: The Complete Picture

**AEGIS is a security control plane that:**

1. **Issues cryptographic identities** to AI agents
2. **Evaluates every action** against policies
3. **Maintains trust scores** based on behavior
4. **Blocks suspicious activities** using pattern detection
5. **Logs everything** in tamper-proof audit trail
6. **Creates investigations** when breaches occur
7. **Allows interactive review** of revoked agents
8. **Enables restoration** after investigation

**All without ever seeing the actual sensitive data the AI agents handle.**

It's like having a **security team** that:
- Checks credentials (identity)
- Verifies permissions (policy)
- Monitors behavior (trust)
- Investigates incidents (forensics)
- Makes informed decisions (restore/revoke)

**And it does this 24/7, automatically, for every single AI agent action.**
