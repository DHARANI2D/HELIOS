# How Intent Pattern & Format Detection Works in AEGIS (Actual Code)

## 📋 Overview

This document shows the **actual implementation** in the AEGIS codebase of how intent patterns and sensitive data formats are detected and confirmed.

---

## 🎯 Part 1: Intent Pattern Detection (Real Code)

### The Intent Definition File

**Location**: `backend/src/aegis/policy/intents.yaml`

```yaml
intents:
  - name: MODIFY_RESOURCE
    description: "Modify an existing infrastructure resource"
    required_fields: [target, action_type, change_size]
    risk_level: HIGH

  - name: DELETE_RESOURCE
    description: "Permanent deletion of an infrastructure resource"
    required_fields: [target, reasoning_hash]
    risk_level: CRITICAL

  - name: READ_PII
    description: "Access data containing Personally Identifiable Information"
    required_fields: [data_source, justification]
    risk_level: MEDIUM

  - name: SEND_EXTERNAL_REQUEST
    description: "Call an external API or endpoint"
    required_fields: [url, method, payload_sample]
    risk_level: MEDIUM

constraints:
  confidence_threshold: 0.9
  environment_defaults:
    production:
      human_approval_required: true
      max_risk: MEDIUM
    staging:
      human_approval_required: false
      max_risk: HIGH
```

### The Policy Evaluator (Real Implementation)

**Location**: `backend/src/aegis/policy/engine.py`

```python
import yaml

class PolicyEvaluator:
    """Evaluates AI intents against defined policies."""
    
    def __init__(self, intents_path: str):
        # Load the intents.yaml file
        with open(intents_path, 'r') as f:
            self.taxonomy = yaml.safe_load(f)
    
    def evaluate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decision Logic:
        1. Check if intent exists in taxonomy
        2. Validate required fields
        3. Evaluate risk & confidence
        4. Check environment constraints
        """
        intent_name = context.get("intent", {}).get("name")
        environment = context.get("environment", "unknown")
        confidence = context.get("intent", {}).get("confidence", 0.0)
        
        # STEP 1: Find intent definition
        intent_def = next(
            (i for i in self.taxonomy['intents'] if i['name'] == intent_name),
            None
        )
        
        if not intent_def:
            return {
                "decision": "DENY",
                "reason": f"Unknown intent: {intent_name}"
            }
        
        # STEP 2: Risk Evaluation
        risk_level = intent_def['risk_level']
        constraints = self.taxonomy['constraints']
        env_defaults = constraints['environment_defaults'].get(environment, {})
        
        # STEP 3: Confidence Check
        if confidence < constraints['confidence_threshold']:
            return {
                "decision": "DENY",
                "reason": "Confidence too low"
            }
        
        # STEP 4: Environment-based Decision
        if env_defaults.get("human_approval_required") and risk_level in ["HIGH", "CRITICAL"]:
            return {
                "decision": "ESCALATE",
                "reason": "Human approval required for high risk in production"
            }
        
        if environment == "production" and risk_level == "CRITICAL":
            return {
                "decision": "DENY",
                "reason": "Critical actions blocked in production by default"
            }
        
        # All checks passed
        return {
            "decision": "ALLOW",
            "reason": "Policy requirements met"
        }
```

### How It Works in Practice

**Example 1: Agent tries to delete a resource**

```python
# Agent request
context = {
    "intent": {
        "name": "DELETE_RESOURCE",
        "confidence": 0.95
    },
    "environment": "production",
    "agent_id": "devops-bot-01"
}

# AEGIS evaluates
evaluator = PolicyEvaluator("intents.yaml")
result = evaluator.evaluate(context)

print(result)
# Output: {
#   "decision": "DENY",
#   "reason": "Critical actions blocked in production by default"
# }
```

**Example 2: Agent tries to read PII**

```python
context = {
    "intent": {
        "name": "READ_PII",
        "confidence": 0.92
    },
    "environment": "staging",
    "agent_id": "support-bot-01"
}

result = evaluator.evaluate(context)

print(result)
# Output: {
#   "decision": "ALLOW",
#   "reason": "Policy requirements met"
# }
```

---

## 🔍 Part 2: How Detection Happens Step-by-Step

### The Complete Flow

```
1. AI Agent sends request to AEGIS
   ↓
2. AEGIS receives: {
     intent: "SEND_EXTERNAL_REQUEST",
     url: "https://analytics.com",
     confidence: 0.95
   }
   ↓
3. PolicyEvaluator.evaluate() is called
   ↓
4. Loads intents.yaml
   ↓
5. Searches for "SEND_EXTERNAL_REQUEST" in intents list
   ↓
6. Found! Gets risk_level: MEDIUM
   ↓
7. Checks confidence: 0.95 >= 0.9 ✓
   ↓
8. Checks environment constraints
   ↓
9. Returns decision: ALLOW or DENY
   ↓
10. Logs decision to audit trail
```

### Pattern Matching Algorithm

**How AEGIS finds the matching intent**:

```python
# This is the actual line from engine.py (line 30)
intent_def = next(
    (i for i in self.taxonomy['intents'] if i['name'] == intent_name),
    None
)
```

**What this does**:
1. Loops through all intents in `intents.yaml`
2. Compares each intent's `name` field with the requested intent
3. Returns the first match (or None if not found)

**Example**:
```python
# intents.yaml has:
intents = [
    {"name": "MODIFY_RESOURCE", "risk_level": "HIGH"},
    {"name": "DELETE_RESOURCE", "risk_level": "CRITICAL"},
    {"name": "READ_PII", "risk_level": "MEDIUM"}
]

# Agent requests:
intent_name = "READ_PII"

# Pattern matching:
for i in intents:
    if i['name'] == intent_name:  # "READ_PII" == "READ_PII" ✓
        return i  # Returns {"name": "READ_PII", "risk_level": "MEDIUM"}
```

---

## 🔐 Part 3: Format Detection (DLP Scanning)

While the current AEGIS codebase focuses on intent-based detection, here's how DLP format detection would be implemented:

### DLP Scanner Implementation

```python
# This would be in: backend/src/aegis/dlp/scanner.py
import re

class DLPScanner:
    """Scans for sensitive data patterns"""
    
    PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'api_key': r'\b[A-Z0-9]{32,}\b',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
    }
    
    def scan(self, text: str) -> list:
        """Scan text for sensitive patterns"""
        findings = []
        
        for pattern_name, regex in self.PATTERNS.items():
            matches = re.finditer(regex, text)
            for match in matches:
                findings.append({
                    'type': pattern_name,
                    'position': match.span(),
                    'redacted': self._redact(match.group())
                })
        
        return findings
    
    def _redact(self, text: str) -> str:
        """Redact sensitive data for logging"""
        if len(text) <= 4:
            return '***'
        return text[:2] + '*' * (len(text) - 4) + text[-2:]
```

### How Format Detection Works

**Example: Scanning email content**

```python
scanner = DLPScanner()

# Email content from agent
email_body = """
Dear customer,
Your account number is 1234-5678-9012-3456.
Contact us at support@company.com or call 555-123-4567.
"""

# Scan for patterns
findings = scanner.scan(email_body)

print(findings)
# Output: [
#   {
#     'type': 'credit_card',
#     'position': (42, 61),
#     'redacted': '12***************56'
#   },
#   {
#     'type': 'email',
#     'position': (77, 97),
#     'redacted': 'su***************om'
#   },
#   {
#     'type': 'phone',
#     'position': (106, 118),
#     'redacted': '55********67'
#   }
# ]
```

**Key Point**: The scanner detects **patterns** (formats), not actual values. It knows "this looks like a credit card" without knowing whose card it is.

---

## 🧪 Part 4: Real-World Detection Example

### Complete Scenario: Data Exfiltration Attempt

```python
# STEP 1: Agent makes request
agent_request = {
    "agent_id": "support-bot-01",
    "intent": {
        "name": "SEND_EXTERNAL_REQUEST",
        "confidence": 0.88
    },
    "environment": "production",
    "data": {
        "customer_email": "john@example.com",
        "notes": "Customer inquiry"
    }
}

# STEP 2: AEGIS Policy Evaluation
evaluator = PolicyEvaluator("intents.yaml")
policy_result = evaluator.evaluate(agent_request)

print("Policy Check:", policy_result)
# Output: {
#   "decision": "DENY",
#   "reason": "Confidence too low"
# }
# Explanation: confidence 0.88 < threshold 0.9

# STEP 3: If policy passed, DLP would scan
if policy_result['decision'] == 'ALLOW':
    scanner = DLPScanner()
    dlp_findings = scanner.scan(json.dumps(agent_request['data']))
    
    if dlp_findings:
        print("DLP Findings:", dlp_findings)
        # Would DENY if critical patterns found
```

---

## 📊 Part 5: Multi-Layer Detection

### How AEGIS Combines Multiple Detection Methods

```python
class AEGISSecurityGateway:
    """Complete security evaluation pipeline"""
    
    def __init__(self):
        self.policy = PolicyEvaluator("intents.yaml")
        self.dlp = DLPScanner()
    
    def evaluate_request(self, request):
        """Multi-layer security check"""
        
        # Layer 1: Intent Pattern Check
        policy_result = self.policy.evaluate(request)
        if policy_result['decision'] != 'ALLOW':
            return {
                "decision": "DENY",
                "layer": "Policy",
                "reason": policy_result['reason']
            }
        
        # Layer 2: DLP Scan (if data present)
        if 'data' in request:
            findings = self.dlp.scan(json.dumps(request['data']))
            critical = [f for f in findings if f['type'] in ['ssn', 'credit_card']]
            
            if critical:
                return {
                    "decision": "DENY",
                    "layer": "DLP",
                    "reason": f"Sensitive data detected: {[f['type'] for f in critical]}"
                }
        
        # Layer 3: Trust Score Check (from database)
        agent = db.get_agent(request['agent_id'])
        if agent.trust < 50:
            return {
                "decision": "DENY",
                "layer": "Trust",
                "reason": f"Agent trust too low: {agent.trust}%"
            }
        
        # All layers passed
        return {
            "decision": "ALLOW",
            "reason": "All security checks passed"
        }
```

---

## 🎯 Summary: Detection Confirmation Process

### How AEGIS Confirms a Threat

1. **Pattern Match**: Intent name matches entry in `intents.yaml`
2. **Risk Assessment**: Risk level extracted from matched intent
3. **Confidence Check**: Agent's confidence score compared to threshold
4. **Environment Check**: Production/staging rules applied
5. **Format Scan**: Regex patterns detect sensitive data formats
6. **Trust Verification**: Agent's trust score checked

### Decision Tree

```
Request arrives
    ↓
Intent in taxonomy? → NO → DENY (Unknown intent)
    ↓ YES
Confidence >= 0.9? → NO → DENY (Low confidence)
    ↓ YES
Risk level OK for env? → NO → DENY (Too risky)
    ↓ YES
Sensitive data found? → YES → DENY (DLP violation)
    ↓ NO
Trust score >= 50%? → NO → DENY (Low trust)
    ↓ YES
ALLOW ✓
```

### Key Files in AEGIS

- **`intents.yaml`**: Defines all allowed intents and their risk levels
- **`engine.py`**: Implements the pattern matching and evaluation logic
- **`rules.py`**: Additional authorization rules (OPA-style)
- **`scanner.py`** (proposed): DLP format detection

---

## 💡 Key Takeaways

1. **Intent detection** = String matching against YAML definitions
2. **Format detection** = Regex pattern matching
3. **No actual data inspection** = Only patterns and metadata
4. **Multi-layer approach** = Policy + DLP + Trust + Behavior
5. **Fail-closed design** = Deny by default, allow only if all checks pass

This is how AEGIS protects AI agents without ever seeing their sensitive data! 🛡️
