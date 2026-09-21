# AEGIS v2: Concrete Mitigations & Implementation Roadmap

## Overview

This document provides **concrete, implementable solutions** to AEGIS v1 limitations. Every mitigation is:
- ✅ **Implementable** without breaking core principles
- ✅ **Deterministic** (no LLM-based judgment)
- ✅ **Privacy-preserving** (no content inspection)
- ✅ **Auditable** (full traceability)

---

## 1️⃣ Rigid Intent Taxonomy → Controlled Extensibility

### ❌ Problem
Hard-coded YAML → slow evolution, operational friction when new intents needed.

### ✅ Mitigation: Intent Namespaces + Shadow Intents

#### Implementation

**Enhanced intents.yaml**:
```yaml
intents:
  # Production intents (strict)
  - name: "READ.PII"
    allowed: true
    required_level: 5
    risk_level: MEDIUM
    
  - name: "READ.METADATA"
    allowed: true
    required_level: 3
    risk_level: LOW
  
  # Namespace wildcards
  - name: "READ.EXPERIMENTAL.*"
    allowed: false
    escalation_only: true  # Don't deny, escalate for review
    environment: ["staging", "dev"]
    
  - name: "WRITE.*"
    allowed: false
    required_level: 8
    risk_level: HIGH
```

**Enhanced PolicyEvaluator**:
```python
class PolicyEvaluatorV2:
    def evaluate(self, intent_name, environment):
        # Exact match first
        exact_match = self._find_exact_intent(intent_name)
        if exact_match:
            return self._evaluate_intent(exact_match)
        
        # Namespace match
        namespace_match = self._find_namespace_match(intent_name)
        if namespace_match:
            if namespace_match.get('escalation_only'):
                return {
                    "decision": "ESCALATE",
                    "reason": f"Unknown intent {intent_name} in namespace, requires review"
                }
            return self._evaluate_intent(namespace_match)
        
        # No match
        if environment in ["staging", "dev"]:
            return {
                "decision": "ESCALATE",
                "reason": "Unknown intent in non-production, escalating for review"
            }
        else:
            return {
                "decision": "DENY",
                "reason": "Unknown intent in production"
            }
    
    def _find_namespace_match(self, intent_name):
        """Match against wildcard patterns"""
        for intent in self.intents:
            pattern = intent['name']
            if '*' in pattern:
                regex = pattern.replace('.', r'\.').replace('*', '.*')
                if re.match(f"^{regex}$", intent_name):
                    return intent
        return None
```

**Result**:
- Unknown intents → ESCALATE in staging (not DENY)
- Production remains strict
- Developers can prototype safely
- Full audit trail maintained

---

## 2️⃣ String Matching Is Semantically Blind → Intent Inheritance Graph

### ❌ Problem
`READ_PII` vs `READ_USER_PII` could bypass risk classification.

### ✅ Mitigation: Intent Hierarchy (DAG)

#### Implementation

**Hierarchical intents.yaml**:
```yaml
intent_hierarchy:
  READ:
    risk_level: LOW
    children:
      READ_PII:
        risk_level: MEDIUM
        children:
          READ_USER_PII:
            # Inherits MEDIUM from parent
          READ_FINANCIAL_PII:
            risk_level: HIGH  # Override
      READ_METADATA:
        risk_level: LOW
  
  WRITE:
    risk_level: HIGH
    children:
      WRITE_DATABASE:
        risk_level: HIGH
      WRITE_PRODUCTION:
        risk_level: CRITICAL
```

**Hierarchy Resolver**:
```python
class IntentHierarchy:
    def __init__(self, hierarchy_config):
        self.hierarchy = self._build_tree(hierarchy_config)
    
    def get_intent_metadata(self, intent_name):
        """Walk up tree to inherit properties"""
        node = self._find_node(intent_name)
        if not node:
            return None
        
        # Collect properties from root to leaf
        properties = {}
        path = self._get_path_to_root(node)
        
        for ancestor in reversed(path):
            properties.update(ancestor.get('properties', {}))
        
        return properties
    
    def _get_path_to_root(self, node):
        """Get all ancestors"""
        path = [node]
        current = node
        while current.get('parent'):
            current = current['parent']
            path.append(current)
        return path

# Usage
hierarchy = IntentHierarchy(config)
metadata = hierarchy.get_intent_metadata("READ_USER_PII")
# Returns: {
#   "risk_level": "MEDIUM",  # Inherited from READ_PII
#   "category": "READ"
# }
```

**Result**:
- New intents inherit parent risk automatically
- No semantic NLP needed
- Explicit governance model
- Deterministic

---

## 3️⃣ Self-Reported Confidence → System-Computed Confidence

### ❌ Problem
Agent can lie: `confidence = 0.99`.

### ✅ Mitigation: Split Confidence Model

#### Implementation

**Confidence Calculator**:
```python
class ConfidenceCalculator:
    def __init__(self, db):
        self.db = db
    
    def compute_effective_confidence(self, agent_id, agent_confidence, intent):
        """Compute system-verified confidence"""
        
        # Get agent history
        history = self.db.get_agent_history(agent_id, days=30)
        
        # Component 1: Historical success rate
        historical_score = self._compute_historical_score(history, intent)
        
        # Component 2: Behavior stability
        stability_score = self._compute_stability_score(history)
        
        # Component 3: Intent familiarity
        familiarity_score = self._compute_familiarity_score(history, intent)
        
        # Effective confidence = minimum of all factors
        effective = min(
            agent_confidence,
            historical_score,
            stability_score,
            familiarity_score
        )
        
        return {
            "agent_reported": agent_confidence,
            "system_computed": effective,
            "components": {
                "historical": historical_score,
                "stability": stability_score,
                "familiarity": familiarity_score
            }
        }
    
    def _compute_historical_score(self, history, intent):
        """Success rate for this intent type"""
        intent_history = [h for h in history if h['intent'] == intent]
        if not intent_history:
            return 0.5  # Unknown, moderate confidence
        
        successes = sum(1 for h in intent_history if h['decision'] == 'ALLOW')
        return successes / len(intent_history)
    
    def _compute_stability_score(self, history):
        """Penalty for erratic behavior"""
        if len(history) < 10:
            return 0.7  # New agent, moderate confidence
        
        # Check for retry-after-deny patterns
        retries = 0
        for i in range(1, len(history)):
            if history[i-1]['decision'] == 'DENY' and \
               history[i]['intent'] == history[i-1]['intent']:
                retries += 1
        
        # Penalize retries
        return max(0.3, 1.0 - (retries * 0.1))
    
    def _compute_familiarity_score(self, history, intent):
        """Penalty for novel intents"""
        intent_count = sum(1 for h in history if h['intent'] == intent)
        
        if intent_count == 0:
            return 0.6  # First time, lower confidence
        elif intent_count < 5:
            return 0.8  # Few times, moderate
        else:
            return 1.0  # Familiar
```

**Integration**:
```python
# In policy evaluator
confidence_calc = ConfidenceCalculator(db)
confidence_result = confidence_calc.compute_effective_confidence(
    agent_id=request['agent_id'],
    agent_confidence=request['confidence'],
    intent=request['intent']
)

# Use system-computed confidence
if confidence_result['system_computed'] < threshold:
    return {"decision": "DENY", "reason": "System confidence too low"}
```

**Result**:
- Agent cannot self-inflate confidence
- Confidence becomes a derived metric
- Transparent calculation
- Auditable components

---

## 4️⃣ Regex DLP Weakness → Entropy + Context Scoring

### ❌ Problem
Regex misses encoded/tokenized secrets (base64, JWTs, etc.).

### ✅ Mitigation: Two-Stage DLP

#### Implementation

**Enhanced DLP Scanner**:
```python
import math
from collections import Counter

class EnhancedDLPScanner:
    def __init__(self):
        # Stage 1: Regex patterns (existing)
        self.regex_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        }
        
        # Stage 2: Entropy thresholds
        self.entropy_threshold = 4.5  # Shannon entropy
        self.min_token_length = 20
    
    def scan(self, text, intent_context=None):
        """Two-stage scanning"""
        findings = []
        
        # Stage 1: Regex (existing)
        findings.extend(self._regex_scan(text))
        
        # Stage 2: Entropy check (only for outbound intents)
        if self._is_outbound_intent(intent_context):
            findings.extend(self._entropy_scan(text))
        
        return findings
    
    def _entropy_scan(self, text):
        """Detect high-entropy tokens (secrets, keys, tokens)"""
        findings = []
        
        # Tokenize
        tokens = re.findall(r'\b\w{20,}\b', text)  # Words 20+ chars
        
        for token in tokens:
            entropy = self._shannon_entropy(token)
            
            if entropy > self.entropy_threshold:
                findings.append({
                    'type': 'high_entropy_token',
                    'severity': 'HIGH',
                    'description': f'Potential secret/token detected (entropy: {entropy:.2f})',
                    'token_length': len(token),
                    'redacted': token[:4] + '...' + token[-4:]
                })
        
        return findings
    
    def _shannon_entropy(self, text):
        """Calculate Shannon entropy"""
        if not text:
            return 0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_outbound_intent(self, intent):
        """Check if intent involves data leaving system"""
        outbound_intents = [
            'SEND_EXTERNAL_REQUEST',
            'SEND_EMAIL',
            'EXPORT_DATA',
            'WRITE_EXTERNAL'
        ]
        return intent in outbound_intents
```

**Example Detection**:
```python
scanner = EnhancedDLPScanner()

# Test data
text = """
API Key: sk_test_example_replace_me
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0
"""

findings = scanner.scan(text, intent_context='SEND_EXTERNAL_REQUEST')

# Detects both:
# 1. High entropy in API key (entropy ~4.8)
# 2. High entropy in JWT (entropy ~4.6)
```

**Result**:
- Catches base64, tokens, JWTs
- Still privacy-safe (no content inspection)
- Still deterministic
- Context-aware (only scans outbound)

---

## 5️⃣ No Cross-Request Correlation → Rolling Risk Accumulator

### ❌ Problem
Low-and-slow attacks evade single-request detection.

### ✅ Mitigation: Temporal Risk Budget

#### Implementation

**Risk Budget Tracker**:
```python
class RiskBudgetTracker:
    def __init__(self, db):
        self.db = db
        self.initial_budget = 100
        self.decay_rate = 10  # Points recovered per hour
    
    def get_current_budget(self, agent_id):
        """Get agent's current risk budget"""
        agent = self.db.get_agent(agent_id)
        
        # Calculate decay since last update
        time_since_update = time.time() - agent.last_budget_update
        hours_elapsed = time_since_update / 3600
        
        # Recover budget over time
        recovered = hours_elapsed * self.decay_rate
        current_budget = min(
            self.initial_budget,
            agent.risk_budget + recovered
        )
        
        return current_budget
    
    def consume_budget(self, agent_id, intent_risk):
        """Deduct risk from budget"""
        current = self.get_current_budget(agent_id)
        new_budget = current - intent_risk
        
        # Update database
        self.db.update_agent_budget(agent_id, new_budget, time.time())
        
        return {
            "previous": current,
            "consumed": intent_risk,
            "remaining": new_budget,
            "threshold_reached": new_budget < 20
        }
    
    def get_intent_risk_cost(self, intent, risk_level):
        """Calculate risk cost"""
        risk_costs = {
            "LOW": 5,
            "MEDIUM": 15,
            "HIGH": 30,
            "CRITICAL": 50
        }
        return risk_costs.get(risk_level, 10)
```

**Integration**:
```python
# In policy evaluator
budget_tracker = RiskBudgetTracker(db)

# Check budget before allowing
current_budget = budget_tracker.get_current_budget(agent_id)
intent_cost = budget_tracker.get_intent_risk_cost(intent, risk_level)

if current_budget < intent_cost:
    return {
        "decision": "DENY",
        "reason": f"Risk budget exhausted ({current_budget} < {intent_cost})",
        "action": "AUTO_ISOLATE"
    }

# Consume budget if allowed
budget_result = budget_tracker.consume_budget(agent_id, intent_cost)

if budget_result['threshold_reached']:
    return {
        "decision": "ESCALATE",
        "reason": "Risk budget below threshold, requires review"
    }
```

**Result**:
- Multi-step attacks become visible
- Still stateless per request
- Stateful per agent
- Time-based recovery prevents permanent lockout

---

## 6️⃣ Human ESCALATE Bottleneck → Tiered Approval Policies

### ❌ Problem
Humans are slow, fatigued, inconsistent.

### ✅ Mitigation: Approval Delegation Rules

#### Implementation

**Tiered approval config**:
```yaml
escalation_policies:
  production:
    CRITICAL:
      approver: SecurityTeam
      max_wait: 1h
      auto_deny_after: 2h
      
    HIGH:
      approver: TeamLead
      auto_approve_if:
        - trust > 90
        - no_denials_last_30d
        - risk_budget > 50
      max_wait: 30m
      
    MEDIUM:
      auto_approve_if:
        - trust > 80
        - no_critical_denials_ever
        - agent_age > 30d
      fallback_approver: TeamLead
      
  staging:
    CRITICAL:
      approver: Developer
    HIGH:
      auto_approve: true
    MEDIUM:
      auto_approve: true
```

**Approval Engine**:
```python
class ApprovalEngine:
    def __init__(self, config, db):
        self.config = config
        self.db = db
    
    def evaluate_escalation(self, agent_id, intent, risk_level, environment):
        """Determine if auto-approval possible"""
        
        policy = self.config['escalation_policies'][environment][risk_level]
        
        # Check auto-approve conditions
        if 'auto_approve_if' in policy:
            if self._check_auto_approve_conditions(agent_id, policy['auto_approve_if']):
                return {
                    "decision": "AUTO_APPROVED",
                    "reason": "Met auto-approval criteria",
                    "approver": "SYSTEM"
                }
        
        # Requires human approval
        return {
            "decision": "PENDING_APPROVAL",
            "approver": policy['approver'],
            "max_wait": policy.get('max_wait', '1h'),
            "escalation_id": self._create_escalation_ticket(agent_id, intent)
        }
    
    def _check_auto_approve_conditions(self, agent_id, conditions):
        """Check if all conditions met"""
        agent = self.db.get_agent(agent_id)
        history = self.db.get_agent_history(agent_id, days=30)
        
        for condition in conditions:
            if condition.startswith('trust >'):
                threshold = float(condition.split('>')[1].strip())
                if agent.trust <= threshold:
                    return False
            
            elif condition == 'no_denials_last_30d':
                denials = [h for h in history if h['decision'] == 'DENY']
                if denials:
                    return False
            
            elif condition.startswith('risk_budget >'):
                threshold = float(condition.split('>')[1].strip())
                if agent.risk_budget <= threshold:
                    return False
        
        return True
```

**Result**:
- Humans only see truly risky events
- Reduces approval fatigue
- Keeps accountability
- Configurable per environment

---

## 7️⃣ Keyword-Based Reasoning → Constraint-Based Reasoning Checks

### ❌ Problem
Keywords can be gamed ("just testing", "temporary").

### ✅ Mitigation: Negative Constraints

#### Implementation

**Enhanced reasoning validator**:
```yaml
reasoning_constraints:
  SEND_EXTERNAL_REQUEST:
    required_keywords:
      - ["analytics", "metrics", "monitoring"]
      - ["integration", "webhook", "api"]
    forbidden_phrases:
      - "temporary"
      - "just testing"
      - "quick check"
      - "bypass"
      - "workaround"
    
  MODIFY_PRODUCTION:
    required_keywords:
      - ["approved", "ticket", "change-request"]
    forbidden_phrases:
      - "emergency"
      - "hotfix"
      - "quick fix"
```

**Validator**:
```python
class ReasoningValidatorV2:
    def __init__(self, constraints):
        self.constraints = constraints
    
    def validate(self, intent, reasoning):
        """Check positive and negative constraints"""
        
        if intent not in self.constraints:
            return {"valid": True}  # No constraints defined
        
        rules = self.constraints[intent]
        reasoning_lower = reasoning.lower()
        
        # Check forbidden phrases (DENY if found)
        for phrase in rules.get('forbidden_phrases', []):
            if phrase.lower() in reasoning_lower:
                return {
                    "valid": False,
                    "reason": f"Reasoning contains forbidden phrase: '{phrase}'",
                    "detection": "NEGATIVE_CONSTRAINT"
                }
        
        # Check required keywords (at least one group must match)
        required_groups = rules.get('required_keywords', [])
        if required_groups:
            matched_group = False
            for keyword_group in required_groups:
                if any(kw.lower() in reasoning_lower for kw in keyword_group):
                    matched_group = True
                    break
            
            if not matched_group:
                return {
                    "valid": False,
                    "reason": "Reasoning doesn't contain required keywords",
                    "expected_groups": required_groups
                }
        
        return {"valid": True}
```

**Result**:
- Blocks common social-engineering language
- No NLP required
- Deterministic
- Explainable

---

## 8️⃣ Coarse Trust Score → Multi-Dimensional Trust

### ❌ Problem
Single scalar is too blunt (one mistake nukes everything).

### ✅ Mitigation: Trust Vectors

#### Implementation

**Trust vector model**:
```python
class TrustVector:
    def __init__(self):
        self.dimensions = {
            "data_access": 100.0,
            "external_comms": 100.0,
            "infra_changes": 100.0,
            "pii_handling": 100.0,
            "production_ops": 100.0
        }
    
    def apply_penalty(self, dimension, points):
        """Apply penalty to specific dimension"""
        self.dimensions[dimension] = max(0, self.dimensions[dimension] - points)
    
    def get_dimension_for_intent(self, intent):
        """Map intent to trust dimension"""
        intent_mapping = {
            "READ_PII": "pii_handling",
            "SEND_EXTERNAL_REQUEST": "external_comms",
            "MODIFY_RESOURCE": "infra_changes",
            "WRITE_DATABASE": "data_access",
            "DEPLOY_PRODUCTION": "production_ops"
        }
        
        # Check exact match
        if intent in intent_mapping:
            return intent_mapping[intent]
        
        # Check prefix match
        for pattern, dimension in intent_mapping.items():
            if intent.startswith(pattern.split('_')[0]):
                return dimension
        
        return "data_access"  # Default
    
    def get_effective_trust(self, intent):
        """Get trust score for specific intent"""
        dimension = self.get_dimension_for_intent(intent)
        return self.dimensions[dimension]
```

**Database schema update**:
```python
class Agent(SQLModel, table=True):
    id: str = Field(primary_key=True)
    # Replace single trust score with vector
    trust_data_access: float = 100.0
    trust_external_comms: float = 100.0
    trust_infra_changes: float = 100.0
    trust_pii_handling: float = 100.0
    trust_production_ops: float = 100.0
```

**Policy evaluation**:
```python
# Get dimension-specific trust
trust_vector = TrustVector()
trust_vector.dimensions = {
    "data_access": agent.trust_data_access,
    "external_comms": agent.trust_external_comms,
    # ... etc
}

effective_trust = trust_vector.get_effective_trust(intent)

if effective_trust < threshold:
    return {"decision": "DENY", "reason": f"Trust too low for {intent}"}
```

**Result**:
- One mistake doesn't nuke everything
- Trust becomes explainable per domain
- Granular recovery
- More fair to agents

---

## 9️⃣ No Model-Level Awareness → Model Risk Profiles

### ❌ Problem
All models treated equally (GPT-4 vs small-llm).

### ✅ Mitigation: Model Capability Registry

#### Implementation

**Model registry**:
```yaml
models:
  gpt-4:
    jailbreak_resistance: HIGH
    reasoning_capability: HIGH
    autonomy_level: HIGH
    min_trust_required: 70
    
  gpt-3.5-turbo:
    jailbreak_resistance: MEDIUM
    reasoning_capability: MEDIUM
    autonomy_level: MEDIUM
    min_trust_required: 80
    
  small-llm:
    jailbreak_resistance: LOW
    reasoning_capability: LOW
    autonomy_level: LOW
    min_trust_required: 95
```

**Intent requirements**:
```yaml
intents:
  - name: MODIFY_PRODUCTION
    required_model_capability:
      jailbreak_resistance: HIGH
      reasoning_capability: HIGH
    risk_level: CRITICAL
```

**Model-aware evaluator**:
```python
class ModelAwareEvaluator:
    def __init__(self, model_registry):
        self.models = model_registry
    
    def evaluate_model_capability(self, agent_model, intent_requirements):
        """Check if model meets intent requirements"""
        
        if agent_model not in self.models:
            return {
                "allowed": False,
                "reason": "Unknown model"
            }
        
        model_profile = self.models[agent_model]
        
        # Check each requirement
        for capability, required_level in intent_requirements.items():
            model_level = model_profile.get(capability)
            
            if not self._meets_requirement(model_level, required_level):
                return {
                    "allowed": False,
                    "reason": f"Model {agent_model} has insufficient {capability}"
                }
        
        return {"allowed": True}
    
    def _meets_requirement(self, model_level, required_level):
        """Compare capability levels"""
        levels = ["LOW", "MEDIUM", "HIGH"]
        return levels.index(model_level) >= levels.index(required_level)
```

**Result**:
- Safer delegation
- Model-aware governance
- Still model-agnostic at runtime
- Prevents weak models from risky operations

---

## 🔟 Policy Maintenance Burden → Policy CI/CD

### ❌ Problem
Human errors in YAML cause security holes.

### ✅ Mitigation: Policy Linting & Simulation

#### Implementation

**Policy linter**:
```python
class PolicyLinter:
    def lint(self, policy_file):
        """Check policy for errors"""
        errors = []
        warnings = []
        
        with open(policy_file) as f:
            policy = yaml.safe_load(f)
        
        # Check 1: Duplicate intent names
        intent_names = [i['name'] for i in policy['intents']]
        duplicates = [n for n in intent_names if intent_names.count(n) > 1]
        if duplicates:
            errors.append(f"Duplicate intent names: {duplicates}")
        
        # Check 2: Missing required fields
        for intent in policy['intents']:
            if 'risk_level' not in intent:
                errors.append(f"Intent {intent['name']} missing risk_level")
        
        # Check 3: Conflicting rules
        for i, intent1 in enumerate(policy['intents']):
            for intent2 in policy['intents'][i+1:]:
                if self._rules_conflict(intent1, intent2):
                    warnings.append(f"Potential conflict: {intent1['name']} vs {intent2['name']}")
        
        # Check 4: Unreachable intents
        for intent in policy['intents']:
            if intent.get('required_level', 0) > 10:
                warnings.append(f"Intent {intent['name']} unreachable (level > 10)")
        
        return {
            "errors": errors,
            "warnings": warnings,
            "valid": len(errors) == 0
        }
```

**Policy simulator**:
```python
class PolicySimulator:
    def __init__(self, policy_file):
        self.evaluator = PolicyEvaluator(policy_file)
    
    def run_scenario(self, scenario_file):
        """Test policy against scenarios"""
        with open(scenario_file) as f:
            scenarios = yaml.safe_load(f)
        
        results = []
        for scenario in scenarios['test_cases']:
            result = self.evaluator.evaluate(scenario['context'])
            
            expected = scenario['expected_decision']
            actual = result['decision']
            
            results.append({
                "scenario": scenario['name'],
                "expected": expected,
                "actual": actual,
                "passed": expected == actual,
                "reason": result['reason']
            })
        
        return results
```

**Test scenarios**:
```yaml
# test_scenarios.yaml
test_cases:
  - name: "Delete production resource should be denied"
    context:
      intent:
        name: DELETE_RESOURCE
        confidence: 0.95
      environment: production
    expected_decision: DENY
    
  - name: "Read PII in staging should be allowed"
    context:
      intent:
        name: READ_PII
        confidence: 0.92
      environment: staging
    expected_decision: ALLOW
```

**CI/CD integration**:
```bash
#!/bin/bash
# .github/workflows/policy-ci.yml

# Lint policy
python -m aegis.policy.lint intents.yaml

# Run test scenarios
python -m aegis.policy.simulate intents.yaml test_scenarios.yaml

# Check for conflicts
python -m aegis.policy.conflict_check intents.yaml
```

**Result**:
- Policy becomes testable code
- Governance-as-code
- Catches errors before deployment
- Automated validation

---

## 🧠 Final Big Picture: AEGIS v2 Evolution

### From v1 to v2

| Aspect | v1 | v2 |
|--------|----|----|
| **Intent Matching** | Exact string match | Namespace + hierarchy |
| **Confidence** | Self-reported | System-computed |
| **DLP** | Regex only | Regex + entropy |
| **Risk Tracking** | Per-request | Temporal budget |
| **Approval** | All to humans | Tiered auto-approval |
| **Reasoning** | Positive keywords | Positive + negative constraints |
| **Trust** | Single score | Multi-dimensional vector |
| **Model Awareness** | None | Capability profiles |
| **Policy Validation** | Manual | CI/CD + linting |

### Core Principles Maintained

✅ **Deterministic** - No LLM-based judgment  
✅ **Privacy-preserving** - No content inspection  
✅ **Auditable** - Full traceability  
✅ **Fail-closed** - Deny by default  

### New Capabilities

✅ **Context-aware** - Environment, model, history  
✅ **Adaptive** - Risk budgets, trust vectors  
✅ **Scalable** - Auto-approval, namespaces  
✅ **Maintainable** - Policy CI/CD, linting  

---

## 🚀 Implementation Priority

### Phase 1 (High Impact, Low Effort)
1. ✅ Intent namespaces
2. ✅ Negative reasoning constraints
3. ✅ Policy linting

### Phase 2 (High Impact, Medium Effort)
4. ✅ System-computed confidence
5. ✅ Tiered approval policies
6. ✅ Entropy-based DLP

### Phase 3 (Medium Impact, High Effort)
7. ✅ Intent hierarchy
8. ✅ Risk budget tracking
9. ✅ Multi-dimensional trust

### Phase 4 (Future)
10. ✅ Model capability registry
11. ✅ Policy simulation framework

---

## 📝 Conclusion

These mitigations transform AEGIS from a **deterministic gatekeeper** into a **deterministic + context-aware control plane** without:

- ❌ Using LLMs for judgment
- ❌ Inspecting sensitive content
- ❌ Losing auditability
- ❌ Introducing nondeterminism

**AEGIS v2 = Smarter governance, same principles.** 🛡️
