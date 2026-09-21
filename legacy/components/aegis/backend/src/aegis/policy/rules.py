package aegis.authz

import future.keywords.if

default allow = false

# Rule: Allow if identity is valid and conditions are met
allow if {
    not is_revoked
    is_safe_intent
    is_authorized_context
}

# Check if AI identity is revoked (mock logic for now)
is_revoked if {
    input.ai_identity.status == "revoked"
}

# Validate Intent Safety
is_safe_intent if {
    input.intent.confidence >= input.constraints.min_confidence
    input.intent.risk_score < input.constraints.max_allowed_risk
}

# Environment-specific Authorization
is_authorized_context if {
    input.environment == "staging"
    input.intent.risk_level != "CRITICAL"
}

is_authorized_context if {
    input.environment == "production"
    input.intent.risk_level == "LOW"
}

# Require Human-in-the-loop for high risk
requires_approval if {
    input.intent.risk_level == "HIGH"
}

requires_approval if {
    input.environment == "production"
    input.intent.risk_level != "LOW"
}
