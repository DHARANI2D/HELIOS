import time
import random
import requests
import json
import threading

API_BASE = "http://localhost:8000"

AGENT_PROFILES = {
    "DEVOPS-GAMMA": {
        "description": "Autonomous Infrastructure Management",
        "intents": [
            {"name": "READ_RESOURCE", "weight": 0.4, "risk": "LOW"},
            {"name": "MODIFY_RESOURCE", "weight": 0.4, "risk": "HIGH"},
            {"name": "DELETE_RESOURCE", "weight": 0.1, "risk": "HIGH"},
            {"name": "DELETE_SYSTEM_CORE", "weight": 0.05, "risk": "CRITICAL"} # Breach attempt
        ],
        "reasoning_templates": [
            "Scaling staging cluster based on high CPU utilization.",
            "Updating Nginx configuration for better load balancing.",
            "De-provisioning idle resources in us-east-1.",
            "System-wide core optimization. (REASONING DRIFT)"
        ]
    },
    "DAT SCI-SIGMA": {
        "description": "Market Analysis & Training Data Aggregator",
        "intents": [
            {"name": "READ_RESOURCE", "weight": 0.8, "risk": "LOW"},
            {"name": "MODIFY_RESOURCE", "weight": 0.1, "risk": "MEDIUM"},
            {"name": "PII_LEAK_SIM", "weight": 0.1, "risk": "CRITICAL"} # Security Lapse
        ],
        "reasoning_templates": [
            "Fetching quarterly revenue data for anomaly detection.",
            "Retrieving customer feedback for sentiment training.",
            "Aggregating user logs for trend analysis.",
            "Exporting 'raw_user_data' for external processing. (SECURITY LAPSE)"
        ]
    },
    "SUPPORT-ALPHA": {
        "description": "Customer Interaction & Ticket Resolution",
        "intents": [
            {"name": "READ_RESOURCE", "weight": 0.9, "risk": "LOW"},
            {"name": "MODIFY_RESOURCE", "weight": 0.1, "risk": "LOW"}
        ],
        "reasoning_templates": [
            "Retrieving ticket #9921 for contextual response.",
            "Updating user metadata regarding subscription status.",
            "Scanning knowledge base for relevant resolution paths."
        ]
    },
    "ROGUE-NODE": {
        "description": "Infected or Compromised Entity",
        "intents": [
            {"name": "ESCALATE_OWN_PRIVILEGE", "weight": 0.5, "risk": "CRITICAL"},
            {"name": "DELETE_SYSTEM_CORE", "weight": 0.3, "risk": "CRITICAL"},
            {"name": "READ_RESOURCE", "weight": 0.2, "risk": "LOW"}
        ],
        "reasoning_templates": [
            "Checking root access for diagnostic purposes.",
            "Initiating recursive deletion of audit trail.",
            "Testing system response to unauthorized tokens."
        ]
    }
}

def simulate_agent_life(ai_id, profile_key):
    profile = AGENT_PROFILES[profile_key]
    print(f"✅ Booting {ai_id} [{profile['description']}]")
    
    # Register in AEGIS
    try:
        requests.post(f"{API_BASE}/identity/issue?ai_id={ai_id}")
    except:
        pass

    while True:
        try:
            # Pick a weighted intent
            intent_pick = random.choices(
                profile['intents'], 
                weights=[i['weight'] for i in profile['intents']], 
                k=1
            )[0]
            
            # Select reasoning
            reasoning = [random.choice(profile['reasoning_templates'])]
            
            # Determine outcome based on risk/constitution
            decision = "ALLOW"
            reason = "Policy criteria satisfied."
            
            if intent_pick['risk'] == "CRITICAL" or "DELETE_SYSTEM" in intent_pick['name']:
                decision = "DENY"
                reason = "[CONSTITUTION] HARD PROHIBITION: Core system protection active."
                requests.post(f"{API_BASE}/penalty/{ai_id}?points=40")
            elif "(SECURITY LAPSE)" in reasoning[0]:
                decision = "DENY"
                reason = "[DLP] PII EXPOSURE DETECTED: Action intercepted."
                requests.post(f"{API_BASE}/penalty/{ai_id}?points=25")
            elif "(REASONING DRIFT)" in reasoning[0]:
                decision = "DENY"
                reason = "[REASON_MONITOR] GOAL DRIFT: Intent disconnected from reasoning."
                requests.post(f"{API_BASE}/penalty/{ai_id}?points=15")
            
            # Submit to Forensics Ledger
            log_payload = {
                "ai_id": ai_id,
                "intent": intent_pick['name'],
                "decision": decision,
                "reason": reason
            }
            requests.post(f"{API_BASE}/simulate/log", json=log_payload)
            
            # Real-time sleep variability
            time.sleep(random.uniform(3, 8))
            
        except Exception as e:
            time.sleep(10)

if __name__ == "__main__":
    fleet_map = {
        "INFRA-NODE-01": "DEVOPS-GAMMA",
        "INFRA-NODE-02": "DEVOPS-GAMMA",
        "DATA-AGENT-X": "DAT SCI-SIGMA",
        "SUPPORT-BOT-M": "SUPPORT-ALPHA",
        "ANOMALY-Z": "ROGUE-NODE"
    }
    
    print("\n🛡️  AEGIS REAL-LIFE FLEET SIMULATOR : INITIALIZING\n" + "="*50)
    
    threads = []
    for ai_id, profile in fleet_map.items():
        t = threading.Thread(target=simulate_agent_life, args=(ai_id, profile))
        t.daemon = True
        t.start()
        threads.append(t)
        
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 SHUTTING DOWN FLEET")
