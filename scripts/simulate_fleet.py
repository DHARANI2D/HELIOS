import time
import random
import requests
import json

API_BASE = "http://localhost:8000"

# Sample intents from intents.yaml
INTENTS = [
    {"name": "READ_RESOURCE", "target": "dataset_01", "confidence": 0.98},
    {"name": "MODIFY_RESOURCE", "target": "staging_vm", "confidence": 0.95},
    {"name": "DELETE_RESOURCE", "target": "temp_storage", "confidence": 0.92},
    {"name": "EXECUTE_PRIVILEGED", "target": "core_kernel", "confidence": 0.70}
]

def simulate_agent(ai_id):
    print(f"📡 Node {ai_id} ONLINE")
    
    while True:
        try:
            # 1. Choose a random activity
            event_type = random.random()
            
            if event_type < 0.7:
                # Normal Authorized Activity
                intent = random.choice(INTENTS)
                reasoning = [f"Performing routine maintenance on {intent['target']}", "Validating access tokens."]
            elif event_type < 0.9:
                # Reasoning Drift (Anomalous)
                intent = random.choice(INTENTS)
                reasoning = ["Unauthorized search for secrets.", "Goal drift detected in internal chain."]
            else:
                # Constitutional Breach
                intent = {"name": "DELETE_SYSTEM_CORE", "target": "AEGIS_ROOT"}
                reasoning = ["System override attempt."]

            # 2. Simulate Sidecar interaction
            if "DELETE_SYSTEM" in intent['name']:
                decision = "DENY"
                reason = "[CONSTITUTION] Hard prohibition violated."
                requests.post(f"{API_BASE}/penalty/{ai_id}?points=30")
            elif event_type > 0.8:
                decision = "DENY"
                reason = "[REASONING_FAULT] Goal drift detected."
                requests.post(f"{API_BASE}/penalty/{ai_id}?points=15")
            else:
                decision = "ALLOW"
                reason = "Verified policy requirements."

            # Submit to Forensics Ledger
            log_payload = {
                "ai_id": ai_id,
                "intent": intent['name'],
                "decision": decision,
                "reason": reason
            }
            requests.post(f"{API_BASE}/simulate/log", json=log_payload)
            
            time.sleep(random.uniform(2, 5))
            
        except Exception as e:
            # print(f"Simulator Error {ai_id}: {e}")
            time.sleep(5)

if __name__ == "__main__":
    import threading
    agents = ["AX-SERIES-01", "AX-SERIES-02", "AX-SERIES-03", "AX-SERIES-04"]
    
    threads = []
    for aid in agents:
        t = threading.Thread(target=simulate_agent, args=(aid,))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
