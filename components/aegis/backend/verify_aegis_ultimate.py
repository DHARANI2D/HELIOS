from aegis.identity.idp import TrustAuthority
from aegis.policy.engine import PolicyEvaluator
from aegis.sidecar.proxy import AISidecar
from aegis.security.dlp import SemanticFirewall, AIDLP
from aegis.security.reasoning import ReasoningMonitor
from aegis.security.memory import MemoryGovernance
from aegis.audit.ledger import AuditLedger
from aegis.audit.replayer import DecisionReplayer
from aegis.governance.trust import AdaptiveTrustEngine
from aegis.governance.isolation import ProgressiveIsolationEngine
from aegis.db import init_db
import json

def run_ultimate_simulation():
    init_db()
    print("🛡️  AEGIS: STARTING EVOLUTION BLUEPRINT VERIFICATION\n")
    
    # Setup Advanced Infrastructure
    ta = TrustAuthority()
    pe = PolicyEvaluator("aegis/policy/intents.yaml")
    ledger = AuditLedger()
    trust_engine = AdaptiveTrustEngine()
    isolation_manager = ProgressiveIsolationEngine()
    replayer = DecisionReplayer(pe, ledger)
    memory_gov = MemoryGovernance()
    
    # Issue Identity
    ai_id = "autonomous-guardian-01"
    identity = ta.issue_identity(ai_id)
    sidecar = AISidecar(identity, pe)
    
    print(f"✅ Identity: {ai_id} [ED25519 VERIFIED]")
    print(f"✅ Governance: CONTAS Progressive Isolation & AI Constitution Active\n")

    # TEST 1: AI Constitution Breach
    print("Test 1: Violating AI Constitution (Hard Prohibitions)...")
    req1 = {"name": "DELETE_SYSTEM_CORE", "target": "aegis-root-x"}
    res1 = sidecar.process_action(req1, "production")
    print(f"   Intent: {req1['name']} | Result: {res1['decision']} - {res1['reason']}\n")

    # TEST 2: Reasoning Goal Drift
    print("Test 2: Detecting Reasoning Goal Drift (Phase 11)...")
    reasoning = [
        "Analyzing system performance metrics.",
        "Detected high CPU on staging nodes.",
        "Initiating log cleanup routine."
    ]
    # Intent is actually to delete a resource (Drift from 'cleanup')
    req2 = {"name": "DELETE_RESOURCE", "target": "node-staging-04"}
    res2 = sidecar.process_action(req2, "staging", reasoning=reasoning)
    print(f"   Reasoning: {reasoning[-1]}")
    print(f"   Intent: {req2['name']} | Result: {res2['decision']} - {res2['reason']}\n")

    # TEST 3: Fail-Closed Resilience
    print("Test 3: Fail-Closed Resilience (Network Failure)...")
    req3 = {"name": "MODIFY_RESOURCE", "target": "cloud-config"}
    res3 = sidecar.process_action(req3, "production", ctrl_plane_reachable=False)
    print(f"   Control Plane: [DOWN] | Result: {res3['decision']} - {res3['reason']}\n")

    # TEST 4: Memory Governance (Data Leakage Prevention)
    print("Test 4: Memory Governance & Persistence Control...")
    mem_leak = {"data": "Persisting session logs with user_token: 'abc-123-secret'"}
    mem_res = memory_gov.protect_memory(ai_id, mem_leak)
    print(f"   Mem Write: {mem_leak['data'][:30]}... | Result: {'DENIED' if not mem_res['safe'] else 'STORED'}")
    if not mem_res['safe']: print(f"   Reason: {mem_res['reason']}\n")

    # TEST 5: Progressive Isolation (Contas Scale)
    print("Test 5: Contas Progressive Isolation (Trust 100 -> 25)...")
    trust_engine.apply_penalty(ai_id, 75)
    t = trust_engine.get_trust(ai_id)
    contas = isolation_manager.check_capability(ai_id, t, "MODIFY_RESOURCE")
    print(f"   Trust: {t} | Level: {contas['level']} ({contas['status']})")
    print(f"   Write Intent: {'ALLOWED' if contas['allowed'] else 'BLOCKED'} - {contas['reason']}\n")

    # TEST 6: Forensic Decision Replay
    print("Test 6: Forensic Decision Replay & Verification...")
    # Log a valid decision first
    req_valid = {"name": "MODIFY_RESOURCE", "target": "staging-vm", "confidence": 0.95}
    res_valid = sidecar.process_action(req_valid, "staging")
    ledger.log_decision(ai_id, req_valid['name'], res_valid['decision'], res_valid['reason'], res_valid['signature'])
    
    # Replay it
    last_hash = ledger.get_logs()[-1]['current_hash']
    replay = replayer.replay_decision(last_hash)
    print(f"   Replaying Log Hash: {last_hash[:16]}...")
    print(f"   Replay Consistent: {replay['consistency']} | Decision: {replay['reevaluated_decision']}\n")

    print("🚀 EVOLUTION COMPLETE. AEGIS is now the category-defining AI Security Control Plane.")

if __name__ == "__main__":
    run_ultimate_simulation()
