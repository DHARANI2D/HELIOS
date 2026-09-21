import hashlib
import json
import time
from typing import List, Dict, Any
from sqlmodel import Session, select, delete
from aegis.db import engine, AuditLog

class AuditLedger:
    """A tamper‑evident, hash‑chained audit log for AI decisions.
    Entries are persisted in the SQLite database via SQLModel.
    """

    def __init__(self):
        # No in‑memory chain needed; logs are stored in DB.
        pass

    def log_decision(self, ai_id: str, intent: str, decision: str, reason: str, signature: str) -> str:
        """Log a policy decision and return the current hash.
        The hash chains to the previous entry for forensic integrity.
        """
        with Session(engine) as session:
            # Retrieve the latest log entry to obtain previous hash
            prev_log = session.exec(select(AuditLog).order_by(AuditLog.id.desc())).first()
            prev_hash = prev_log.current_hash if prev_log else "GENESIS"

            now = time.time()
            entry_data = {
                "ai_id": ai_id,
                "intent": intent,
                "decision": decision,
                "reason": reason,
                "prev_hash": prev_hash,
                "timestamp": now,
            }
            current_hash = hashlib.sha256(json.dumps(entry_data, sort_keys=True).encode()).hexdigest()

            log_entry = AuditLog(
                ai_id=ai_id,
                intent=intent,
                decision=decision,
                reason=reason,
                current_hash=current_hash,
                prev_hash=prev_hash,
                signature=signature,
                timestamp_raw=now,
            )
            session.add(log_entry)
            session.commit()
            session.refresh(log_entry)
            return current_hash

    def get_logs(self) -> List[Dict[str, Any]]:
        """Return all logs ordered newest first.
        The UI can slice as needed.
        """
        with Session(engine) as session:
            logs = session.exec(select(AuditLog).order_by(AuditLog.id.desc())).all()
            return [log.dict() for log in logs]

    def verify_integrity(self) -> bool:
        """Verify the hash chain integrity across all stored logs.
        Returns True if the chain is intact, False otherwise.
        """
        with Session(engine) as session:
            logs = session.exec(select(AuditLog).order_by(AuditLog.id)).all()
            prev_hash = "GENESIS"
            for log in logs:
                entry = {
                    "ai_id": log.ai_id,
                    "intent": log.intent,
                    "decision": log.decision,
                    "reason": log.reason,
                    "prev_hash": log.prev_hash,
                    "timestamp": log.timestamp_raw,
                }
                expected_hash = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
                if log.current_hash != expected_hash or log.prev_hash != prev_hash:
                    return False
                prev_hash = log.current_hash
            return True
