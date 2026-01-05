from fastapi import APIRouter
from aegis.audit.ledger import AuditLedger
from typing import List, Dict, Any

router = APIRouter(prefix="/logs", tags=["Audit"])
ledger = AuditLedger()

@router.get("")
def get_logs():
    """Returns recent audit log entries."""
    return ledger.get_logs()[-10:]
