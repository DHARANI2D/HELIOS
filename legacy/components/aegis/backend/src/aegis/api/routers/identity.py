from fastapi import APIRouter, HTTPException, Query
from aegis.identity.idp import TrustAuthority

router = APIRouter(prefix="/identity", tags=["Identity"])
ta = TrustAuthority()

@router.post("/issue")
def issue_id_query(ai_id: str = Query(...)) -> dict:
    """Issue a new identity via query parameter."""
    ta.issue_identity(ai_id)
    return {"status": "issued", "ai_id": ai_id}

@router.post("/issue/{ai_id}")
def issue_id_path(ai_id: str) -> dict:
    """Issue a new identity via path parameter."""
    ta.issue_identity(ai_id)
    return {"status": "issued", "ai_id": ai_id}
