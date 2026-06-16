from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from ...core.config import settings

router = APIRouter(prefix="/settings", tags=["settings"])

class SettingsUpdateSchema(BaseModel):
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    
    OLLAMA_BASE_URL: Optional[str] = None
    LOCAL_MODEL: Optional[str] = None
    CLOUD_MODEL: Optional[str] = None
    
    EMBEDDING_PROVIDER: Optional[str] = None
    EMBEDDING_MODEL: Optional[str] = None

@router.get("")
async def get_settings():
    """Retrieve current active server settings (with masked credentials)."""
    def mask_key(k: Optional[str]) -> str:
        if not k:
            return ""
        return k[:8] + "..." if len(k) > 8 else "..."

    return {
        "OPENAI_API_KEY": mask_key(settings.OPENAI_API_KEY),
        "ANTHROPIC_API_KEY": mask_key(settings.ANTHROPIC_API_KEY),
        "VIRUSTOTAL_API_KEY": mask_key(settings.VIRUSTOTAL_API_KEY),
        "ABUSEIPDB_API_KEY": mask_key(settings.ABUSEIPDB_API_KEY),
        "OLLAMA_BASE_URL": settings.OLLAMA_BASE_URL,
        "LOCAL_MODEL": settings.LOCAL_MODEL,
        "CLOUD_MODEL": settings.CLOUD_MODEL,
        "EMBEDDING_PROVIDER": settings.EMBEDDING_PROVIDER,
        "EMBEDDING_MODEL": settings.EMBEDDING_MODEL
    }

@router.post("")
async def update_settings(payload: SettingsUpdateSchema):
    """Dynamically updates active configurations in-memory on the backend."""
    # Update keys only if they are not the masked placeholder variants
    if payload.OPENAI_API_KEY is not None and not payload.OPENAI_API_KEY.endswith("..."):
        settings.OPENAI_API_KEY = payload.OPENAI_API_KEY or None
        
    if payload.ANTHROPIC_API_KEY is not None and not payload.ANTHROPIC_API_KEY.endswith("..."):
        settings.ANTHROPIC_API_KEY = payload.ANTHROPIC_API_KEY or None
        
    if payload.VIRUSTOTAL_API_KEY is not None and not payload.VIRUSTOTAL_API_KEY.endswith("..."):
        settings.VIRUSTOTAL_API_KEY = payload.VIRUSTOTAL_API_KEY or None
        
    if payload.ABUSEIPDB_API_KEY is not None and not payload.ABUSEIPDB_API_KEY.endswith("..."):
        settings.ABUSEIPDB_API_KEY = payload.ABUSEIPDB_API_KEY or None

    if payload.OLLAMA_BASE_URL is not None:
        settings.OLLAMA_BASE_URL = payload.OLLAMA_BASE_URL
        
    if payload.LOCAL_MODEL is not None:
        settings.LOCAL_MODEL = payload.LOCAL_MODEL
        
    if payload.CLOUD_MODEL is not None:
        settings.CLOUD_MODEL = payload.CLOUD_MODEL
        
    if payload.EMBEDDING_PROVIDER is not None:
        settings.EMBEDDING_PROVIDER = payload.EMBEDDING_PROVIDER
        
    if payload.EMBEDDING_MODEL is not None:
        settings.EMBEDDING_MODEL = payload.EMBEDDING_MODEL

    return {
        "status": "success",
        "message": "Configuration updated successfully in memory"
    }
