from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # App Settings
    PROJECT_NAME: str = "ASIP"
    API_V1_STR: str = "/api/v1"
    
    # Database (Defaults to PostgreSQL, fallbacks to SQLite locally if postgres is missing)
    DATABASE_URL: str = "postgresql+asyncpg://asip:asip@localhost/asip"
    
    # Redis for caching & task status storage
    REDIS_URL: str = "redis://localhost:6379"
    
    # Directories
    UPLOAD_DIR: str = "./uploads"
    EXTRACT_DIR: str = "./extracted"
    
    # Threat Intel APIs (Optional)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    
    # Model API Keys (Optional)
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    
    # Model Selection
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    LOCAL_MODEL: str = "qwen2.5:14b"
    CLOUD_MODEL: str = "claude-3-5-sonnet-20241022"
    
    # Vector Database (Qdrant) & Embeddings
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    QDRANT_API_KEY: Optional[str] = None
    EMBEDDING_PROVIDER: str = "mock"  # Options: mock, openai, ollama
    EMBEDDING_MODEL: str = "text-embedding-3-small"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.EXTRACT_DIR, exist_ok=True)
