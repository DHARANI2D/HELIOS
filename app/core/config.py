import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "DESAS"
    VERSION: str = "2.1.0"
    
    # Validation & Limits
    MAX_UPLOAD_SIZE_BYTES: int = 10_485_760  # 10 MB
    
    # External APIs
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    MXTOOLBOX_API_KEY: str = ""
    
    # Whitelists
    DOMAIN_WHITELIST: list[str] = [
        "googleapis.com", 
        "gstatic.com", 
        "google.com", 
        "microsoft.com", 
        "office.com",
        "live.com",
        "azure.com"
    ]

    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
