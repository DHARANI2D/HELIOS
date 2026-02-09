import os
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.settings_manager import get_dynamic_settings

class Settings(BaseSettings):
    PROJECT_NAME: str = "DESAS"
    VERSION: str = "2.2.0" # Incremented for dynamic settings
    
    # Validation & Limits
    MAX_UPLOAD_SIZE_BYTES: int = 10_485_760  # 10 MB
    
    # Static Configuration (Fallbacks)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = "c2049f09aecf31dfa290c809f63d4b2ef0f029d3161d61bfe47c9ff0d6be9ce63caa59986eabd4bc"
    URLSCAN_API_KEY: str = ""
    MXTOOLBOX_API_KEY: str = ""
    
    # Whitelists
    DOMAIN_WHITELIST: list[str] = [
        "google.com", 
        "microsoft.com", 
        "office.com",
        "live.com"
    ]

    @property
    def vt_key(self) -> str:
        dyn = get_dynamic_settings()
        return dyn.VIRUSTOTAL_API_KEY or self.VIRUSTOTAL_API_KEY

    @property
    def abuse_key(self) -> str:
        dyn = get_dynamic_settings()
        return dyn.ABUSEIPDB_API_KEY or self.ABUSEIPDB_API_KEY

    @property
    def mx_key(self) -> str:
        dyn = get_dynamic_settings()
        return dyn.MXTOOLBOX_API_KEY or self.MXTOOLBOX_API_KEY

    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
