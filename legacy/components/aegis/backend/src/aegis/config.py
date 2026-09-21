from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "AEGIS Control Plane"
    API_PORT: int = 8000
    LOG_LEVEL: str = "INFO"
    ENVIRONMENT: str = "production"
    
    # Security
    CONSULTATION_ENABLED: bool = True
    CONSTITUTION_PATH: str = "aegis/governance/constitution.py"

    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env")

settings = Settings()
