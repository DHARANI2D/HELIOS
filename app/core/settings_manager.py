import json
import os
from pydantic import BaseModel

def get_data_dir():
    """Returns a platform-specific directory for application data."""
    if os.name == 'nt': # Windows
        base_dir = os.environ.get('APPDATA')
    else: # macOS / Linux
        base_dir = os.path.expanduser('~/Library/Application Support')
        if not os.path.exists(base_dir):
            base_dir = os.path.expanduser('~/.local/share')
            
    data_dir = os.path.join(base_dir, "DESAS")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir

DATA_DIR = get_data_dir()
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

class AppSettings(BaseModel):
    VIRUSTOTAL_API_KEY: str = ""
    MXTOOLBOX_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    DOMAIN_WHITELIST: list[str] = ["google.com", "microsoft.com", "office.com", "live.com"]

def get_persisted_settings() -> dict:
    """Loads settings from settings.json if it exists."""
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_settings(settings_data: dict):
    """Saves settings to settings.json."""
    try:
        # Filter to only keep valid settings keys
        valid_keys = AppSettings.model_fields.keys()
        filtered_data = {k: v for k, v in settings_data.items() if k in valid_keys}
        
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(filtered_data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False

def get_dynamic_settings() -> AppSettings:
    """Returns AppSettings object merged with persisted data."""
    persisted = get_persisted_settings()
    return AppSettings(**persisted)
