import json
import os
from pydantic import BaseModel

SETTINGS_FILE = "settings.json"

class AppSettings(BaseModel):
    VIRUSTOTAL_API_KEY: str = ""
    MXTOOLBOX_API_KEY: str = ""
    # Add other dynamic settings here if needed

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
