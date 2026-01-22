import json
import os
from app.core.config import settings

WHITELIST_FILE = "whitelist.json"

def get_whitelist() -> list[str]:
    """
    Returns the current whitelist.
    Merges configuration defaults with the persistent JSON file.
    """
    # Start with defaults from config
    current_list = set(settings.DOMAIN_WHITELIST)
    
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                saved_list = json.load(f)
                if isinstance(saved_list, list):
                    current_list.update(saved_list)
        except Exception:
            pass # Ignore file errors, fallback to defaults
            
    return sorted(list(current_list))

def add_to_whitelist(domain: str) -> list[str]:
    """
    Adds a domain to the persistent whitelist.
    Returns the updated list.
    """
    current = get_whitelist()
    domain = domain.lower().strip()
    
    if domain and domain not in current:
        current.append(domain)
        current.sort()
        
        # Save ONLY the diff or the whole thing? 
        # For simplicity, we save the entire merged list to the JSON file
        # This means the JSON file becomes the source of truth + config defaults are just seeds
        try:
            with open(WHITELIST_FILE, 'w') as f:
                json.dump(current, f, indent=2)
        except Exception as e:
            print(f"Error saving whitelist: {e}")
            
    return current

def remove_from_whitelist(domain: str) -> list[str]:
    """
    Removes a domain from the persistent whitelist.
    Returns the updated list.
    """
    current = get_whitelist()
    domain = domain.lower().strip()
    
    if domain in current:
        current.remove(domain)
        current.sort()
        
        try:
            with open(WHITELIST_FILE, 'w') as f:
                json.dump(current, f, indent=2)
        except Exception as e:
            print(f"Error saving whitelist: {e}")
            
    return current
