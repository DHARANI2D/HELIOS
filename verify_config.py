import os

# Create a temporary .env file for testing
with open(".env", "w") as f:
    f.write("VIRUSTOTAL_API_KEY=test_key_12345\n")
    f.write("ABUSEIPDB_API_KEY=test_abuse_key\n")

try:
    from app.core.config import settings
    
    print("--- Configuration Check ---")
    print(f"Project Name: {settings.PROJECT_NAME}")
    print(f"Version: {settings.VERSION}")
    
    # Check if env vars were loaded
    if settings.VIRUSTOTAL_API_KEY == "test_key_12345":
        print("✓ VIRUSTOTAL_API_KEY loaded successfully from .env")
    else:
        print(f"✗ Failed to load VIRUSTOTAL_API_KEY. Got: '{settings.VIRUSTOTAL_API_KEY}'")

    if settings.ABUSEIPDB_API_KEY == "test_abuse_key":
        print("✓ ABUSEIPDB_API_KEY loaded successfully from .env")
    else:
        print(f"✗ Failed to load ABUSEIPDB_API_KEY. Got: '{settings.ABUSEIPDB_API_KEY}'")

finally:
    # Cleanup
    if os.path.exists(".env"):
        os.remove(".env")
