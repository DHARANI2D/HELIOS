from app.sandbox.exfiltration import ExfiltrationEngine
import base64
import gzip
import io

def test_engine():
    engine = ExfiltrationEngine()
    print("--- Testing SOC-Grade Exfiltration Engine ---")

    # 1. Test PII Detection
    print("\n[1] Testing PII Detection (Credit Card + Luhn)")
    # 4111 1111 1111 1111 is the standard industry test Visa number - Luhn-valid, never a real card
    test_data = "Target acquired. User CC: 4111 1111 1111 1111"
    res = engine.process_payload(test_data)
    print(f"PII Detected: {res['pii_detected']}")
    assert any("Credit Card" in p for p in res['pii_detected']), "Expected a validated credit card match"

    # 2. Test Recursive Decoding
    print("\n[2] Testing Recursive Decoding (B64 -> Gzip)")
    inner_secret = "AWS Key Leak: AKIAIOSFODNN7EXAMPLE"  # AWS's own docs example key, safe dummy
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(inner_secret.encode())
    encoded_payload = base64.b64encode(buf.getvalue()).decode()
    res = engine.process_payload(encoded_payload)
    print(f"Decoded Secret Detection: {res['pii_detected']} (layers: {res['obfuscation_layers']}, signals: {res['obfuscation_signals']})")
    assert res["pii_detected"], "Expected the recursive decoder to unwrap the gzip+base64 payload and find the AWS key"
    
    # 3. Test DNS Tunneling
    print("\n[3] Testing DNS Tunneling")
    suspicious_subdomain = "v1-0-0-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
    res = engine.process_payload("ping", subdomain=suspicious_subdomain, domain="malicious.com")
    print(f"DNS Tunneling Detected: {res['dns_tunneling']}")
    print(f"DNS Reasons: {res['dns_reasons']}")

    # 4. Test Entropy
    print("\n[4] Testing Entropy")
    low_entropy = "Hello world, this is a normal message."
    high_entropy = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
    print(f"Low Entropy Score: {engine.calculate_entropy(low_entropy):.2f}")
    print(f"High Entropy Score: {engine.calculate_entropy(high_entropy):.2f}")

if __name__ == "__main__":
    test_engine()
