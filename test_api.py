import httpx
import time

def test_api():
    client = httpx.Client(timeout=10.0)

    print("=" * 70)
    print("      DETECTO HIGH-ACCURACY THREAT ENGINE VALIDATION")
    print("=" * 70)

    test_cases = [
        ("https://microsoft.com", "Verified Allowlist Enterprise Domain"),
        ("https://github.com/torvalds/linux", "Verified Allowlist Developer Domain"),
        ("http://paypa1-security-verification.xyz/login", "Homoglyph Typosquatting ('paypa1' targeting PayPal)"),
        ("http://apple-secure-verify.com/signin", "Brand Impersonation ('apple' with phishing tokens)"),
        ("http://192.168.1.100:8080/paypal/login-verification.php?client_id=89201", "Raw IP + Brand Credential Harvester"),
        ("http://login-verify-account.com/auth", "Deceptive Generic Phishing Pattern")
    ]

    print("\nScanning URLs with Deep Accuracy Layers:")
    for url, desc in test_cases:
        t0 = time.time()
        r = client.post(
            "http://127.0.0.1:8000/api/scan",
            json={"url": url, "live_probe": True}
        )
        elapsed = time.time() - t0
        data = r.json()

        badge = data["classification"]
        risk = data["risk_score"]
        conf = data["confidence"]
        typo = f"Spoofs {data['spoofed_brand']}" if data.get("is_typosquatting") else "Authentic"
        pwd = "Password-Form" if data.get("has_password_input") else "No-Form"

        print(f"  [{badge:<10}] Risk: {risk:>5.1f}% | Conf: {conf:>5.1f}% | {typo:<18} | {elapsed:.2f}s | {url}")
        print(f"      Type:        {desc}")
        print(f"      Top Signal:  {data['risk_reasons'][0]}")
        print()

    print("Fetching Aggregated Stats:")
    stats = client.get("http://127.0.0.1:8000/api/stats").json()
    print(f"  Total Scans: {stats['total_scans']} | Safe: {stats['safe_scans']} | Suspicious: {stats['suspicious_scans']} | Malicious: {stats['malicious_scans']}")
    print("=" * 70)

if __name__ == "__main__":
    test_api()
