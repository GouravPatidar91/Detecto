import os
import json
import joblib
import pandas as pd
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple

from backend.feature_extractor import extract_url_features, probe_live_network, normalize_url
from backend.typosquatting import check_typosquatting, extract_registered_domain
from backend.advanced_probe import unwrap_shortener, inspect_dom_and_brand

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(CURRENT_DIR, "..", "ml", "saved_models", "url_classifier.joblib")
FEATURE_NAMES_PATH = os.path.join(CURRENT_DIR, "..", "ml", "saved_models", "feature_names.json")

# Verified high-authority root domains for zero-false-positive allowlisting
VERIFIED_ALLOWLIST = {
    "google.com", "youtube.com", "wikipedia.org", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "cloudflare.com", "mozilla.org", "python.org",
    "stackoverflow.com", "linkedin.com", "twitter.com", "x.com", "netflix.com",
    "facebook.com", "instagram.com", "reddit.com", "nytimes.com", "bbc.com",
    "cnn.com", "medium.com", "dropbox.com", "zoom.us", "salesforce.com",
    "adobe.com", "spotify.com", "nih.gov", "nasa.gov", "who.int", "un.org",
    "mit.edu", "stanford.edu", "harvard.edu", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "paypal.com", "gitlab.com", "docker.com", "apache.org"
}

class DetectoMLService:
    def __init__(self):
        self.model = None
        self.feature_names = []
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(FEATURE_NAMES_PATH):
            self.model = joblib.load(MODEL_PATH)
            with open(FEATURE_NAMES_PATH, "r", encoding="utf-8") as f:
                self.feature_names = json.load(f)
            print(f"[DetectoMLService] Loaded trained model with {len(self.feature_names)} features.")
        else:
            raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Train the model first.")

    def is_allowlisted(self, hostname: str) -> bool:
        """Checks if a domain is part of the trusted enterprise/academic allowlist."""
        root_domain, _ = extract_registered_domain(hostname)
        if root_domain in VERIFIED_ALLOWLIST:
            return True
        if hostname.endswith(".gov") or hostname.endswith(".edu") or hostname.endswith(".edu.in"):
            return True
        return False

    def _generate_reasons(
        self,
        url: str,
        features: Dict[str, float],
        network_info: Dict[str, Any],
        typosquat_info: Dict[str, Any],
        dom_info: Dict[str, Any]
    ) -> List[str]:
        reasons = []

        # 1. Critical DOM & Brand Impersonation Findings
        if dom_info.get("brand_title_mismatch"):
            reasons.append(dom_info["dom_finding"])

        if typosquat_info.get("is_typosquatting"):
            reasons.append(f"Brand Impersonation: {typosquat_info['technique']}")

        if dom_info.get("has_password_input") and not typosquat_info.get("is_official_brand"):
            reasons.append("Credential submission form (<input type='password'>) detected on unverified external domain.")

        # 2. Host and Structural Findings
        if features.get("is_ip_address", 0) == 1.0:
            reasons.append("Host is an explicit raw numeric IP address rather than a registered domain name.")

        sub_count = int(features.get("subdomain_count", 0))
        if sub_count >= 3:
            reasons.append(f"Excessive subdomain nesting detected ({sub_count} subdomains).")

        kw_count = int(features.get("suspicious_keyword_count", 0))
        if kw_count > 0:
            reasons.append(f"Contains high-value target or credential-harvesting tokens ({kw_count} matches).")

        if features.get("domain_has_hyphen", 0) == 1.0:
            reasons.append("Domain contains hyphenation frequently used in brand spoofing.")

        if features.get("is_suspicious_tld", 0) == 1.0:
            reasons.append("Domain utilizes a Top-Level Domain (TLD) with high historical abuse rates in phishing/malware.")

        if features.get("is_shortener", 0) == 1.0:
            reasons.append("URL utilizes a known URL redirection/shortener service hiding the true destination.")

        if features.get("has_custom_port", 0) == 1.0:
            reasons.append("Connects via non-standard web port.")

        if features.get("count_at", 0) > 0:
            reasons.append("Contains '@' symbol, a technique used to obscure malicious host destinations.")

        if features.get("domain_entropy", 0) > 3.8:
            reasons.append(f"High domain character randomness (entropy {features['domain_entropy']:.2f}) typical of DGA or malware c2.")

        # 3. Network & Security Findings
        if features.get("is_https", 0) == 0.0:
            reasons.append("Connection lacks HTTPS encryption (transmitted in plaintext).")
        elif network_info.get("ssl_valid") is False and network_info.get("live_probe_status") == "ssl_warning":
            reasons.append("HTTPS is present but SSL certificate is untrusted or self-signed.")

        if not network_info.get("dns_resolved") and network_info.get("live_probe_status") == "dns_failed":
            reasons.append("Domain failed live DNS resolution (inactive, sinkholed, or unrouted host).")

        if not reasons:
            reasons.append("URL exhibits standard lexical structure, valid domain hierarchy, and verified SSL certificate.")

        return reasons

    def analyze_url(self, raw_url: str, enable_live_probe: bool = True) -> Dict[str, Any]:
        normalized = normalize_url(raw_url)
        parsed = urlparse(normalized)
        domain = (parsed.hostname or normalized).lower()

        # Step 1: URL Shortener / Redirect Unwrapping
        final_url = normalized
        is_redirected = False
        redirect_hops = 0
        if enable_live_probe:
            final_url, is_redirected, redirect_hops = unwrap_shortener(normalized, timeout_sec=0.8)
            if is_redirected:
                parsed = urlparse(final_url)
                domain = (parsed.hostname or domain).lower()

        # Step 2: High-Authority Allowlist Check
        allowlisted = self.is_allowlisted(domain)

        # Step 3: Extract Feature Vector
        features = extract_url_features(final_url)

        # Step 4: Typosquatting & Edit-Distance Analysis
        typosquat_info = check_typosquatting(domain)

        # Step 5: Live Network Probe & DOM Content Inspection
        network_info = {
            "dns_resolved": False,
            "resolved_ip": None,
            "ssl_valid": False,
            "ssl_issuer": None,
            "live_probe_status": "bypassed"
        }
        dom_info = {
            "dom_scanned": False,
            "page_title": None,
            "has_password_input": False,
            "brand_title_mismatch": False,
            "spoofed_brand_in_title": None,
            "dom_risk_penalty": 0.0,
            "dom_finding": None
        }

        if enable_live_probe:
            try:
                network_info = probe_live_network(final_url, timeout=1.0)
            except Exception as e:
                network_info["live_probe_status"] = f"error: {str(e)[:40]}"

            # Only inspect DOM if DNS resolved, host is reachable, and NOT already allowlisted
            if network_info.get("dns_resolved") and not allowlisted and not typosquat_info.get("is_official_brand"):
                dom_info = inspect_dom_and_brand(final_url, domain, timeout_sec=0.6)

        # Step 6: Machine Learning Inference
        input_row = [features[name] for name in self.feature_names]
        input_df = pd.DataFrame([input_row], columns=self.feature_names)
        prob_malicious = float(self.model.predict_proba(input_df.values)[0][1])

        # Step 7: Multi-Layer Heuristic Calibration
        heuristic_penalty = 0.0

        if typosquat_info.get("is_typosquatting"):
            heuristic_penalty += typosquat_info["confidence_penalty"]

        if dom_info.get("brand_title_mismatch"):
            heuristic_penalty += dom_info["dom_risk_penalty"]

        if dom_info.get("has_password_input") and not allowlisted and not typosquat_info.get("is_official_brand"):
            heuristic_penalty += 0.30

        if features.get("is_ip_address", 0) == 1.0:
            heuristic_penalty += 0.40

        if features.get("count_at", 0) > 0:
            heuristic_penalty += 0.35

        if features.get("suspicious_keyword_count", 0) >= 2 and features.get("is_https", 0) == 0.0:
            heuristic_penalty += 0.30

        if features.get("is_suspicious_tld", 0) == 1.0 and features.get("suspicious_keyword_count", 0) >= 1:
            heuristic_penalty += 0.25

        # Allowlist override: genuine trusted domains with valid SSL have 0% risk
        if allowlisted and (network_info.get("ssl_valid") or features.get("is_https") == 1.0) and not typosquat_info.get("is_typosquatting"):
            final_prob = 0.0
            heuristic_penalty = 0.0
        else:
            final_prob = min(1.0, max(0.0, prob_malicious + heuristic_penalty))

        risk_score = round(final_prob * 100.0, 1)

        # Step 8: Map into 3 tiers per synopsis specification
        if final_prob < 0.35:
            classification = "Safe"
            confidence = round((1.0 - final_prob) * 100.0, 1)
            status_message = "This URL exhibits characteristics consistent with legitimate and benign websites."
            if allowlisted:
                status_message = "Verified trusted enterprise/academic domain on official cybersecurity allowlist."
        elif 0.35 <= final_prob <= 0.65:
            classification = "Suspicious"
            confidence = round((1.0 - abs(final_prob - 0.5) * 2) * 100.0, 1)
            status_message = "This URL exhibits abnormal or borderline features. Exercise caution before proceeding or submitting credentials."
        else:
            classification = "Malicious"
            confidence = round(final_prob * 100.0, 1)
            status_message = "High risk detected! This URL displays strong indicators of phishing, credential harvesting, or malware distribution."

        # Step 9: Educational Explanation Reasons
        reasons = self._generate_reasons(final_url, features, network_info, typosquat_info, dom_info)

        return {
            "url": final_url,
            "original_url": normalized,
            "domain": domain,
            "classification": classification,
            "risk_score": risk_score,
            "confidence": confidence,
            "status_message": status_message,
            "dns_resolved": network_info["dns_resolved"],
            "resolved_ip": network_info["resolved_ip"],
            "ssl_valid": network_info["ssl_valid"],
            "ssl_issuer": network_info["ssl_issuer"],
            "live_probe_status": network_info["live_probe_status"],
            "is_redirected": is_redirected,
            "redirect_hops": redirect_hops,
            "is_typosquatting": typosquat_info["is_typosquatting"],
            "spoofed_brand": typosquat_info["spoofed_brand"],
            "has_password_input": dom_info["has_password_input"],
            "brand_title_mismatch": dom_info["brand_title_mismatch"],
            "page_title": dom_info["page_title"],
            "risk_reasons": reasons,
            "features": features
        }

# Global singleton
ml_service = DetectoMLService()
