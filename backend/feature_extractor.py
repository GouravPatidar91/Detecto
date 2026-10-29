import re
import math
import socket
import ssl
from urllib.parse import urlparse
from typing import Dict, Any, Tuple
import concurrent.futures

# Suspicious keywords frequently observed in phishing / malicious URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "banking", "secure", "signin",
    "ebayisapi", "webscr", "password", "confirm", "wallet", "security",
    "billing", "admin", "auth", "support", "service", "recover", "invoice",
    "appleid", "paypal", "microsoft", "google", "netflix", "dropbox"
]

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "tiny.cc", "rebrand.ly", "shorturl.at"
}

# Suspicious / high-abuse TLDs
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".icu", ".work", ".live", ".cfd", ".sbs",
    ".bond", ".rest", ".quest", ".click", ".link", ".cc", ".tk", ".ml", ".ga"
}

IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect algorithmically generated strings (DGA)."""
    if not text:
        return 0.0
    prob_dict = {}
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in prob_dict.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def normalize_url(raw_url: str) -> str:
    """Cleans and normalizes URL string."""
    url = raw_url.strip()
    if not (url.startswith("http://") or url.startswith("https://") or url.startswith("ftp://")):
        url = "http://" + url
    return url


def extract_url_features(raw_url: str) -> Dict[str, float]:
    """
    Extracts lexical, structural, statistical, and domain characteristics
    from a URL for machine learning inference.
    """
    url = normalize_url(raw_url)
    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # Check for IP address in hostname
    is_ip = 1.0 if IPV4_PATTERN.match(hostname) else 0.0

    # Subdomains count
    parts = hostname.split(".")
    if is_ip:
        subdomain_count = 0.0
    else:
        subdomain_count = float(max(0, len(parts) - 2))

    # Keyword matching in whole URL
    url_lower = url.lower()
    keyword_count = sum(1.0 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Shortener check
    is_shortener = 1.0 if hostname in SHORTENER_DOMAINS else 0.0

    # Suspicious TLD check
    is_suspicious_tld = 1.0 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0

    # Digit counts and ratios
    digits_in_url = sum(c.isdigit() for c in url)
    letters_in_url = sum(c.isalpha() for c in url)
    digit_ratio = float(digits_in_url) / float(len(url)) if len(url) > 0 else 0.0

    # Domain hyphen check (prefix/suffix attack e.g. paypal-verify.com)
    domain_has_hyphen = 1.0 if "-" in hostname else 0.0

    # Non-standard port
    has_custom_port = 0.0
    if parsed.port and parsed.port not in (80, 443):
        has_custom_port = 1.0

    features: Dict[str, float] = {
        "url_length": float(len(url)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "count_dots": float(url.count(".")),
        "count_slashes": float(url.count("/")),
        "count_hyphens": float(url.count("-")),
        "count_underscores": float(url.count("_")),
        "count_question_marks": float(url.count("?")),
        "count_equals": float(url.count("=")),
        "count_ampersands": float(url.count("&")),
        "count_at": float(url.count("@")),
        "count_percent": float(url.count("%")),
        "count_exclamation": float(url.count("!")),
        "count_tilde": float(url.count("~")),
        "count_digits": float(digits_in_url),
        "digit_ratio": round(digit_ratio, 4),
        "subdomain_count": subdomain_count,
        "is_ip_address": is_ip,
        "is_https": 1.0 if parsed.scheme == "https" else 0.0,
        "is_shortener": is_shortener,
        "is_suspicious_tld": is_suspicious_tld,
        "domain_has_hyphen": domain_has_hyphen,
        "suspicious_keyword_count": float(keyword_count),
        "has_custom_port": has_custom_port,
        "domain_entropy": calculate_entropy(hostname),
        "url_entropy": calculate_entropy(url),
    }

    return features


import dns.resolver

_dns_resolver = dns.resolver.Resolver(configure=False)
_dns_resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
_dns_resolver.lifetime = 0.8
_dns_resolver.timeout = 0.8

def probe_live_network(raw_url: str, timeout: float = 0.8) -> Dict[str, Any]:
    """
    Performs safe, non-blocking live network inspection on real-world URLs:
    - Ultra-fast asynchronous DNS resolution via 1.1.1.1 (Cloudflare) / 8.8.8.8 (Google)
    - Direct IPv4 SSL certificate handshake for HTTPS
    """
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    result = {
        "dns_resolved": False,
        "resolved_ip": None,
        "ssl_valid": False,
        "ssl_issuer": None,
        "live_probe_status": "unreachable",
    }

    if not hostname:
        return result

    # 1. DNS Resolution
    ip_addr = None
    if IPV4_PATTERN.match(hostname):
        ip_addr = hostname
        result["dns_resolved"] = True
        result["resolved_ip"] = hostname
        result["live_probe_status"] = "resolved_ip"
    else:
        try:
            answers = _dns_resolver.resolve(hostname, "A")
            ip_addr = str(answers[0].address)
            result["dns_resolved"] = True
            result["resolved_ip"] = ip_addr
            result["live_probe_status"] = "resolved"
        except Exception:
            result["dns_resolved"] = False
            result["resolved_ip"] = None
            result["live_probe_status"] = "dns_failed"
            return result

    # 2. SSL Verification if HTTPS
    if parsed.scheme == "https" and ip_addr:
        try:
            context = ssl.create_default_context()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip_addr, port))
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["ssl_valid"] = True
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["ssl_issuer"] = issuer.get("organizationName") or issuer.get("commonName") or "Verified CA"
                result["live_probe_status"] = "ssl_verified"
        except Exception:
            result["ssl_valid"] = False
            result["ssl_issuer"] = "Self-Signed / Invalid SSL"
            result["live_probe_status"] = "ssl_warning"

    return result
