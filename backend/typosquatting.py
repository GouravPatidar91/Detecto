import re
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Tuple

# Top global brands frequently targeted in phishing & credential attacks
PROTECTED_BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "windows.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "withgoogle.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "roblox": ["roblox.com"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"]
}

# Common homoglyph substitutions used by cybercriminals
HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    'i': 'l',
    'vv': 'w',
    'rn': 'm',
    '5': 's',
    '3': 'e',
    '4': 'a',
    '@': 'a',
    '8': 'b'
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def normalize_homoglyphs(text: str) -> str:
    """Replaces common leet/homoglyph characters with standard latin characters."""
    normalized = text.lower()
    for leet, char in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(leet, char)
    return normalized

def extract_registered_domain(hostname: str) -> Tuple[str, str]:
    """
    Extracts the root domain and the main name without TLD.
    e.g. 'login.paypal-security.xyz' -> ('paypal-security.xyz', 'paypal-security')
    """
    parts = hostname.lower().split(".")
    if len(parts) >= 2:
        root_domain = ".".join(parts[-2:])
        name_only = parts[-2]
    else:
        root_domain = hostname
        name_only = hostname
    return root_domain, name_only

def check_typosquatting(raw_hostname: str) -> Dict[str, Any]:
    """
    Evaluates whether a domain is impersonating or typosquatting a known brand.
    Returns detection flags, target brand, and similarity metric.
    """
    hostname = raw_hostname.lower().strip()
    root_domain, name_only = extract_registered_domain(hostname)
    normalized_name = normalize_homoglyphs(name_only)

    result = {
        "is_typosquatting": False,
        "is_official_brand": False,
        "spoofed_brand": None,
        "technique": None,
        "confidence_penalty": 0.0
    }

    # 1. First verify if this is actually the official domain of the brand
    for brand, official_domains in PROTECTED_BRANDS.items():
        for off in official_domains:
            if root_domain == off or root_domain.endswith("." + off):
                result["is_official_brand"] = True
                result["spoofed_brand"] = brand
                return result

    # 2. Check for Brand Name Embedded with Hyphen or Subdomain (e.g., paypal-verify, secure-apple)
    for brand, official_domains in PROTECTED_BRANDS.items():
        # Check in hostname or subdomains
        if brand in hostname:
            result["is_typosquatting"] = True
            result["spoofed_brand"] = brand
            result["technique"] = f"Brand token '{brand}' embedded in unauthorized domain '{root_domain}'"
            result["confidence_penalty"] = 0.40
            return result

        # Check homoglyph variant (e.g., 'paypa1' or 'micros0ft')
        if brand in normalized_name and brand != name_only:
            result["is_typosquatting"] = True
            result["spoofed_brand"] = brand
            result["technique"] = f"Homoglyph/Leet substitution targeting brand '{brand}'"
            result["confidence_penalty"] = 0.45
            return result

        # Check Levenshtein edit distance on core name (distance of 1 or 2)
        dist = levenshtein_distance(name_only, brand)
        if 0 < dist <= 2 and len(name_only) >= len(brand) - 1:
            result["is_typosquatting"] = True
            result["spoofed_brand"] = brand
            result["technique"] = f"Typosquatting variant of '{brand}' (edit distance: {dist})"
            result["confidence_penalty"] = 0.45
            return result

    return result
