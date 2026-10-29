import re
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Tuple
from backend.typosquatting import PROTECTED_BRANDS, extract_registered_domain

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None
    HAS_HTTPX = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    BeautifulSoup = None
    HAS_BS4 = False

SHORTENER_HOSTS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "tiny.cc", "rebrand.ly", "shorturl.at"
}

def unwrap_shortener(url: str, timeout_sec: float = 0.5) -> Tuple[str, bool, int]:
    """
    Follows redirects for shortened or redirection URLs to reveal the terminal URL.
    Returns: (final_url, is_redirected, hops_count)
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not HAS_HTTPX or hostname not in SHORTENER_HOSTS:
        return url, False, 0

    try:
        with httpx.Client(timeout=httpx.Timeout(timeout_sec, connect=0.3)) as client:
            resp = client.head(url, follow_redirects=True)
            final_url = str(resp.url)
            hops = len(resp.history)
            return final_url, (hops > 0 or final_url != url), hops
    except Exception:
        return url, False, 0

def inspect_dom_and_brand(url: str, hostname: str, timeout_sec: float = 0.6) -> Dict[str, Any]:
    """
    Performs fast, bounded HTML stream inspection:
    - Streams only the initial 30KB of HTML (head + form tags) to prevent latency
    - Identifies credential harvesting forms (<input type="password">)
    - Extracts page <title> and checks for Brand Impersonation Title Mismatch
    """
    result = {
        "dom_scanned": False,
        "page_title": None,
        "has_password_input": False,
        "brand_title_mismatch": False,
        "spoofed_brand_in_title": None,
        "dom_risk_penalty": 0.0,
        "dom_finding": None
    }
    if not HAS_HTTPX or not HAS_BS4:
        return result

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html"
        }
        with httpx.Client(timeout=httpx.Timeout(timeout_sec, connect=0.3), follow_redirects=True) as client:
            with client.stream("GET", url, headers=headers) as resp:
                if resp.status_code != 200:
                    return result

                html_chunks = []
                total_len = 0
                for text_chunk in resp.iter_text():
                    html_chunks.append(text_chunk)
                    total_len += len(text_chunk)
                    if total_len > 35000:
                        break

                raw_html = "".join(html_chunks)
                result["dom_scanned"] = True
                soup = BeautifulSoup(raw_html, "html.parser")

                # 1. Check for password input field
                pwd_input = soup.find("input", {"type": "password"})
                if not pwd_input:
                    pwd_input = soup.find("input", {"name": re.compile(r"pass|pwd", re.I)})
                result["has_password_input"] = bool(pwd_input)

                # 2. Extract Title
                if soup.title and soup.title.string:
                    title_text = soup.title.string.strip()
                    result["page_title"] = title_text[:120]
                    title_lower = title_text.lower()

                    # Check if title claims to be a protected brand
                    root_domain, _ = extract_registered_domain(hostname)
                    for brand, official_domains in PROTECTED_BRANDS.items():
                        if brand in title_lower:
                            is_genuine = any(root_domain == off or root_domain.endswith("." + off) for off in official_domains)
                            if not is_genuine:
                                result["brand_title_mismatch"] = True
                                result["spoofed_brand_in_title"] = brand
                                result["dom_finding"] = (
                                    f"Page claims to be '{brand.upper()}' in HTML title ('{title_text[:60]}'), "
                                    f"but domain '{hostname}' is NOT an authorized {brand.capitalize()} property."
                                )
                                result["dom_risk_penalty"] = 0.50
                                break

                if not result["dom_finding"] and result["has_password_input"]:
                    root_domain, _ = extract_registered_domain(hostname)
                    result["dom_finding"] = f"Credential submission form (<input type='password'>) detected on domain '{root_domain}'."

    except Exception:
        # Failsafe non-blocking fallback
        pass

    return result
