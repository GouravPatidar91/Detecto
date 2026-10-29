import random
import csv
import os

# Base domains for benign websites
BENIGN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
    "amazon.com", "reddit.com", "netflix.com", "linkedin.com", "microsoft.com",
    "instagram.com", "twitter.com", "x.com", "apple.com", "github.com",
    "cloudflare.com", "bing.com", "twitch.tv", "adobe.com", "spotify.com",
    "cnn.com", "bbc.com", "nytimes.com", "medium.com", "stackoverflow.com",
    "quora.com", "dropbox.com", "salesforce.com", "zoom.us", "vimeo.com",
    "harvard.edu", "mit.edu", "stanford.edu", "nasa.gov", "nih.gov",
    "who.int", "un.org", "python.org", "mozilla.org", "apache.org",
    "coursera.org", "khanacademy.org", "udemy.com", "gitlab.com", "docker.com",
    "craigslist.org", "ebay.com", "walmart.com", "target.com", "homedepot.com",
    "espn.com", "cnet.com", "theguardian.com", "forbes.com", "bloomberg.com",
    "reuters.com", "wsj.com", "healthline.com", "webmd.com", "tripadvisor.com",
    "booking.com", "airbnb.com", "expedia.com", "zillow.com", "weather.com",
    "usps.com", "fedex.com", "ups.com", "paypal.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "citigroup.com", "capitalone.com"
]

BENIGN_SUBDOMAINS = ["www", "blog", "news", "mail", "api", "support", "docs", "dev", "app", "store", "en", "m", "portal"]
BENIGN_PATHS = [
    "", "home", "about-us", "contact", "articles/technology", "products/item-detail",
    "research/paper-2024", "help/faq", "pricing", "features", "solutions/enterprise",
    "careers/openings", "community/forum/topic", "legal/privacy-policy",
    "legal/terms-of-service", "downloads/client-v2", "categories/electronics",
    "guide/getting-started", "explore/trending", "news/daily-update", "archive/2023",
    "wiki/Computer_security", "torvalds/linux", "releases/tag/v1.0", "watch?v=dQw4w9WgXcQ"
]

BENIGN_PARAMS = [
    "", "?page=2", "?lang=en", "?ref=homepage", "?category=tech&sort=recent",
    "?query=machine+learning&page=1", "?source=newsletter&utm_medium=email",
    "?id=84920&mode=view", "?session_id=none", "?filter=all&view=grid",
    "?v=12345&tab=overview", "?user_id=10293&format=json"
]

# Malicious / Phishing building blocks
SUSPICIOUS_BRANDS = [
    "paypal", "apple", "netflix", "microsoft", "google", "amazon", "chase",
    "wellsfargo", "bankofamerica", "facebook", "instagram", "coinbase", "binance",
    "metamask", "whatsapp", "dropbox", "dhl", "fedex", "usps", "irs-tax"
]

SUSPICIOUS_ACTIONS = [
    "login", "verify", "verification", "secure", "signin", "account-update",
    "banking-portal", "auth-session", "confirm-identity", "recover-wallet",
    "security-alert", "billing-resolve", "client-validation", "unlock-account",
    "passcode-reset", "ebayisapi", "webscr", "redirect-login"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".icu", ".work", ".live", ".cfd", ".sbs",
    ".bond", ".rest", ".quest", ".click", ".link", ".cc", ".tk", ".ml", ".ga"
]

SUSPICIOUS_FREE_HOSTS = [
    "firebaseapp.com", "web.app", "000webhostapp.com", "ngrok-free.app",
    "glitch.me", "weebly.com", "wixsite.com", "pages.dev", "duckdns.org"
]

def generate_benign_url():
    scheme = "https" if random.random() < 0.85 else "http"
    domain = random.choice(BENIGN_DOMAINS)
    if random.random() < 0.4:
        sub = random.choice(BENIGN_SUBDOMAINS)
        domain = f"{sub}.{domain}"
    path = random.choice(BENIGN_PATHS)
    param = random.choice(BENIGN_PARAMS)
    
    url = f"{scheme}://{domain}"
    if path:
        url += f"/{path}"
    if param:
        url += param
    return url

def generate_malicious_url():
    pattern_type = random.randint(1, 7)
    
    # Pattern 1: Brand spoofing with hyphen and keywords (without digits)
    if pattern_type == 1:
        brand = random.choice(SUSPICIOUS_BRANDS)
        action = random.choice(SUSPICIOUS_ACTIONS)
        tld = random.choice(SUSPICIOUS_TLDS)
        domain = f"{brand}-{action}{tld}"
        sub = random.choice(["login", "secure", "verify", "auth", "portal", "account"])
        return f"http://{sub}.{domain}/signin/index.php"

    # Pattern 2: Brand spoofing with numbers
    elif pattern_type == 2:
        brand = random.choice(SUSPICIOUS_BRANDS)
        action = random.choice(SUSPICIOUS_ACTIONS)
        tld = random.choice(SUSPICIOUS_TLDS)
        domain = f"{brand}-{action}{random.randint(10, 999)}{tld}"
        sub = random.choice(["login", "secure", "verify", "auth", "portal"])
        return f"http://{sub}.{domain}/cgi-bin/update.php?id={random.randint(1000, 99999)}&key={random.randint(100, 999)}"

    # Pattern 3: Multi-level deceptive subdomains
    elif pattern_type == 3:
        brand = random.choice(SUSPICIOUS_BRANDS)
        action = random.choice(SUSPICIOUS_ACTIONS)
        free_host = random.choice(SUSPICIOUS_FREE_HOSTS)
        return f"http://{brand}.{action}.account-user.{free_host}/login.html"

    # Pattern 4: IP Address Host URL (direct IP phishing/malware delivery)
    elif pattern_type == 4:
        ip = f"{random.randint(11, 215)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        port = f":{random.choice([8080, 8888, 8000, 4443, 8443, 9090])}" if random.random() < 0.4 else ""
        brand = random.choice(SUSPICIOUS_BRANDS)
        action = random.choice(SUSPICIOUS_ACTIONS)
        return f"http://{ip}{port}/{brand}/{action}/verification.php?client_id={random.randint(10000, 99999)}"

    # Pattern 5: High-entropy DGA / Random malware distribution domain
    elif pattern_type == 5:
        random_chars = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(14, 28)))
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{random_chars}{tld}/download/payload_{random.randint(100, 999)}.exe"

    # Pattern 6: Credential harvester with @ symbol trick or nested redirect
    elif pattern_type == 6:
        brand = random.choice(SUSPICIOUS_BRANDS)
        target_domain = random.choice(BENIGN_DOMAINS)
        evil_domain = f"secure-{brand}-login.info"
        return f"http://{target_domain}@{evil_domain}/signin/index.php"

    # Pattern 7: Generic suspicious login / verify URL (like login-verify-account.com)
    else:
        domain = random.choice([
            "login-verify-account.com", "secure-account-verification.net",
            "verify-security-login.xyz", "appleid-login-recover.cc",
            "paypal-resolve-case.com", "banking-auth-portal.top"
        ])
        path = random.choice(["auth", "login", "verify", "webscr", "confirm"])
        return f"http://{domain}/{path}"

def build_dataset(output_path: str, count_per_class: int = 15000):
    print(f"Generating balanced dataset of {count_per_class * 2} URLs...")
    urls = []
    
    # Generate benign
    for _ in range(count_per_class):
        urls.append({"url": generate_benign_url(), "label": 0})
        
    # Generate malicious
    for _ in range(count_per_class):
        urls.append({"url": generate_malicious_url(), "label": 1})
        
    random.shuffle(urls)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(urls)
        
    print(f"Dataset successfully created at {output_path} with {len(urls)} samples.")

if __name__ == "__main__":
    output_file = os.path.join(os.path.dirname(__file__), "..", "data", "urls_dataset.csv")
    build_dataset(output_file, count_per_class=15000)
