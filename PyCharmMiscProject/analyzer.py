import urllib.parse
import requests
import re
import os
import difflib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import List

# --- CONFIGURATION & LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SUSPICIOUS_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]
TARGET_BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "bank"]

# Reusable HTTP session for connection pooling (Faster API calls)
http_session = requests.Session()


# --- DATA STRUCTURES ---
class RiskLevel(Enum):
    SAFE = "green"
    WARNING = "orange"
    MALICIOUS = "red"
    ERROR = "grey"


@dataclass
class ScanResult:
    status: str
    level: RiskLevel
    message: str


# --- LAYER 1: UN-SHORTENER ---
def expand_url(url: str, max_redirects: int = 3) -> str:
    """Securely traces a shortened URL to its true destination, preventing infinite loops."""
    current_url = url
    for _ in range(max_redirects):
        try:
            response = http_session.head(current_url, allow_redirects=False, timeout=5)
            if response.status_code in [301, 302, 303, 307, 308]:
                current_url = response.headers.get('Location', current_url)
            else:
                break  # Reached the final destination
        except requests.RequestException as e:
            logging.warning(f"Failed to expand URL {current_url}: {e}")
            break
    return current_url


# --- LAYER 2: ADVANCED HEURISTICS (FUZZY MATCHING) ---
def check_heuristics(domain: str, path: str) -> bool:
    """Uses Levenshtein distance (fuzzy matching) to catch typosquatting."""
    clean_domain = domain.replace("www.", "")
    domain_parts = re.split(r'[-.]', clean_domain)

    for brand in TARGET_BRANDS:
        for part in domain_parts:
            # Calculate similarity ratio (e.g., "paypa1" vs "paypal" is highly similar)
            similarity = difflib.SequenceMatcher(None, brand.lower(), part.lower()).ratio()

            if similarity >= 0.8:
                if not clean_domain.endswith(f"{brand}.com") and not clean_domain.endswith(f"{brand}.co.uk"):
                    logging.info(f"Fuzzy match detected! '{part}' is suspiciously close to '{brand}'")
                    return True
    return False


# --- LAYER 3: MACHINE LEARNING HOOK (PLACEHOLDER) ---
def ml_threat_score(url: str) -> float:
    """
    Placeholder for your Scikit-Learn Random Forest model.
    In your final project, this would extract features (URL length, special chars)
    and pass them to a loaded .pkl model to return a threat probability.
    """
    # Example logic: if the URL has an IP address instead of a domain name, it's highly suspicious.
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", urllib.parse.urlparse(url).netloc):
        return 0.95
    return 0.10  # Safe baseline


# --- LAYER 4: THREAT INTELLIGENCE API ---
def check_google_safe_browsing(url: str) -> str:
    """Queries Google Safe Browsing API using pooled sessions."""
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "YOUR_API_KEY_HERE")

    if api_key == "YOUR_API_KEY_HERE":
        return "API_NOT_CONFIGURED"

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "secure-qr-sandbox", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = http_session.post(api_url, json=payload, timeout=5)
        if "matches" in response.json():
            return "THREAT_FOUND"
        return "CLEAN"
    except requests.RequestException:
        return "API_ERROR"


# --- THE MAIN ANALYZER FUNCTION ---
def analyze_qr_data(payload: str) -> ScanResult:
    """The master function. Runs the payload through all security layers."""
    logging.info(f"Analyzing Payload: {payload}")

    try:
        parsed_url = urllib.parse.urlparse(payload)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            return ScanResult("SAFE", RiskLevel.SAFE, "Payload is plain text (Not a clickable link).")
    except ValueError:
        return ScanResult("ERROR", RiskLevel.ERROR, "Could not parse payload.")

    original_domain = parsed_url.netloc.lower()
    current_url = payload

    # 1. Un-shorten
    for shortener in SUSPICIOUS_SHORTENERS:
        if shortener in original_domain:
            logging.info(f"URL Shortener detected ({shortener}). Tracing...")
            current_url = expand_url(payload)
            parsed_url = urllib.parse.urlparse(current_url)
            break

    final_domain = parsed_url.netloc.lower()
    final_path = parsed_url.path

    # 2. Check HTTP vs HTTPS
    if parsed_url.scheme == "http":
        return ScanResult("WARNING", RiskLevel.WARNING, f"Unencrypted HTTP connection to {final_domain}.")

    # 3. Heuristics & ML
    if check_heuristics(final_domain, final_path):
        return ScanResult("MALICIOUS", RiskLevel.MALICIOUS, "Brand spoofing/Typosquatting detected!")

    if ml_threat_score(current_url) > 0.85:
        return ScanResult("MALICIOUS", RiskLevel.MALICIOUS,
                          "Machine Learning model flagged this URL structure as anomalous.")

    # 4. Google Safe Browsing
    api_result = check_google_safe_browsing(current_url)
    if api_result == "THREAT_FOUND":
        return ScanResult("MALICIOUS", RiskLevel.MALICIOUS, "Flagged as malware/phishing by Google Safe Browsing!")

    return ScanResult("SAFE", RiskLevel.SAFE, f"URL ({final_domain}) passed all security checks.")