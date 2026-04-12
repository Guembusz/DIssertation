import difflib
import json
import logging
import os
import re
import urllib.parse
import math
import concurrent.futures
from dataclasses import dataclass
from enum import Enum
from logging.handlers import RotatingFileHandler

import requests

# --- CONFIGURATION & PERSISTENT LOGGING ---
# Create an enterprise-grade logger that writes to a file and the console
logger = logging.getLogger("QRSecurityEngine")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# 1. File Handler (Keeps an audit trail, max 5MB per file, keeps 3 backups)
file_handler = RotatingFileHandler('security_audit.log', maxBytes=5*1024*1024, backupCount=3)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# 2. Console Handler (So you can still see it in the terminal)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Note: Update all `logging.info(...)` calls in your code to `logger.info(...)`
# Update all `logging.warning(...)` to `logger.warning(...)`

# --- LOAD EXTERNAL CONFIGURATION ---
try:
    with open('config.json', 'r') as config_file:
        config_data = json.load(config_file)
        SUSPICIOUS_SHORTENERS = config_data.get("suspicious_shorteners", [])
        TARGET_BRANDS = config_data.get("target_brands", [])
        logger.info("Successfully loaded config.json")
except FileNotFoundError:
    logger.warning("config.json not found! Falling back to default lists.")
    # Fallback lists just in case the user deletes the file
    SUSPICIOUS_SHORTENERS = ["bit.ly", "tinyurl.com"]
    TARGET_BRANDS = ["paypal", "apple", "google"]

# Reusable HTTP session for connection pooling (Faster API calls)
http_session = requests.Session()


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
    current_url = url
    for _ in range(max_redirects):
        try:
            response = http_session.head(current_url, allow_redirects=False, timeout=5)
            if response.status_code in [301, 302, 303, 307, 308]:
                current_url = response.headers.get('Location', current_url)
            else:
                break
        except requests.RequestException as e:
            logger.warning(f"Failed to expand URL {current_url}: {e}")
            break
    return current_url

# --- LAYER 2: ADVANCED HEURISTICS (FUZZY MATCHING) ---
def check_heuristics(domain: str, path: str) -> bool:
    clean_domain = domain.replace("www.", "")
    domain_parts = re.split(r'[-.]', clean_domain)

    for brand in TARGET_BRANDS:
        for part in domain_parts:
            similarity = difflib.SequenceMatcher(None, brand.lower(), part.lower()).ratio()
            if similarity >= 0.8:
                if not clean_domain.endswith(f"{brand}.com") and not clean_domain.endswith(f"{brand}.co.uk"):
                    logger.info(f"Fuzzy match detected! '{part}' is suspiciously close to '{brand}'")
                    return True
    return False

# --- LAYER 3: MATHEMATICAL HEURISTICS (REPLACED ML) ---
def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon entropy of a string to detect randomized domains/paths.
    In a dissertation, explain this detects Domain Generation Algorithms (DGAs)
    by mathematically proving the string contains highly randomized characters.
    """
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy



# --- Layer 4 : Detection of Homograph Attacks
def detect_homograph_attack(domain: str) -> bool:
    """
    Detects Internationalized Domain Name (IDN) Homograph attacks.
    If a domain contains non-ASCII characters, it might be spoofing a Western brand.
    """
    # If the domain cannot be represented purely in standard ASCII,
    # it contains foreign/unicode characters often used in visual spoofing.
    if not domain.isascii():
        logging.warning(f"Homograph attack detected! Non-ASCII characters in domain: {domain}")
        return True
    return False

# --- LAYER 4: THREAT INTELLIGENCE API ---
def check_google_safe_browsing(url: str) -> str:
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
    logger.info(f"Analyzing Payload: {payload}")

    try:
        parsed_url = urllib.parse.urlparse(payload)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            return ScanResult("SAFE", RiskLevel.SAFE, "Payload is plain text (Not a clickable link).")
    except ValueError:
        return ScanResult("ERROR", RiskLevel.ERROR, "Could not parse payload.")

    original_domain = parsed_url.netloc.lower()
    current_url = payload

    # 1. Un-shorten (Must happen sequentially before we analyze the final URL)
    for shortener in SUSPICIOUS_SHORTENERS:
        if shortener in original_domain:
            logger.info(f"URL Shortener detected ({shortener}). Tracing...")
            current_url = expand_url(payload)
            parsed_url = urllib.parse.urlparse(current_url)
            break

    final_domain = parsed_url.netloc.lower()
    final_path = parsed_url.path

    # 2. Check HTTP vs HTTPS
    if parsed_url.scheme == "http":
        return ScanResult("WARNING", RiskLevel.WARNING, f"Unencrypted HTTP connection to {final_domain}.")

    # 3. CONCURRENT EXECUTION LAYER (Architecture Upgrade)
    # Run heavy network and math checks simultaneously to optimize system latency
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        # Submit tasks to the thread pool
        future_api = executor.submit(check_google_safe_browsing, current_url)
        future_heuristics = executor.submit(check_heuristics, final_domain, final_path)
        future_homograph = executor.submit(detect_homograph_attack, final_domain)
        future_entropy = executor.submit(calculate_shannon_entropy, final_path)

        # Retrieve results as the threads finish their work
        api_result = future_api.result()
        is_typosquatting = future_heuristics.result()
        is_homograph = future_homograph.result()
        path_entropy = future_entropy.result()

    # 4. EVALUATE THREATS (Ordered by severity and determinism)
    if is_homograph:
        return ScanResult("MALICIOUS", RiskLevel.MALICIOUS,
                          "IDN Homograph Attack Detected! Domain uses deceptive Unicode characters.")

    if is_typosquatting:
        return ScanResult("MALICIOUS", RiskLevel.MALICIOUS, "Brand spoofing/Typosquatting detected!")

    if path_entropy > 4.2:
        return ScanResult("MALICIOUS", RiskLevel.MALICIOUS,
                          "High Shannon Entropy detected! URL mathematically flagged as randomized/DGA.")

    if api_result == "THREAT_FOUND":
        return ScanResult("MALICIOUS", RiskLevel.MALICIOUS, "Flagged as malware/phishing by Google Safe Browsing!")

    # 5. Passed all checks
    return ScanResult("SAFE", RiskLevel.SAFE, f"URL ({final_domain}) passed all security checks.")