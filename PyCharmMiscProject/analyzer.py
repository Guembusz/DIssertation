
import abc  # Abstract Base Classes (used to make 'blueprints' for other classes)
import difflib  # Helps us compare strings to see how similar they are (for typos)
import json  # Lets us read .json files (how we store configuration settings)
import logging  # A professional version of print() that saves output to a file
import os  # Allows the user interact with the computer's operating system (like getting secret passwords)
import re  # Regular Expressions (advanced text searching)
import urllib.parse  # A tool designed to chop up URLs into parts (domain, path, etc.)
import math  # Basic math functions
import concurrent.futures  # Lets you do multiple things at the EXACT same time
from dataclasses import dataclass  # A quick way to make a class that just holds data
from enum import Enum  # creates fixed lists of options (like SAFE)
from logging.handlers import RotatingFileHandler  # Stops log files from getting too big by rotating them
from typing import Optional, List  # Helps us tell Python what type of data to expect (good for catching bugs)

import requests  # The standard tool for making web requests (like opening a webpage in code)


# SETTING UP LOGGER (The "Black Box" flight recorder)

# Use logging instead of print() to save a permanent record of what happens.
logger = logging.getLogger("QRSecurityEngine")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# This saves the logs to a file. If the file gets to 5MB, it starts a new one so it doesn't eat up hard drive space.
file_handler = RotatingFileHandler('security_audit.log', maxBytes=5 * 1024 * 1024, backupCount=3)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# This makes sure the logs also print to the console so the developer can see them live.
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


# LOADING SETTINGS (Configuration)

# Loads target brands from a separate file.
try:
    with open('config.json', 'r') as config_file:
        config_data = json.load(config_file)
        SUSPICIOUS_SHORTENERS = config_data.get("suspicious_shorteners", [])
        TARGET_BRANDS = config_data.get("target_brands", [])
        logger.info("Successfully loaded config.json")
except FileNotFoundError:
    # A "fallback" plan just in case the config.json file is missing
    logger.warning("config.json not found! Falling back to default lists.")
    SUSPICIOUS_SHORTENERS = ["bit.ly", "tinyurl.com"]
    TARGET_BRANDS = ["paypal", "apple", "google", "microsoft"]

# A 'Session' keeps the internet connection open, making multiple requests much faster.

# Network Optimization Reference:
# Utilizing a global requests.Session() to persist the TCP connection and
# enable HTTP Keep-Alive pooling, drastically reducing the latency of the
# HTTP HEAD unrolling requests (Reitz, Python Requests Documentation).
http_session = requests.Session()
http_session = requests.Session()



# DATA STRUCTURES (Custom Data Types)

class RiskLevel(Enum):
    """An Enum is a way to define a strict set of allowed values."""
    SAFE = "green"
    WARNING = "orange"
    MALICIOUS = "red"
    ERROR = "grey"


@dataclass
class ScanResult:
    """A Dataclass """
    status: str
    level: RiskLevel
    message: str
    severity: int  # A score from 0-100. Higher number = more dangerous.



# OBJECT-ORIENTED DESIGN

    """
    Abstract Base Class defining the interface for all security algorithms.

    Architectural Reference:
    Implements the 'Strategy Design Pattern' as defined by Gamma et al. (1994) 
    in 'Design Patterns: Elements of Reusable Object-Oriented Software'. 
    This allows algorithms to be encapsulated and executed interchangeably 
    without modifying the core multithreaded Controller logic.
    """


class ThreatHeuristic(abc.ABC):
    """Creates the blueprint """

    @abc.abstractmethod
    def evaluate(self, url: str, domain: str, path: str) -> Optional[ScanResult]:
        pass


class HomographHeuristic(ThreatHeuristic):
    """Checks if hackers are using foreign alphabet characters that look like English letters ."""

    def evaluate(self, url: str, domain: str, path: str) -> Optional[ScanResult]:
        # 'isascii()' checks if the letters are standard English keyboard letters.
        if not domain.isascii():
            logger.warning(f"Homograph attack detected! Non-ASCII characters in domain: {domain}")
            # Return a ScanResult with a high severity (100) as it's an attack
            return ScanResult("MALICIOUS", RiskLevel.MALICIOUS,
                              "IDN Homograph Attack Detected! Domain uses deceptive Unicode characters.", 100)
        return None  # If it's safe, return 'None'.



# MATHEMATICAL REFERENCE:
# Based on the string metric algorithm developed by Vladimir Levenshtein (1965).
# This class utilizes Python's native difflib.SequenceMatcher (based on the
# Ratcliff/Obershelp pattern recognition algorithm) to calculate the
# mathematical ratio of similarity between the payload and targeted corporate brands.



class TyposquattingHeuristic(ThreatHeuristic):
    """Checks for misspellings of famous brands ."""

    def evaluate(self, url: str, domain: str, path: str) -> Optional[ScanResult]:
        clean_domain = domain.replace("www.", "")
        domain_parts = re.split(r'[-.]', clean_domain)  # Splits 'google-login.com' into ['google', 'login', 'com']

        for brand in TARGET_BRANDS:
            for part in domain_parts:
                # SequenceMatcher compares two words and gives a score from 0.0 to 1.0 based on how similar they are.
                similarity = difflib.SequenceMatcher(None, brand.lower(), part.lower()).ratio()

                # If they are 80% similar, but NOT the exact real domain, it's probably a typo-squatter
                if similarity >= 0.8:
                    if not clean_domain.endswith(f"{brand}.com") and not clean_domain.endswith(f"{brand}.co.uk"):
                        logger.info(f"Fuzzy match detected! '{part}' is suspiciously close to '{brand}'")
                        return ScanResult("MALICIOUS", RiskLevel.MALICIOUS,
                                          f"Brand spoofing/Typosquatting detected targeting {brand.capitalize()}!", 90)
        return None


class EntropyHeuristic(ThreatHeuristic):
    """Math check: Uses Shannon Entropy to mathematically prove if a string is randomized."""

    def evaluate(self, url: str, domain: str, path: str) -> Optional[ScanResult]:
        if not path:
            return None
        entropy = 0
        for x in set(path):
            p_x = float(path.count(x)) / len(path)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)

        if entropy > 4.2:  # 4.2 is a threshold. Anything higher is highly chaotic/random.
            return ScanResult("MALICIOUS", RiskLevel.MALICIOUS,
                              "High Shannon Entropy detected! URL mathematically flagged as randomized/DGA.", 80)
        return None


class GoogleSafeBrowsingHeuristic(ThreatHeuristic):
    """Asks Google's database if they have seen this bad link before."""

    def evaluate(self, url: str, domain: str, path: str) -> Optional[ScanResult]:
        # NEVER type passwords directly in code. So it gets it from the computer's 'Environment Variables'
        api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "YOUR_API_KEY_HERE")
        if api_key == "YOUR_API_KEY_HERE":
            return None  # If the developer forgot to add their API key, just skip this check quietly.

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
            # Send the request over the internet to Google
            response = http_session.post(api_url, json=payload, timeout=5)
            if "matches" in response.json():
                return ScanResult("MALICIOUS", RiskLevel.MALICIOUS,
                                  "Flagged as malware/phishing by Google Safe Browsing API!", 95)
        except requests.RequestException:
            pass  # If internet is broken, don't crash the app. Just skip it.
        return None



# THE MAIN ENGINE

class QRAnalyzerEngine:
    """The manager that holds all security checks and runs them."""

    def __init__(self):
        # Hands the Engine all the security tests it needs to run.
        self.heuristics: List[ThreatHeuristic] = [
            HomographHeuristic(),
            TyposquattingHeuristic(),
            EntropyHeuristic(),
            GoogleSafeBrowsingHeuristic()
        ]

    def _expand_url(self, url: str, max_redirects: int = 3) -> str:
        """Helper tool: Un-hides links like bit.ly by following where they go."""
        current_url = url
        for _ in range(max_redirects):
            try:
                response = http_session.head(current_url, allow_redirects=False, timeout=5)
                # HTTP codes 301 and 302 mean "Redirect: Go to this other page instead"
                if response.status_code in [301, 302, 303, 307, 308]:
                    current_url = response.headers.get('Location', current_url)
                else:
                    break
            except requests.RequestException as e:
                break
        return current_url

    def analyze(self, payload: str) -> ScanResult:
        """This is the main function that receives the QR code text and decides if it is safe."""
        logger.info(f"Analyzing Payload: {payload}")

        try:
            # Parses the URL into useful pieces
            parsed_url = urllib.parse.urlparse(payload)
            if not all([parsed_url.scheme, parsed_url.netloc]):
                return ScanResult("SAFE", RiskLevel.SAFE, "Payload is plain text (Not a clickable link).", 0)
        except ValueError:
            return ScanResult("ERROR", RiskLevel.ERROR, "Could not parse payload.", 0)

        original_domain = parsed_url.netloc.lower()
        current_url = payload

        # Step 1: Pre-Processing. Un-shorten URLs if they are using bit.ly or tinyurl.
        for shortener in SUSPICIOUS_SHORTENERS:
            if shortener in original_domain:
                logger.info(f"URL Shortener detected ({shortener}). Tracing...")
                current_url = self._expand_url(payload)
                parsed_url = urllib.parse.urlparse(current_url)  # Re-chop the newly discovered, un-hidden URL
                break

        final_domain = parsed_url.netloc.lower()
        final_path = parsed_url.path

        # Collect any warnings or errors in this empty list
        results: List[ScanResult] = []

        # Step 2: Check for older, unencrypted HTTP websites.
        if parsed_url.scheme == "http":
            results.append(
                ScanResult("WARNING", RiskLevel.WARNING, f"Unencrypted HTTP connection to {final_domain}.", 50))


        # MULTI-THREADING (Running tasks at the exact same time)

        # Normally, code runs line-by-line.
        # A ThreadPoolExecutor hires "virtual workers" to do the jobs at the exact same time.
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.heuristics)) as executor:

            # Hand a job to each worker
            futures = [
                executor.submit(heuristic.evaluate, current_url, final_domain, final_path)
                for heuristic in self.heuristics
            ]

            # As soon as a worker finishes their job, grab their result and put it in the 'results' list
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        # Step 4: Final Evaluation
        # If any checks found a threat, sort them by 'Severity' (most dangerous at the top)
        if results:
            # lambda x: x.severity is a mini-function telling Python to look at the 'severity' number to sort them.
            results.sort(key=lambda x: x.severity, reverse=True)
            return results[0]  # Return the single most dangerous threat found

        # If the 'results' list is still empty, the website passed every test!
        return ScanResult("SAFE", RiskLevel.SAFE, f"URL ({final_domain}) passed all security checks.", 0)



# WRAPPERS (Making sure older code doesn't break)

# Create one main Engine object to be used by the rest of the application
engine_instance = QRAnalyzerEngine()


def analyze_qr_data(payload: str) -> ScanResult:
    """Other files (like app.py) call this simple function, and pass it to the complex Engine."""
    return engine_instance.analyze(payload)


# These two functions are just here so that the existing 'tests.py' file doesn't crash.
# They pretend to be the old functions, but actually route the test to our new OOP system.
def check_heuristics(domain: str, path: str) -> bool:
    res = TyposquattingHeuristic().evaluate("dummy", domain, path)
    return res is not None

# MATHEMATICAL REFERENCE:
# Based on the foundational Information Theory mathematics proposed by
# Claude E. Shannon (1948) in 'A Mathematical Theory of Communication'.
# Equation: H(X) = -sum(P(x_i) * log2(P(x_i)))
# The algorithm calculates the probability of each character's occurrence
# and computes the negative sum of these probabilities multiplied by their base-2 logarithm.
def calculate_shannon_entropy(path: str) -> float:
    if not path:
        return 0
    entropy = 0
    for x in set(path):
        p_x = float(path.count(x)) / len(path)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy