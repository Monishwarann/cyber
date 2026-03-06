"""
URL Feature Extraction Engine for Cyber Shield.
Extracts structural, lexical, and statistical features from URLs
for phishing detection analysis.
"""
import re
import math
import socket
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import List, Dict, Tuple
import tldextract  # type: ignore[import]

# Configure tldextract to use /tmp for cache (needed for Vercel/Read-only FS)
extract = tldextract.TLDExtract(cache_dir='/tmp/.tldextract_cache')


# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'pw', 'cc',
    'club', 'work', 'date', 'stream', 'download', 'racing',
    'win', 'bid', 'link', 'click', 'loan', 'trade', 'party',
    'science', 'review', 'accountant', 'cricket', 'faith'
}

# Suspicious keywords in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification',
    'update', 'secure', 'security', 'account', 'banking',
    'confirm', 'password', 'credential', 'authenticate',
    'wallet', 'paypal', 'amazon', 'apple', 'microsoft',
    'google', 'facebook', 'netflix', 'instagram', 'bank',
    'alert', 'suspend', 'restrict', 'unusual', 'locked',
    'expire', 'urgent', 'immediately', 'limited', 'offer',
    'free', 'winner', 'prize', 'reward', 'bonus', 'claim',
    'webscr', 'cmd', 'redirect', 'checkout', 'payment'
]

# Known brand domains (for impersonation detection)
BRAND_DOMAINS = {
    'paypal.com', 'google.com', 'facebook.com', 'amazon.com',
    'apple.com', 'microsoft.com', 'netflix.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'dropbox.com', 'adobe.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'americanexpress.com', 'citibank.com', 'usbank.com'
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length)
                    for count in counter.values())
    return round(entropy, 4)


def has_ip_address(url: str) -> bool:
    """Check if URL contains an IP address instead of a domain."""
    ip_patterns = [
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'0x[0-9a-fA-F]+',
        r'\d{8,10}',
    ]
    for pattern in ip_patterns:
        if re.search(pattern, urlparse(url).netloc):
            return True
    return False


def detect_homoglyphs(domain: str) -> List[str]:
    """Detect homoglyph attacks in domain names."""
    homoglyph_map = {
        '0': 'o', '1': 'l', 'l': 'I', 'rn': 'm',
        'vv': 'w', 'cl': 'd', 'nn': 'm'
    }
    findings = []
    for fake, real in homoglyph_map.items():
        if fake in domain.lower():
            findings.append(f"Possible homoglyph: '{fake}' may impersonate '{real}'")
    return findings


def check_brand_impersonation(domain: str) -> List[str]:
    """Check if the domain is attempting to impersonate a known brand."""
    findings = []
    extracted = extract(domain)
    full_domain = f"{extracted.domain}.{extracted.suffix}"

    for brand in BRAND_DOMAINS:
        brand_name = brand.split('.')[0]
        if brand_name in extracted.domain and full_domain != brand:
            findings.append(f"Possible impersonation of {brand}")

    return findings


def count_redirects(url: str) -> int:
    """Estimate redirect count from URL structure."""
    redirect_indicators = ['redirect', 'redir', 'url=', 'goto=', 'next=',
                           'return=', 'dest=', 'destination=', 'link=']
    count = sum(1 for indicator in redirect_indicators if indicator in url.lower())
    count += url.count('http') - 1  # Multiple http in URL
    return max(0, count)


def extract_url_features(url: str) -> Dict:
    """
    Extract comprehensive features from a URL for phishing detection.
    Returns a dictionary of features for ML analysis.
    """
    try:
        parsed = urlparse(url)
        extracted = extract(url)

        # Basic URL features
        url_length = len(url)
        domain = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""

        # Count special characters
        num_dots = url.count('.')
        num_hyphens = url.count('-')
        num_underscores = url.count('_')
        num_at = url.count('@')
        num_tilde = url.count('~')
        num_percent = url.count('%')
        num_ampersand = url.count('&')
        num_hash = url.count('#')
        num_equal = url.count('=')

        # Query parameters
        params = parse_qs(query)
        num_params = len(params)
        num_fragments = 1 if fragment else 0

        # Subdomain analysis
        subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
        num_subdomains = len([s for s in subdomains if s])

        # Protocol
        has_https = parsed.scheme == 'https'

        # IP address check
        has_ip = has_ip_address(url)

        # Domain features
        domain_length = len(extracted.domain)
        path_length = len(path)

        # TLD check
        has_suspicious_tld = extracted.suffix.lower() in SUSPICIOUS_TLDS

        # Entropy
        url_entropy = calculate_entropy(url)
        domain_entropy = calculate_entropy(domain)

        # Suspicious keywords
        url_lower = url.lower()
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

        # Redirect analysis
        redirect_count = count_redirects(url)

        # Homoglyph detection
        homoglyphs = detect_homoglyphs(domain)

        # Brand impersonation
        brand_impersonation = check_brand_impersonation(domain)

        # Path depth
        path_depth = len([p for p in path.split('/') if p])

        # Digit ratio in domain
        digit_count = sum(1 for c in extracted.domain if c.isdigit())
        digit_ratio = digit_count / max(len(extracted.domain), 1)

        # Special character ratio
        special_chars = sum(1 for c in url if not c.isalnum())
        special_ratio = special_chars / max(len(url), 1)

        features = {
            "length": url_length,
            "num_dots": num_dots,
            "num_hyphens": num_hyphens,
            "num_underscores": num_underscores,
            "num_at": num_at,
            "num_tilde": num_tilde,
            "num_percent": num_percent,
            "num_params": num_params,
            "num_fragments": num_fragments,
            "num_subdomains": num_subdomains,
            "has_ip": has_ip,
            "has_https": has_https,
            "domain_length": domain_length,
            "path_length": path_length,
            "path_depth": path_depth,
            "has_suspicious_tld": has_suspicious_tld,
            "entropy": url_entropy,
            "domain_entropy": domain_entropy,
            "digit_ratio": round(digit_ratio, 4),
            "special_char_ratio": round(special_ratio, 4),
            "suspicious_keywords": found_keywords,
            "redirect_count": redirect_count,
            "homoglyphs": homoglyphs,
            "brand_impersonation": brand_impersonation,
        }

        return features

    except Exception as e:
        return {
            "length": len(url),
            "num_dots": 0,
            "num_hyphens": 0,
            "num_underscores": 0,
            "num_at": 0,
            "num_tilde": 0,
            "num_percent": 0,
            "num_params": 0,
            "num_fragments": 0,
            "num_subdomains": 0,
            "has_ip": False,
            "has_https": False,
            "domain_length": 0,
            "path_length": 0,
            "path_depth": 0,
            "has_suspicious_tld": False,
            "entropy": 0,
            "domain_entropy": 0,
            "digit_ratio": 0,
            "special_char_ratio": 0,
            "suspicious_keywords": [],
            "redirect_count": 0,
            "homoglyphs": [],
            "brand_impersonation": [],
            "error": str(e),
        }


def compute_url_risk_score(features: Dict) -> float:
    """
    Compute a risk score (0-1) based on URL features.
    Uses weighted feature scoring.
    """
    score = 0.0
    weights = {
        "length": 0.05,
        "dots": 0.05,
        "hyphens": 0.04,
        "at_sign": 0.10,
        "ip_address": 0.15,
        "no_https": 0.08,
        "suspicious_tld": 0.10,
        "high_entropy": 0.06,
        "suspicious_keywords": 0.12,
        "subdomains": 0.06,
        "redirects": 0.08,
        "homoglyphs": 0.06,
        "brand_impersonation": 0.12,
        "digit_ratio": 0.04,
        "special_ratio": 0.04,
    }

    # Length risk (longer URLs more suspicious)
    if features["length"] > 75:
        score += weights["length"]
    if features["length"] > 150:
        score += weights["length"]

    # Dots (many subdomains)
    if features["num_dots"] > 4:
        score += weights["dots"]

    # Hyphens
    if features["num_hyphens"] > 3:
        score += weights["hyphens"]

    # @ sign (almost always phishing)
    if features["num_at"] > 0:
        score += weights["at_sign"]

    # IP address
    if features["has_ip"]:
        score += weights["ip_address"]

    # No HTTPS
    if not features["has_https"]:
        score += weights["no_https"]

    # Suspicious TLD
    if features["has_suspicious_tld"]:
        score += weights["suspicious_tld"]

    # High entropy
    if features["entropy"] > 4.5:
        score += weights["high_entropy"]

    # Suspicious keywords
    keyword_count = len(features["suspicious_keywords"])
    if keyword_count > 0:
        score += min(weights["suspicious_keywords"], keyword_count * 0.03)

    # Many subdomains
    if features["num_subdomains"] > 2:
        score += weights["subdomains"]

    # Redirects
    if features["redirect_count"] > 0:
        score += min(weights["redirects"], features["redirect_count"] * 0.04)

    # Homoglyphs
    if features.get("homoglyphs"):
        score += weights["homoglyphs"]

    # Brand impersonation
    if features.get("brand_impersonation"):
        score += weights["brand_impersonation"]

    # Digit ratio
    if features["digit_ratio"] > 0.3:
        score += weights["digit_ratio"]

    # Special char ratio
    if features["special_char_ratio"] > 0.3:
        score += weights["special_ratio"]

    return min(round(score, 4), 1.0)
