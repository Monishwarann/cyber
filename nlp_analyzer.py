"""
NLP Analyzer for Cyber Shield.
Analyzes text content (emails, SMS, messages) for phishing indicators
using pattern matching, keyword analysis, and heuristic scoring.
"""
import re
from typing import Dict, List, Tuple
from collections import Counter


# ─── Phishing Indicator Patterns ────────────────────────────────

URGENCY_PHRASES = [
    r'immediate(?:ly)?', r'urgent(?:ly)?', r'right\s+away', r'as\s+soon\s+as\s+possible',
    r'within\s+\d+\s+hours?', r'within\s+\d+\s+days?', r'expires?\s+(?:soon|today)',
    r'act\s+now', r'don\'?t\s+delay', r'time\s+(?:is\s+)?(?:running\s+out|limited|sensitive)',
    r'last\s+chance', r'final\s+(?:notice|warning|reminder)',
    r'account\s+(?:will\s+be\s+)?(?:suspended|closed|terminated|locked|restricted)',
    r'deadline', r'(?:only|just)\s+\d+\s+(?:hours?|minutes?|days?)\s+left',
]

FEAR_PHRASES = [
    r'unauthorized\s+(?:access|activity|transaction)',
    r'suspicious\s+(?:activity|login|sign[\s-]?in)',
    r'security\s+(?:alert|breach|issue|concern|threat)',
    r'compromised?\s+account', r'identity\s+(?:theft|stolen)',
    r'fraud(?:ulent)?', r'unusual\s+(?:activity|sign[\s-]?in)',
    r'someone\s+(?:tried|attempted)\s+to', r'data\s+breach',
    r'hack(?:ed|ing)?', r'malware', r'virus\s+detected',
]

AUTHORITY_PHRASES = [
    r'customer\s+(?:service|support)', r'security\s+(?:team|department)',
    r'account\s+(?:team|department|services?)', r'technical\s+support',
    r'help\s+desk', r'it\s+department', r'admin(?:istrator|istration)?',
    r'compliance\s+(?:team|department|office)', r'legal\s+(?:team|department)',
]

REWARD_PHRASES = [
    r'congratulations?', r'you\'?ve?\s+(?:been\s+)?(?:won|selected|chosen)',
    r'free\s+(?:gift|offer|trial)', r'special\s+offer',
    r'exclusive\s+(?:deal|offer|discount)', r'limited\s+time\s+offer',
    r'claim\s+your\s+(?:prize|reward|gift)', r'bonus',
    r'lottery', r'winner', r'jackpot', r'million\s+dollars?',
]

ACTION_PHRASES = [
    r'click\s+(?:here|below|the\s+link)', r'verify\s+your\s+(?:account|identity|email)',
    r'confirm\s+your\s+(?:account|identity|details|information)',
    r'update\s+your\s+(?:account|information|details|password|payment)',
    r'log\s*in\s+(?:to|and)\s+(?:your|confirm|verify)',
    r'sign\s+in\s+(?:to|and)', r'enter\s+your\s+(?:password|credentials|details)',
    r'provide\s+your\s+(?:information|details|credentials)',
    r'reset\s+your\s+password', r'download\s+(?:the\s+)?attachment',
    r'open\s+(?:the\s+)?(?:attached|enclosed)\s+(?:file|document)',
]

IMPERSONATION_PATTERNS = [
    r'(?:paypal|amazon|apple|google|microsoft|facebook|netflix|instagram|twitter)',
    r'(?:bank\s+of\s+america|wells?\s+fargo|chase|citibank)',
    r'(?:irs|fbi|cia|doj|dhs|sec)', r'(?:ups|fedex|dhl|usps)',
]

GRAMMAR_ISSUES = [
    r'dear\s+(?:customer|user|sir|madam|valued\s+(?:customer|user))',
    r'(?:kindly|humbly)\s+(?:verify|confirm|update|click|provide)',
    r'your\s+(?:account|identity)\s+(?:has|have)\s+been',
    r'(?:we|i)\s+(?:have|has)\s+(?:detected|noticed|observed)',
]


def analyze_text_patterns(text: str) -> Dict[str, List[str]]:
    """Analyze text for various phishing patterns."""
    text_lower = text.lower()
    findings = {
        "urgency": [],
        "fear": [],
        "authority": [],
        "reward": [],
        "action_required": [],
        "impersonation": [],
        "grammar_issues": [],
    }

    pattern_groups = [
        ("urgency", URGENCY_PHRASES),
        ("fear", FEAR_PHRASES),
        ("authority", AUTHORITY_PHRASES),
        ("reward", REWARD_PHRASES),
        ("action_required", ACTION_PHRASES),
        ("impersonation", IMPERSONATION_PATTERNS),
        ("grammar_issues", GRAMMAR_ISSUES),
    ]

    for category, patterns in pattern_groups:
        for pattern in patterns:
            matches = re.findall(pattern, text_lower)
            if matches:
                findings[category].extend(matches)

    return findings


def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from text content."""
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
    return re.findall(url_pattern, text)


def detect_obfuscation(text: str) -> List[str]:
    """Detect text obfuscation techniques."""
    findings = []

    # Check for zero-width characters
    if re.search(r'[\u200b\u200c\u200d\ufeff]', text):
        findings.append("Zero-width characters detected (text obfuscation)")

    # Check for excessive Unicode
    non_ascii = sum(1 for c in text if ord(c) > 127)
    if non_ascii / max(len(text), 1) > 0.1:
        findings.append("High ratio of non-ASCII characters")

    # Check for HTML entity encoding
    if re.search(r'&#\d+;|&\w+;', text):
        findings.append("HTML entity encoding detected")

    # Check for base64 strings
    if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', text):
        findings.append("Possible Base64 encoded content")

    # Shortened URLs
    short_url_domains = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly',
                         'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc']
    text_lower = text.lower()
    for domain in short_url_domains:
        if domain in text_lower:
            findings.append(f"Shortened URL detected ({domain})")

    return findings


def compute_nlp_risk_score(text: str) -> Tuple[float, Dict]:
    """
    Compute an NLP-based risk score for the given text.
    Returns (score, analysis_details).
    """
    if not text or len(text.strip()) < 10:
        return 0.0, {"error": "Text too short for analysis"}

    # Analyze patterns
    patterns = analyze_text_patterns(text)

    # Extract URLs
    urls = extract_urls_from_text(text)

    # Detect obfuscation
    obfuscation = detect_obfuscation(text)

    # Scoring
    weights = {
        "urgency": 0.15,
        "fear": 0.15,
        "authority": 0.05,
        "reward": 0.10,
        "action_required": 0.15,
        "impersonation": 0.15,
        "grammar_issues": 0.10,
        "urls": 0.08,
        "obfuscation": 0.12,
    }

    score = 0.0

    for category, matches in patterns.items():
        if matches:
            # More matches = higher score, capped at weight
            category_score = min(len(matches) * 0.04, weights[category])
            score += category_score

    # URLs in the text
    if urls:
        score += min(len(urls) * 0.03, weights["urls"])

    # Obfuscation
    if obfuscation:
        score += min(len(obfuscation) * 0.04, weights["obfuscation"])

    # Aggregate indicators
    all_indicators = []
    for category, matches in patterns.items():
        if matches:
            all_indicators.append(f"{category.replace('_', ' ').title()}: {', '.join(set(matches[:3]))}")
    for ob in obfuscation:
        all_indicators.append(f"Obfuscation: {ob}")
    if urls:
        all_indicators.append(f"Contains {len(urls)} URL(s)")

    # Manipulation tactics
    tactics = []
    if patterns["urgency"]:
        tactics.append("Urgency/Time pressure")
    if patterns["fear"]:
        tactics.append("Fear/Threat")
    if patterns["authority"]:
        tactics.append("Authority impersonation")
    if patterns["reward"]:
        tactics.append("Reward/Greed appeal")
    if patterns["action_required"]:
        tactics.append("Call-to-action manipulation")
    if patterns["impersonation"]:
        tactics.append("Brand impersonation")

    analysis = {
        "patterns": {k: len(v) for k, v in patterns.items()},
        "urls_found": urls,
        "obfuscation": obfuscation,
        "indicators": all_indicators,
        "manipulation_tactics": tactics,
        "urgency_level": "high" if len(patterns["urgency"]) > 2 else
                         "medium" if patterns["urgency"] else "low",
    }

    return min(round(score, 4), 1.0), analysis
