"""
ML Engine for Cyber Shield.
Implements ensemble machine learning models for phishing detection
using URL features and content analysis.
"""
import numpy as np  # type: ignore[import]
from typing import Dict, Tuple, List, Union
import json
import os


class PhishingMLEngine:
    """
    Ensemble ML engine for phishing detection.
    Uses weighted feature analysis with trained thresholds.
    """

    def __init__(self):
        self.is_loaded = True
        # Feature weights learned from phishing datasets
        self.url_feature_weights = {
            "length": 0.03,
            "num_dots": 0.05,
            "num_hyphens": 0.04,
            "num_at": 0.12,
            "has_ip": 0.15,
            "has_https": -0.08,  # Negative = reduces risk
            "has_suspicious_tld": 0.10,
            "entropy": 0.06,
            "num_subdomains": 0.05,
            "redirect_count": 0.08,
            "num_params": 0.03,
            "path_depth": 0.03,
            "digit_ratio": 0.05,
            "special_char_ratio": 0.04,
            "domain_length": 0.03,
            "suspicious_keywords_count": 0.10,
        }

        # Thresholds for classification
        self.thresholds = {
            "safe": 0.2,
            "low": 0.35,
            "medium": 0.55,
            "high": 0.75,
            "critical": 0.90,
        }

        # Ensemble weights for different model outputs
        self.ensemble_weights = {
            "url_ml": 0.20,
            "nlp": 0.15,
            "gemini": 0.25,
            "virustotal": 0.12,
            "abuseipdb": 0.08,
            "remote_ml": 0.20,
        }

        # VirusTotal escalation thresholds (malicious vendor count → minimum score)
        self.vt_escalation = [
            (20, 0.95),   # 20+ vendors → critical
            (10, 0.85),   # 10+ vendors → high
            (5,  0.75),   # 5+  vendors → high
            (3,  0.65),   # 3+  vendors → medium
            (1,  0.55),   # 1+  vendor  → medium
        ]

    def predict_url(self, features: Dict) -> Tuple[float, Dict]:
        """
        Predict phishing probability from URL features.
        Returns (score, details).
        """
        score = 0.0
        feature_contributions = {}

        # Normalize and weight features
        for feature, weight in self.url_feature_weights.items():
            value = 0

            if feature == "length":
                # Normalize URL length (0-200+ range)
                raw = features.get("length", 0)
                value = min(raw / 200.0, 1.0)
            elif feature == "num_dots":
                value = min(features.get("num_dots", 0) / 8.0, 1.0)
            elif feature == "num_hyphens":
                value = min(features.get("num_hyphens", 0) / 5.0, 1.0)
            elif feature == "num_at":
                value = 1.0 if features.get("num_at", 0) > 0 else 0.0
            elif feature == "has_ip":
                value = 1.0 if features.get("has_ip", False) else 0.0
            elif feature == "has_https":
                value = 1.0 if features.get("has_https", False) else 0.0
            elif feature == "has_suspicious_tld":
                value = 1.0 if features.get("has_suspicious_tld", False) else 0.0
            elif feature == "entropy":
                value = min(features.get("entropy", 0) / 6.0, 1.0)
            elif feature == "num_subdomains":
                value = min(features.get("num_subdomains", 0) / 5.0, 1.0)
            elif feature == "redirect_count":
                value = min(features.get("redirect_count", 0) / 3.0, 1.0)
            elif feature == "num_params":
                value = min(features.get("num_params", 0) / 5.0, 1.0)
            elif feature == "path_depth":
                value = min(features.get("path_depth", 0) / 6.0, 1.0)
            elif feature == "digit_ratio":
                value = features.get("digit_ratio", 0)
            elif feature == "special_char_ratio":
                value = features.get("special_char_ratio", 0)
            elif feature == "domain_length":
                value = min(features.get("domain_length", 0) / 30.0, 1.0)
            elif feature == "suspicious_keywords_count":
                value = min(len(features.get("suspicious_keywords", [])) / 5.0, 1.0)

            contribution = value * weight
            score += contribution
            if abs(contribution) > 0.01:
                feature_contributions[feature] = round(contribution, 4)

        # Apply sigmoid-like normalization
        score = 1 / (1 + np.exp(-10 * (score - 0.3)))
        score = round(float(score), 4)

        details = {
            "raw_score": score,
            "feature_contributions": feature_contributions,
            "top_risk_factors": sorted(
                feature_contributions.items(),
                key=lambda x: abs(x[1]),
                reverse=True
            )[:5],  # type: ignore[index]
        }

        return score, details

    def compute_ensemble_score(  # type: ignore[misc]
        self,
        url_ml_score: float = 0.0,
        nlp_score: float = 0.0,
        gemini_score: float = 0.0,
        virustotal_score: float = 0.0,
        abuseipdb_score: float = 0.0,
        remote_ml_score: float = 0.0,
        available_models: Union[Dict[str, bool], None] = None,
        vt_malicious_count: int = 0,
        gemini_is_fallback: bool = False,
        abuseipdb_abuse_score: int = 0,
    ) -> Tuple[float, str]:
        """
        Compute ensemble score from all model outputs.
        Handles missing model outputs gracefully.
        - Excludes Gemini from ensemble when it returns a fallback (invalid key).
        - Applies VirusTotal override escalation when many vendors flag a URL.
        """
        if available_models is None:
            available_models = {
                "url_ml": True,
                "nlp": True,
                "gemini": True,
                "virustotal": True,
                "abuseipdb": True,
                "remote_ml": True,
            }

        scores = {
            "url_ml": url_ml_score,
            "nlp": nlp_score,
            "gemini": gemini_score,
            "virustotal": virustotal_score,
            "abuseipdb": abuseipdb_score,
            "remote_ml": remote_ml_score,
        }

        # ── Exclude Gemini if it returned a fallback (invalid/leaked key) ──
        effective_available = dict(available_models)
        if gemini_is_fallback and effective_available.get("gemini"):
            effective_available["gemini"] = False

        # Calculate weighted average of available models
        total_weight = 0.0
        weighted_sum = 0.0

        for model_name, weight in self.ensemble_weights.items():
            if effective_available.get(model_name, False):
                weighted_sum = weighted_sum + float(scores[model_name]) * float(weight)  # type: ignore[operator]
                total_weight = total_weight + float(weight)  # type: ignore[operator]

        if total_weight == 0:
            return 0.5, "medium"

        ensemble_score = float(weighted_sum) / float(total_weight)

        # ── VirusTotal Override: escalate score if many vendors flag URL ──
        for vendor_threshold, min_score in self.vt_escalation:
            if vt_malicious_count >= vendor_threshold:
                if ensemble_score < min_score:
                    ensemble_score = min_score
                break

        # ── AbuseIPDB Override: high abuse confidence → floor the score ──
        if abuseipdb_abuse_score >= 80:
            ensemble_score = max(ensemble_score, 0.90)
        elif abuseipdb_abuse_score >= 50:
            ensemble_score = max(ensemble_score, 0.75)
        elif abuseipdb_abuse_score >= 25:
            ensemble_score = max(ensemble_score, 0.55)

        ensemble_score = round(float(ensemble_score), 4)

        # Determine threat level
        threat_level = "safe"
        for level, threshold in sorted(self.thresholds.items(),
                                        key=lambda x: x[1]):
            if ensemble_score >= threshold:
                threat_level = level

        return ensemble_score, threat_level

    def generate_explanation(  # type: ignore[misc]
        self,
        features: Dict,
        url_score: float,
        nlp_analysis: Dict,
        gemini_analysis: Union[Dict, None] = None,
        vt_result: Union[Dict, None] = None,
        abuseipdb_result: Union[Dict, None] = None,
    ) -> Tuple[str, List[str], List[str]]:
        """
        Generate human-readable explanation of the detection result.
        Returns (explanation, indicators, recommendations).
        """
        indicators = []
        recommendations = []

        # URL indicators
        if features.get("has_ip"):
            indicators.append("🔴 URL uses an IP address instead of a domain name")
        if features.get("has_suspicious_tld"):
            indicators.append("🟠 Domain uses a suspicious top-level domain")
        if not features.get("has_https"):
            indicators.append("🟡 Connection is not secured with HTTPS")
        if features.get("num_at", 0) > 0:
            indicators.append("🔴 URL contains @ symbol (URL obfuscation technique)")
        if len(features.get("suspicious_keywords", [])) > 0:
            kws = ", ".join(features["suspicious_keywords"][:5])
            indicators.append(f"🟠 Suspicious keywords detected: {kws}")
        if features.get("redirect_count", 0) > 0:
            indicators.append(f"🟡 Possible redirect chain detected ({features['redirect_count']} indicators)")
        if features.get("homoglyphs"):
            for h in features["homoglyphs"]:
                indicators.append(f"🔴 {h}")
        if features.get("brand_impersonation"):
            for b in features["brand_impersonation"]:
                indicators.append(f"🔴 {b}")
        if features.get("num_subdomains", 0) > 2:
            indicators.append(f"🟡 Excessive subdomains detected ({features['num_subdomains']})")
        if features.get("entropy", 0) > 4.5:
            indicators.append("🟡 High entropy in URL (possible random/generated domain)")

        # NLP indicators
        if nlp_analysis:
            for indicator in nlp_analysis.get("indicators", []):
                indicators.append(f"🟠 {indicator}")
            for tactic in nlp_analysis.get("manipulation_tactics", []):
                indicators.append(f"⚠️ Manipulation tactic: {tactic}")

        # Gemini indicators
        if gemini_analysis:
            for indicator in gemini_analysis.get("indicators", []):
                indicators.append(f"🤖 AI Detected: {indicator}")

        # VirusTotal indicators
        if vt_result and vt_result.get("detected"):
            indicators.append(
                f"🛡️ VirusTotal: {vt_result['positives']}/{vt_result['total_scanners']} "
                f"security vendors flagged this URL"
            )

        # AbuseIPDB indicators
        if abuseipdb_result and abuseipdb_result.get("detected"):
            score = abuseipdb_result.get("abuse_score", 0)
            ip = abuseipdb_result.get("ip_address", "unknown")
            reports = abuseipdb_result.get("total_reports", 0)
            cats = abuseipdb_result.get("threat_categories", [])
            indicators.append(
                f"🚨 AbuseIPDB: IP {ip} has {score}% abuse confidence "
                f"({reports} reports)"
            )
            if cats:
                indicators.append(
                    f"🚨 AbuseIPDB threat categories: {', '.join(cats[:5])}"
                )

        # Generate explanation
        if url_score > 0.75:
            explanation = (
                "⛔ HIGH RISK: This URL exhibits multiple strong phishing indicators. "
                "It is highly likely to be a phishing attempt designed to steal your credentials "
                "or personal information. DO NOT interact with this URL."
            )
            recommendations = [
                "Do not click any links on this page",
                "Do not enter any personal information",
                "Report this URL to your IT department",
                "If you already entered information, change your passwords immediately",
                "Enable two-factor authentication on your accounts",
            ]
        elif url_score > 0.55:
            explanation = (
                "⚠️ MEDIUM RISK: This URL shows several suspicious characteristics. "
                "Exercise extreme caution. Verify the legitimacy of the sender or website "
                "through official channels before interacting."
            )
            recommendations = [
                "Verify the sender through a separate, trusted channel",
                "Do not enter sensitive information without verification",
                "Check the URL carefully for misspellings or unusual characters",
                "Look for the padlock icon and valid SSL certificate",
            ]
        elif url_score > 0.35:
            explanation = (
                "🟡 LOW RISK: This URL shows some minor suspicious traits, but may be legitimate. "
                "Proceed with normal caution and verify if unsure."
            )
            recommendations = [
                "Verify the URL matches the expected website",
                "Be cautious with any requests for personal information",
            ]
        else:
            explanation = (
                "✅ SAFE: This URL appears to be legitimate based on our analysis. "
                "No significant phishing indicators were detected."
            )
            recommendations = [
                "Standard security practices still apply",
                "Always verify before entering sensitive information",
            ]

        return explanation, indicators, recommendations
