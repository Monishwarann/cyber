"""
Remote ML Model Predictor for Cyber Shield.
Integrates the deployed phishing detection ML model at the remote API endpoint.

The remote model expects 48 URL-based features and returns a phishing prediction.
This module handles:
  - Feature extraction & mapping from local URL features to the remote schema
  - Async HTTP calls to the remote prediction API
  - Response parsing and error handling with fallback
"""
import os
import re
import math
import asyncio
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Tuple, Optional

import httpx  # type: ignore[import]
from dotenv import load_dotenv  # type: ignore[import]

load_dotenv()

# Remote API base URL (from .env as MODEL_API_KEY or fallback)
REMOTE_ML_API_URL = os.getenv(
    "MODEL_API_KEY",
    "https://cyber-security-ml-zyp6.onrender.com"
).rstrip("/")


class RemoteMLPredictor:
    """
    Client for the remote Phishing Detection ML API.
    
    Maps locally-extracted URL features to the 48-feature schema
    expected by the remote model, sends predictions asynchronously,
    and parses the response.
    """

    def __init__(self, api_url: Optional[str] = None, timeout: float = 30.0):
        self.api_url = (api_url or REMOTE_ML_API_URL).rstrip("/")
        self.predict_endpoint = f"{self.api_url}/predict"
        self.timeout = timeout
        self.available = True
        self._verified = False

    async def verify_api(self) -> Dict[str, Any]:
        """Health-check the remote ML API."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(self.api_url)
                if resp.status_code == 200:
                    data = resp.json()
                    self._verified = True
                    self.available = True
                    return {
                        "valid": True,
                        "status": "active",
                        "message": data.get("status", "API reachable"),
                    }
                else:
                    self.available = False
                    return {
                        "valid": False,
                        "status": "error",
                        "message": f"API returned status {resp.status_code}",
                    }
        except Exception as e:
            self.available = False
            return {
                "valid": False,
                "status": "unreachable",
                "message": str(e),
            }

    # ──────────────────────────────────────────────────────────────
    #  Feature mapping: local features → remote 48-feature schema
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _count_sensitive_words(url: str) -> int:
        """Count sensitive / credential-related words in the URL."""
        sensitive = [
            "login", "signin", "sign-in", "verify", "account", "update",
            "secure", "banking", "confirm", "password", "credential",
            "authenticate", "wallet", "payment", "checkout", "webscr",
            "suspend", "restrict", "unusual", "alert", "locked", "expire",
        ]
        url_lower = url.lower()
        return sum(1 for word in sensitive if word in url_lower)

    @staticmethod
    def _has_random_string(domain: str) -> int:
        """Heuristic: domain looks randomly generated (high consonant clusters)."""
        consonant_clusters = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', domain.lower())
        return 1 if len(consonant_clusters) >= 1 else 0

    @staticmethod
    def _embedded_brand_name(url: str, domain: str) -> int:
        """Check if a well-known brand name appears outside the real domain."""
        brands = [
            "paypal", "google", "facebook", "amazon", "apple",
            "microsoft", "netflix", "instagram", "twitter", "linkedin",
            "chase", "wellsfargo", "bankofamerica", "dropbox", "adobe",
        ]
        url_lower = url.lower()
        domain_lower = domain.lower()
        for brand in brands:
            if brand in url_lower and brand not in domain_lower:
                return 1
        return 0

    def build_remote_features(self, url: str, local_features: Dict) -> Dict[str, Any]:
        """
        Map local URL features + raw URL analysis to the 48 features
        expected by the remote /predict endpoint.
        """
        parsed = urlparse(url)
        hostname = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""
        domain = hostname.split(":")[0]  # strip port

        # ── Basic counts ──
        num_dots = url.count(".")
        subdomain_level = local_features.get("num_subdomains", 0)
        path_level = local_features.get("path_depth", 0)
        url_length = len(url)
        num_dash = url.count("-")
        num_dash_in_hostname = hostname.count("-")
        at_symbol = 1 if "@" in url else 0
        tilde_symbol = 1 if "~" in url else 0
        num_underscore = url.count("_")
        num_percent = url.count("%")

        # Query components
        query_params = parse_qs(query)
        num_query_components = len(query_params)
        num_ampersand = url.count("&")
        num_hash = url.count("#")

        # Numeric characters
        num_numeric_chars = sum(1 for c in url if c.isdigit())

        # Protocol
        no_https = 0 if local_features.get("has_https", False) else 1

        # Domain analysis
        random_string = self._has_random_string(domain)
        ip_address = 1 if local_features.get("has_ip", False) else 0

        # Subdomain / path domain tricks
        domain_in_subdomains = 0
        domain_in_paths = 0
        brands = ["paypal", "google", "facebook", "amazon", "apple", "microsoft"]
        for brand in brands:
            parts = hostname.split(".")
            if len(parts) > 2 and brand in ".".join(parts[:-2]).lower():
                domain_in_subdomains = 1
            if brand in path.lower():
                domain_in_paths = 1

        https_in_hostname = 1 if "https" in hostname.lower() else 0
        hostname_length = len(hostname)
        path_length = len(path)
        query_length = len(query)
        double_slash_in_path = 1 if "//" in path else 0

        num_sensitive_words = self._count_sensitive_words(url)
        embedded_brand_name = self._embedded_brand_name(url, domain)

        # ── Content-based features (defaults for URL-only scan) ──
        # These would ideally come from HTML analysis; we use safe defaults
        pct_ext_hyperlinks = 0.0
        pct_ext_resource_urls = 0.0
        ext_favicon = 0
        insecure_forms = 0
        relative_form_action = 0
        ext_form_action = 0
        abnormal_form_action = 0
        pct_null_self_redirect_hyperlinks = 0.0
        frequent_domain_name_mismatch = 0
        fake_link_in_status_bar = 0
        right_click_disabled = 0
        pop_up_window = 0
        submit_info_to_email = 0
        iframe_or_frame = 0
        missing_title = 0
        images_only_in_form = 0

        # ── Ratio/threshold features (RT variants) ──
        subdomain_level_rt = 1 if subdomain_level >= 3 else (0 if subdomain_level <= 1 else -1)
        url_length_rt = 1 if url_length >= 75 else (0 if url_length <= 54 else -1)
        pct_ext_resource_urls_rt = 1 if pct_ext_resource_urls >= 0.5 else (0 if pct_ext_resource_urls <= 0.2 else -1)
        abnormal_ext_form_action_r = 1 if abnormal_form_action else 0
        ext_meta_script_link_rt = 0  # safe default
        pct_ext_null_self_redirect_hyperlinks_rt = (
            1 if pct_null_self_redirect_hyperlinks >= 0.5
            else (0 if pct_null_self_redirect_hyperlinks <= 0.1 else -1)
        )

        return {
            "NumDots": num_dots,
            "SubdomainLevel": subdomain_level,
            "PathLevel": path_level,
            "UrlLength": url_length,
            "NumDash": num_dash,
            "NumDashInHostname": num_dash_in_hostname,
            "AtSymbol": at_symbol,
            "TildeSymbol": tilde_symbol,
            "NumUnderscore": num_underscore,
            "NumPercent": num_percent,
            "NumQueryComponents": num_query_components,
            "NumAmpersand": num_ampersand,
            "NumHash": num_hash,
            "NumNumericChars": num_numeric_chars,
            "NoHttps": no_https,
            "RandomString": random_string,
            "IpAddress": ip_address,
            "DomainInSubdomains": domain_in_subdomains,
            "DomainInPaths": domain_in_paths,
            "HttpsInHostname": https_in_hostname,
            "HostnameLength": hostname_length,
            "PathLength": path_length,
            "QueryLength": query_length,
            "DoubleSlashInPath": double_slash_in_path,
            "NumSensitiveWords": num_sensitive_words,
            "EmbeddedBrandName": embedded_brand_name,
            "PctExtHyperlinks": pct_ext_hyperlinks,
            "PctExtResourceUrls": pct_ext_resource_urls,
            "ExtFavicon": ext_favicon,
            "InsecureForms": insecure_forms,
            "RelativeFormAction": relative_form_action,
            "ExtFormAction": ext_form_action,
            "AbnormalFormAction": abnormal_form_action,
            "PctNullSelfRedirectHyperlinks": pct_null_self_redirect_hyperlinks,
            "FrequentDomainNameMismatch": frequent_domain_name_mismatch,
            "FakeLinkInStatusBar": fake_link_in_status_bar,
            "RightClickDisabled": right_click_disabled,
            "PopUpWindow": pop_up_window,
            "SubmitInfoToEmail": submit_info_to_email,
            "IframeOrFrame": iframe_or_frame,
            "MissingTitle": missing_title,
            "ImagesOnlyInForm": images_only_in_form,
            "SubdomainLevelRT": subdomain_level_rt,
            "UrlLengthRT": url_length_rt,
            "PctExtResourceUrlsRT": pct_ext_resource_urls_rt,
            "AbnormalExtFormActionR": abnormal_ext_form_action_r,
            "ExtMetaScriptLinkRT": ext_meta_script_link_rt,
            "PctExtNullSelfRedirectHyperlinksRT": pct_ext_null_self_redirect_hyperlinks_rt,
        }

    async def predict(self, url: str, local_features: Dict) -> Dict[str, Any]:
        """
        Send features to the remote ML API and return the prediction result.

        Returns a dict with keys:
            - risk_score (float 0-1)
            - prediction (str: 'phishing' or 'legitimate')
            - confidence (float 0-1)
            - source ('remote_ml')
            - raw_response (the original API response)
            - features_sent (the 48-feature payload)
        """
        if not self.available:
            return self._fallback("Remote ML API is not available")

        try:
            features_payload = self.build_remote_features(url, local_features)

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.predict_endpoint,
                    json=features_payload,
                )
                response.raise_for_status()
                result = response.json()

            # ── Parse the response ──
            # The remote API might return different formats; handle common ones
            risk_score = self._extract_risk_score(result)
            prediction = "phishing" if risk_score >= 0.5 else "legitimate"

            return {
                "risk_score": round(risk_score, 4),
                "prediction": prediction,
                "confidence": round(abs(risk_score - 0.5) * 2, 4),  # 0-1 scale
                "source": "remote_ml",
                "model_api": self.api_url,
                "raw_response": result,
                "features_sent": features_payload,
            }

        except httpx.TimeoutException:
            return self._fallback("Remote ML API timed out")
        except httpx.HTTPStatusError as e:
            return self._fallback(f"Remote ML API HTTP error: {e.response.status_code}")
        except Exception as e:
            return self._fallback(f"Remote ML API error: {str(e)}")

    @staticmethod
    def _extract_risk_score(result: Any) -> float:
        """
        Extract a risk score from the remote API response.
        Handles multiple possible response formats.
        
        Known response format from our API:
            {"prediction": 0/1, "phishing_probability": float, "risk_level": str}
        """
        if isinstance(result, dict):
            # Prioritize phishing_probability (continuous 0-1 score)
            if "phishing_probability" in result:
                val = result["phishing_probability"]
                if isinstance(val, (int, float)):
                    return float(max(0.0, min(1.0, val)))

            # Fallback: check other common keys
            for key in ["risk_score", "score", "probability", "prediction",
                        "result", "label"]:
                if key in result:
                    val = result[key]
                    if isinstance(val, (int, float)):
                        # For binary prediction (0/1), map to risk scores
                        if key == "prediction":
                            return 0.95 if val >= 1 else 0.05
                        return float(max(0.0, min(1.0, val)))
                    if isinstance(val, str):
                        val_lower = val.strip().lower()
                        if val_lower in ("phishing", "malicious", "1", "positive"):
                            return 0.95
                        elif val_lower in ("legitimate", "safe", "benign", "0", "negative"):
                            return 0.05
                        try:
                            return float(max(0.0, min(1.0, float(val))))
                        except ValueError:
                            pass
        elif isinstance(result, (int, float)):
            return float(max(0.0, min(1.0, result)))

        # Default: unknown
        return 0.5

    @staticmethod
    def _fallback(reason: str) -> Dict[str, Any]:
        """Return a fallback result when the remote API is unavailable."""
        return {
            "risk_score": 0.0,
            "prediction": "unknown",
            "confidence": 0.0,
            "source": "fallback",
            "error": reason,
        }
