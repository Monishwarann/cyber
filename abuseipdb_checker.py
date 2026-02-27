"""
AbuseIPDB Integration for Cyber Shield.
Resolves the hostname from a scanned URL to an IP address, then queries
AbuseIPDB for its abuse confidence score and historical report data.
The result is used as an additional signal in the ensemble phishing score.
"""
import os
import socket
import re
from typing import Dict, Optional, Union
from urllib.parse import urlparse

import httpx  # type: ignore[import]
from dotenv import load_dotenv  # type: ignore[import]

load_dotenv()


class AbuseIPDBChecker:
    """
    AbuseIPDB API integration for IP reputation checks.

    Workflow:
      1. Parse the URL to extract the hostname/domain.
      2. If the hostname is already an IP, use it directly; otherwise do a
         DNS lookup to resolve it.
      3. Query AbuseIPDB's /check endpoint for that IP.
      4. Map the abuse confidence score (0-100) → normalised risk score (0-1).
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self):
        self.api_key: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")
        self.available: bool = bool(self.api_key)
        self.key_valid: bool = False

        if self.available:
            self._validate_key_sync()
        else:
            print("[WARN] AbuseIPDB API key not found in .env")

    # ─── Private helpers ──────────────────────────────────────────

    def _get_headers(self) -> Dict:
        return {
            "Key": self.api_key or "",
            "Accept": "application/json",
        }

    @staticmethod
    def _extract_ip(url: str) -> Optional[str]:
        """
        Parse a URL and resolve its hostname to an IP address.
        Returns None if resolution fails or the host is localhost.
        """
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            hostname: str = parsed.hostname or ""

            if not hostname:
                return None

            # Skip private / loopback addresses
            if hostname in ("localhost", "127.0.0.1", "::1"):
                return None

            # Check if hostname is already an IPv4 or IPv6 literal
            _ipv4_re = re.compile(
                r"^(\d{1,3}\.){3}\d{1,3}$"
            )
            if _ipv4_re.match(hostname):
                return hostname

            # DNS lookup (synchronous – only at request time, not at startup)
            ip = socket.gethostbyname(hostname)
            return ip

        except (socket.gaierror, ValueError, Exception):
            return None

    def _validate_key_sync(self) -> None:
        """Validate the API key at startup with a lightweight request."""
        try:
            # AbuseIPDB doesn't have a /me endpoint; instead check a known
            # safe IP (1.1.1.1 – Cloudflare DNS) with maxAgeInDays=1 so the
            # response is fast and doesn't consume meaningful quota.
            response = httpx.get(
                f"{self.BASE_URL}/check",
                headers=self._get_headers(),
                params={"ipAddress": "1.1.1.1", "maxAgeInDays": "1"},
                timeout=15.0,
            )
            if response.status_code == 200:
                self.key_valid = True
                print("[OK] AbuseIPDB API key VERIFIED")
            elif response.status_code == 401:
                self.key_valid = False
                self.available = False
                print("[FAIL] AbuseIPDB API key is INVALID (401 Unauthorized)")
            elif response.status_code == 422:
                # Validation error but key itself was accepted
                self.key_valid = True
                print("[OK] AbuseIPDB API key VERIFIED (422 on test IP – key OK)")
            else:
                self.key_valid = False
                print(
                    f"[WARN] AbuseIPDB API key check returned status {response.status_code}"
                )
        except httpx.TimeoutException:
            self.key_valid = False
            print("[WARN] AbuseIPDB API key check timed out (network issue)")
        except Exception as e:
            self.key_valid = False
            print(f"[WARN] AbuseIPDB API key check failed: {e}")

    # ─── Public API ───────────────────────────────────────────────

    async def verify_api_key(self) -> Dict:
        """
        Async API key verification. Calls /check on 1.1.1.1.
        Returns a status dict compatible with the health endpoint.
        """
        if not self.api_key:
            return {
                "valid": False,
                "status": "missing",
                "message": "No AbuseIPDB API key configured in .env",
            }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=self._get_headers(),
                    params={"ipAddress": "1.1.1.1", "maxAgeInDays": "1"},
                )

                if response.status_code == 200:
                    data = response.json().get("data", {})
                    self.key_valid = True
                    self.available = True
                    return {
                        "valid": True,
                        "status": "active",
                        "message": "AbuseIPDB API key is valid and working",
                        "test_ip": "1.1.1.1",
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    }
                elif response.status_code == 401:
                    self.key_valid = False
                    return {
                        "valid": False,
                        "status": "invalid",
                        "message": "AbuseIPDB API key is invalid (401 Unauthorized)",
                    }
                else:
                    return {
                        "valid": False,
                        "status": "error",
                        "message": f"Unexpected status code: {response.status_code}",
                        "body": response.text[:200],
                    }
        except httpx.TimeoutException:
            return {
                "valid": False,
                "status": "timeout",
                "message": "AbuseIPDB API request timed out",
            }
        except Exception as e:
            return {
                "valid": False,
                "status": "error",
                "message": f"Connection error: {str(e)}",
            }

    async def check_url(self, url: str, max_age_days: int = 90) -> Dict:
        """
        Main entry point: check a URL's resolved IP against AbuseIPDB.

        Args:
            url:          The full URL string to inspect.
            max_age_days: How far back (in days) to look for reports. Default 90.

        Returns a standardised dict with:
            - ip_address        : resolved IP (or None)
            - abuse_score       : 0-100 integer from AbuseIPDB
            - risk_score        : normalised 0.0-1.0 float for ensemble
            - is_whitelisted    : bool
            - total_reports     : int
            - distinct_users    : int
            - country_code      : str
            - isp               : str
            - domain            : str
            - usage_type        : str
            - detected          : bool (True if abuse_score > 25)
            - threat_categories : list[str] – human-readable category names
            - source            : "abuseipdb" | "fallback"
        """
        if not self.available:
            return self._fallback_response(note="AbuseIPDB not available")

        # Step 1 – resolve hostname → IP
        ip = self._extract_ip(url)
        if not ip:
            return self._fallback_response(
                note=f"Could not resolve hostname for URL: {url}"
            )

        # Step 2 – query AbuseIPDB
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=self._get_headers(),
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": str(max_age_days),
                        "verbose": "",  # include category names
                    },
                )

                if response.status_code == 200:
                    return self._parse_response(response.json(), ip)
                elif response.status_code == 422:
                    # Unprocessable – private / reserved IP
                    return self._fallback_response(
                        note=f"Private/reserved IP {ip} – skipped"
                    )
                elif response.status_code == 429:
                    return self._fallback_response(error="AbuseIPDB rate limit exceeded")
                elif response.status_code == 401:
                    return self._fallback_response(error="AbuseIPDB API key invalid")
                else:
                    return self._fallback_response(
                        error=f"AbuseIPDB HTTP {response.status_code}"
                    )

        except httpx.TimeoutException:
            return self._fallback_response(error="AbuseIPDB request timed out")
        except Exception as e:
            return self._fallback_response(error=str(e))

    # ─── Parsing ──────────────────────────────────────────────────

    # AbuseIPDB category ID → human-readable label
    CATEGORY_MAP: Dict[int, str] = {
        3:  "Fraud Orders",
        4:  "DDoS Attack",
        5:  "FTP Brute-Force",
        6:  "Ping of Death",
        7:  "Phishing",
        8:  "Fraud VoIP",
        9:  "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH Brute-Force",
        23: "IoT Targeted",
    }

    def _parse_response(self, payload: Dict, ip: str) -> Dict:
        """Parse raw AbuseIPDB /check response into a standardised result."""
        try:
            data = payload.get("data", {})

            abuse_score: int = int(data.get("abuseConfidenceScore", 0))
            total_reports: int = int(data.get("totalReports", 0))
            distinct_users: int = int(data.get("numDistinctUsers", 0))
            is_whitelisted: bool = bool(data.get("isWhitelisted", False))
            country_code: str = str(data.get("countryCode", ""))
            isp: str = str(data.get("isp", ""))
            domain: str = str(data.get("domain", ""))
            usage_type: str = str(data.get("usageType", ""))

            # Map category IDs → readable labels
            raw_cats = data.get("reports", [])
            cat_ids: set = set()
            for report in raw_cats:
                for cid in report.get("categories", []):
                    cat_ids.add(int(cid))
            threat_categories = [
                self.CATEGORY_MAP.get(cid, f"Category {cid}") for cid in sorted(cat_ids)
            ]

            # Normalise score to 0-1
            risk_score = round(abuse_score / 100.0, 4)

            # Whitelisted IPs are considered safe regardless of score
            if is_whitelisted:
                risk_score = 0.0

            detected = abuse_score > 25 and not is_whitelisted

            return {
                "ip_address": ip,
                "abuse_score": abuse_score,
                "risk_score": risk_score,
                "is_whitelisted": is_whitelisted,
                "total_reports": total_reports,
                "distinct_users": distinct_users,
                "country_code": country_code,
                "isp": isp,
                "domain": domain,
                "usage_type": usage_type,
                "detected": detected,
                "threat_categories": threat_categories,
                "source": "abuseipdb",
            }

        except Exception as e:
            return self._fallback_response(error=f"Parse error: {str(e)}")

    # ─── Fallback ─────────────────────────────────────────────────

    def _fallback_response(
        self,
        error: Union[str, None] = None,
        note: Union[str, None] = None,
    ) -> Dict:
        return {
            "ip_address": None,
            "abuse_score": 0,
            "risk_score": 0.0,
            "is_whitelisted": False,
            "total_reports": 0,
            "distinct_users": 0,
            "country_code": "",
            "isp": "",
            "domain": "",
            "usage_type": "",
            "detected": False,
            "threat_categories": [],
            "source": "fallback",
            "note": note or error or "AbuseIPDB unavailable",
        }
