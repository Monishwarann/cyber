"""
VirusTotal Integration for Cyber Shield.
Queries the VirusTotal API for URL threat intelligence
and reputation analysis.
"""
import os
import hashlib
import base64
import asyncio
import time
from typing import Dict, Union, Optional
import httpx  # type: ignore[import]
from dotenv import load_dotenv  # type: ignore[import]

load_dotenv()


class VirusTotalChecker:
    """
    VirusTotal API integration for URL threat intelligence.
    Uses the VirusTotal v3 API for comprehensive URL scanning.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.available = bool(self.api_key)
        self.key_valid = False
        self.api_user = None
        self.api_quota = {}
        self.last_health_check = None
        self.last_health_result = None

        if self.available:
            # Do a REAL validation on startup using sync httpx
            self._validate_key_sync()
        else:
            print("[WARN] VirusTotal API key not found in .env")

    def _validate_key_sync(self):
        """Validate the API key at startup by calling /users/me."""
        try:
            response = httpx.get(
                f"{self.BASE_URL}/users/me",
                headers=self._get_headers(),
                timeout=15.0,
            )
            if response.status_code == 200:
                data = response.json()
                user_data = data.get("data", {})
                attributes = user_data.get("attributes", {})
                self.key_valid = True
                self.api_user = attributes.get("user", {}).get("name", "Unknown")
                quotas = attributes.get("quotas", {})
                self.api_quota = {
                    "api_requests_daily": quotas.get("api_requests_daily", {}),
                    "api_requests_monthly": quotas.get("api_requests_monthly", {}),
                }
                print(f"[OK] VirusTotal API key VERIFIED - User: {self.api_user}")
            elif response.status_code == 401:
                self.key_valid = False
                self.available = False
                print("[FAIL] VirusTotal API key is INVALID (401 Unauthorized)")
            elif response.status_code == 403:
                self.key_valid = False
                self.available = False
                print("[FAIL] VirusTotal API key is FORBIDDEN (403)")
            else:
                # Key might still work for URL scanning, mark as partial
                self.key_valid = False
                print(f"[WARN] VirusTotal API key check returned status {response.status_code}")
        except httpx.TimeoutException:
            self.key_valid = False
            print("[WARN] VirusTotal API key check timed out (network issue)")
        except Exception as e:
            self.key_valid = False
            print(f"[WARN] VirusTotal API key check failed: {e}")

    async def verify_api_key(self) -> Dict:
        """
        Live API key verification - calls /users/me to check key validity.
        Returns detailed status with user info and quota.
        """
        if not self.api_key:
            return {
                "valid": False,
                "status": "missing",
                "message": "No API key configured in .env",
            }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/users/me",
                    headers=self._get_headers(),
                )

                if response.status_code == 200:
                    data = response.json()
                    user_data = data.get("data", {})
                    attributes = user_data.get("attributes", {})
                    quotas = attributes.get("quotas", {})

                    daily = quotas.get("api_requests_daily", {})
                    monthly = quotas.get("api_requests_monthly", {})

                    self.key_valid = True
                    self.available = True
                    return {
                        "valid": True,
                        "status": "active",
                        "message": "API key is valid and working",
                        "user": attributes.get("user", {}).get("name", "N/A"),
                        "type": attributes.get("type", "N/A"),
                        "quota": {
                            "daily_used": daily.get("used", 0),
                            "daily_allowed": daily.get("allowed", 0),
                            "monthly_used": monthly.get("used", 0),
                            "monthly_allowed": monthly.get("allowed", 0),
                        },
                        "privileges": attributes.get("privileges", {}),
                    }
                elif response.status_code == 401:
                    self.key_valid = False
                    return {
                        "valid": False,
                        "status": "invalid",
                        "message": "API key is invalid (401 Unauthorized)",
                    }
                elif response.status_code == 403:
                    self.key_valid = False
                    return {
                        "valid": False,
                        "status": "forbidden",
                        "message": "API key access forbidden (403)",
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
                "message": "VirusTotal API request timed out",
            }
        except Exception as e:
            return {
                "valid": False,
                "status": "error",
                "message": f"Connection error: {str(e)}",
            }

    async def health_scan(self) -> Dict:
        """
        Deep health check - scans a known safe URL (google.com) to
        confirm the full scanning pipeline works end-to-end.
        """
        if not self.available:
            return {
                "healthy": False,
                "message": "VirusTotal not available",
            }

        test_url = "https://www.google.com"
        start_time = time.time()

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                url_id = self._url_id(test_url)
                response = await client.get(
                    f"{self.BASE_URL}/urls/{url_id}",
                    headers=self._get_headers(),
                )

                elapsed = round((time.time() - start_time) * 1000, 2)

                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result = {
                        "healthy": True,
                        "message": "VirusTotal scanning pipeline working",
                        "test_url": test_url,
                        "response_time_ms": elapsed,
                        "scanners_responded": sum(stats.values()),
                        "analysis_stats": stats,
                    }
                    self.last_health_check = time.time()
                    self.last_health_result = result
                    return result
                elif response.status_code == 404:
                    return {
                        "healthy": True,
                        "message": "API responding (URL not in database yet)",
                        "response_time_ms": elapsed,
                    }
                else:
                    return {
                        "healthy": False,
                        "message": f"Unexpected status: {response.status_code}",
                        "response_time_ms": elapsed,
                    }

        except Exception as e:
            return {
                "healthy": False,
                "message": f"Health scan failed: {str(e)}",
            }

    def _get_headers(self) -> Dict:
        """Get API request headers."""
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    def _url_id(self, url: str) -> str:
        """Generate VirusTotal URL identifier."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def scan_url(self, url: str) -> Dict:
        """
        Scan a URL using VirusTotal API.
        First checks existing reports, submits for scanning if needed.
        """
        if not self.available:
            return self._fallback_response()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # First, try to get existing report
                url_id = self._url_id(url)
                report = await self._get_url_report(client, url_id)

                if report:
                    return report

                # If no existing report, submit for scanning
                scan_result = await self._submit_url(client, url)
                if scan_result:
                    # Wait briefly and check for results
                    await asyncio.sleep(2)
                    report = await self._get_url_report(client, url_id)
                    if report:
                        return report

                return self._fallback_response(note="URL submitted for scanning, results pending")

        except httpx.TimeoutException:
            return self._fallback_response(error="VirusTotal request timed out")
        except Exception as e:
            return self._fallback_response(error=str(e))

    async def _get_url_report(self, client: httpx.AsyncClient, url_id: str) -> Optional[Dict]:
        """Get existing URL report from VirusTotal."""
        try:
            response = await client.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers=self._get_headers(),
            )

            if response.status_code == 200:
                data = response.json()
                return self._parse_report(data)
            elif response.status_code == 404:
                return None  # URL not in database
            else:
                return None

        except Exception:
            return None

    async def _submit_url(self, client: httpx.AsyncClient, url: str) -> Optional[Dict]:
        """Submit a URL for scanning."""
        try:
            response = await client.post(
                f"{self.BASE_URL}/urls",
                headers=self._get_headers(),
                data={"url": url},
            )

            if response.status_code == 200:
                return response.json()
            return None

        except Exception:
            return None

    def _parse_report(self, data: Dict) -> Dict:
        """Parse VirusTotal API response into a standardized format."""
        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            total = malicious + suspicious + undetected + harmless

            # Get categories from vendors
            categories = []
            for vendor, result in results.items():
                if result.get("category") == "malicious":
                    cat = result.get("result", "malicious")
                    if cat and cat not in categories:
                        categories.append(cat)

            # Compute VT-based risk score
            positives = malicious + suspicious
            vt_risk_score = positives / max(total, 1)

            return {
                "detected": positives > 0,
                "positives": positives,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_scanners": total,
                "risk_score": round(vt_risk_score, 4),
                "categories": list(categories)[:10],  # type: ignore[index]
                "scan_date": attributes.get("last_analysis_date"),
                "reputation": attributes.get("reputation", 0),
                "times_submitted": attributes.get("times_submitted", 0),
                "source": "virustotal",
            }

        except Exception as e:
            return self._fallback_response(error=f"Parse error: {str(e)}")

    def _fallback_response(self, error: Union[str, None] = None, note: Union[str, None] = None) -> Dict:  # type: ignore[misc]
        """Return a fallback response when VT is unavailable."""
        return {
            "detected": False,
            "positives": 0,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_scanners": 0,
            "risk_score": 0.0,
            "categories": [],
            "scan_date": None,
            "reputation": 0,
            "source": "fallback",
            "note": note or error or "VirusTotal unavailable",
        }
