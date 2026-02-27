"""
Gemini AI Analyzer for Cyber Shield.
Uses Google's Gemini API for advanced semantic phishing detection,
contextual reasoning, and explainable AI output.
"""
import json
import os
import asyncio
from typing import Dict, Union, Optional
import google.generativeai as genai  # type: ignore[import]
from dotenv import load_dotenv  # type: ignore[import]

load_dotenv()


class GeminiPhishingAnalyzer:
    """
    Advanced phishing analysis using Google Gemini AI.
    Provides contextual reasoning, AI-generated phishing detection,
    and explainable AI output.
    """

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        self.available = False
        self.model = None
        self.key_valid = False
        self.model_name = "gemini-2.0-flash"

        if not api_key:
            print("[WARN] Gemini API key not found in .env")
            return

        try:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(self.model_name)
            # ── Real key validation: send a tiny test call ──
            test_resp = self.model.generate_content("Reply with only: OK")
            _ = test_resp.text  # Will throw if key is invalid
            self.available = True
            self.key_valid = True
            print("[OK] Gemini AI initialized and API key VERIFIED successfully")
        except Exception as e:
            err = str(e)
            if "leaked" in err.lower() or "403" in err or "reported" in err.lower():
                print(f"[FAIL] Gemini API key has been REPORTED AS LEAKED. Get a new key at https://aistudio.google.com/app/apikey")
            elif "API_KEY_INVALID" in err or "400" in err or "API Key not found" in err:
                print(f"[FAIL] Gemini API key is INVALID: {err[:120]}")
            elif "429" in err or "quota" in err.lower():
                print(f"[WARN] Gemini API key is valid but RATE LIMITED (quota exceeded)")
                self.available = True   # Key is valid, just quota
                self.key_valid = True
            else:
                print(f"[WARN] Gemini AI initialization failed: {err[:120]}")
            # Leave available=False so fallback is never used in ensemble
            self.model = None


    async def verify_api_key(self) -> Dict:
        """
        Live API key verification - sends a tiny test prompt to Gemini
        to confirm the key is valid and the model is reachable.
        """
        if not self.model:
            return {
                "valid": False,
                "status": "missing_or_invalid",
                "message": "Gemini model not initialized — key missing, invalid, or leaked.",
                "model": self.model_name,
            }

        try:
            # Run the blocking SDK call in a thread pool so we don't block asyncio
            def _test():
                resp = self.model.generate_content("Reply with only: OK")  # type: ignore[union-attr]
                return resp.text.strip() if resp.text else ""

            reply = await asyncio.to_thread(_test)

            self.key_valid = True
            self.available = True
            return {
                "valid": True,
                "status": "active",
                "message": "Gemini API key is valid and responding",
                "model": self.model_name,
                "test_response": reply[:50],
            }

        except Exception as e:
            error_msg = str(e)
            status = "error"
            message = f"API check failed: {error_msg[:200]}"

            if "leaked" in error_msg.lower() or "reported" in error_msg.lower():
                status = "leaked"
                message = "API key has been reported as leaked — replace it immediately"
                self.key_valid = False
                self.available = False
            elif "429" in error_msg or "quota" in error_msg.lower():
                status = "rate_limited"
                message = "API key is valid but rate limited (free tier quota exceeded)"
                self.key_valid = True  # Key is valid, just rate limited
            elif "401" in error_msg or "unauthorized" in error_msg.lower():
                status = "invalid"
                message = "API key is INVALID (unauthorized)"
                self.key_valid = False
                self.available = False
            elif "403" in error_msg or "forbidden" in error_msg.lower() or "API_KEY_INVALID" in error_msg:
                status = "invalid"
                message = "API key is invalid or forbidden (403)"
                self.key_valid = False
                self.available = False

            return {
                "valid": self.key_valid,
                "status": status,
                "message": message,
                "model": self.model_name,
            }


    def _build_analysis_prompt(
        self,
        url: Optional[str] = None,
        content: Optional[str] = None,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        url_features: Optional[Dict] = None,
    ) -> str:
        """Build the analysis prompt for Gemini."""
        prompt = """You are Cyber Shield, an advanced AI cybersecurity analyst specializing in phishing detection.
Analyze the following data for phishing indicators and provide a comprehensive assessment.

IMPORTANT: You must respond ONLY with a valid JSON object (no markdown, no code blocks, no extra text).

The JSON must have this exact structure:
{
    "risk_score": <float 0.0-1.0>,
    "classification": "<Safe|Suspicious|Phishing|Highly Dangerous>",
    "reasoning": "<detailed explanation>",
    "indicators": ["<indicator1>", "<indicator2>"],
    "brand_impersonation": "<brand name or null>",
    "urgency_level": "<low|medium|high|critical>",
    "manipulation_tactics": ["<tactic1>", "<tactic2>"],
    "recommendation": "<actionable advice>",
    "ai_generated_likelihood": "<low|medium|high>",
    "zero_day_indicators": ["<indicator>"]
}

DATA TO ANALYZE:
"""
        if url:
            prompt += f"\n🔗 URL: {url}"
        if content:
            prompt += f"\n📧 Content: {str(content)[:2000]}"  # Limit content length
        if sender:
            prompt += f"\n👤 Sender: {sender}"
        if subject:
            prompt += f"\n📌 Subject: {subject}"
        if url_features:
            prompt += f"\n📊 URL Features: {json.dumps(url_features, default=str)}"

        prompt += """

ANALYSIS GUIDELINES:
1. Assess if the URL structure matches known phishing patterns
2. Check for domain spoofing, homoglyph attacks, and brand impersonation
3. Analyze content for social engineering tactics (urgency, fear, authority, reward)
4. Detect AI-generated phishing text patterns
5. Evaluate zero-day attack indicators
6. Provide clear, actionable explanations

Respond with ONLY the JSON object, no other text."""

        return prompt

    async def analyze(
        self,
        url: Optional[str] = None,
        content: Optional[str] = None,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        url_features: Optional[Dict] = None,
    ) -> Dict:
        """
        Perform comprehensive phishing analysis using Gemini AI.
        Returns analysis results as a dictionary.
        """
        if not self.available or not self.model:
            return self._fallback_response()

        try:
            prompt = self._build_analysis_prompt(
                url=url,
                content=content,
                sender=sender,
                subject=subject,
                url_features=url_features,
            )

            def _call_gemini():
                resp = self.model.generate_content(prompt)  # type: ignore[union-attr]
                return resp.text.strip() if resp.text else ""

            result_text = await asyncio.to_thread(_call_gemini)

            # Clean up response if it has markdown formatting
            if result_text.startswith("```"):
                lines = result_text.split("\n")
                result_text = "\n".join(lines[1:-1])

            result = json.loads(result_text)

            # Validate and normalize
            result["risk_score"] = max(0.0, min(1.0, float(result.get("risk_score", 0.5))))
            result["classification"] = result.get("classification", "Unknown")
            result["reasoning"] = result.get("reasoning", "Analysis incomplete")
            result["indicators"] = result.get("indicators", [])
            result["brand_impersonation"] = result.get("brand_impersonation")
            result["urgency_level"] = result.get("urgency_level", "low")
            result["manipulation_tactics"] = result.get("manipulation_tactics", [])
            result["recommendation"] = result.get("recommendation", "Exercise caution")
            result["source"] = "gemini_ai"

            return result

        except json.JSONDecodeError as e:
            print(f"[WARN] Gemini response parse error: {e}")
            return self._fallback_response(error=f"Parse error: {str(e)}")
        except Exception as e:
            print(f"[WARN] Gemini analysis error: {e}")
            return self._fallback_response(error=str(e))

    def _fallback_response(self, error: Union[str, None] = None) -> Dict:  # type: ignore[misc]
        """Return a fallback response when Gemini is unavailable."""
        return {
            "risk_score": 0.5,
            "classification": "Unknown",
            "reasoning": error or "Gemini AI unavailable - using ML models only",
            "indicators": [],
            "brand_impersonation": None,
            "urgency_level": "unknown",
            "manipulation_tactics": [],
            "recommendation": "Use other detection methods for verification",
            "source": "fallback",
        }

    async def explain_threat(self, scan_result: Dict) -> str:
        """
        Generate a plain-language threat explanation for users.
        """
        if not self.available or not self.model:
            return "AI explanation unavailable. Please review the technical indicators."

        try:
            prompt = f"""You are a cybersecurity expert explaining a phishing detection result to a non-technical user.
Based on this analysis result, provide a clear, concise explanation in 2-3 sentences.
Use simple language that anyone can understand. Be direct about the risk level.

Analysis Result: {json.dumps(scan_result, default=str)}

Respond with ONLY the plain text explanation, no JSON or formatting."""

            if self.model is None:
                return "AI explanation unavailable. Model not initialized."
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            return f"Could not generate AI explanation: {str(e)}"
