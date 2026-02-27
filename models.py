"""
Pydantic models for the Cyber Shield Phishing Detection System.
Defines request/response schemas for all API endpoints.
"""
from pydantic import BaseModel, Field  # type: ignore[import]
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanType(str, Enum):
    URL = "url"
    EMAIL = "email"
    SMS = "sms"
    CONTENT = "content"


# ─── Request Models ────────────────────────────────────────────
class URLScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan for phishing")
    deep_scan: bool = Field(default=True, description="Enable deep scan with Gemini AI")


class ContentScanRequest(BaseModel):
    content: str = Field(..., description="Email/SMS/message content to analyze")
    sender: Optional[str] = Field(None, description="Sender information")
    subject: Optional[str] = Field(None, description="Email subject line")
    scan_type: ScanType = Field(default=ScanType.EMAIL, description="Type of content")


class FullScanRequest(BaseModel):
    url: Optional[str] = Field(None, description="URL to scan")
    content: Optional[str] = Field(None, description="Content to analyze")
    sender: Optional[str] = Field(None, description="Sender info")
    subject: Optional[str] = Field(None, description="Subject line")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


# ─── Response Models ───────────────────────────────────────────
class URLFeatures(BaseModel):
    length: int
    num_dots: int
    num_hyphens: int
    num_at: int
    num_params: int
    num_fragments: int
    num_subdomains: int
    has_ip: bool
    has_https: bool
    domain_length: int
    path_length: int
    has_suspicious_tld: bool
    entropy: float
    suspicious_keywords: List[str]
    redirect_count: int


class GeminiAnalysis(BaseModel):
    risk_score: float = Field(..., ge=0, le=1)
    classification: str
    reasoning: str
    indicators: List[str]
    brand_impersonation: Optional[str] = None
    urgency_level: str
    manipulation_tactics: List[str]
    recommendation: str


class VirusTotalResult(BaseModel):
    detected: bool
    positives: int
    total_scanners: int
    scan_date: Optional[str] = None
    permalink: Optional[str] = None
    categories: List[str] = []


class ScanResult(BaseModel):
    scan_id: str
    timestamp: str
    scan_type: ScanType
    target: str
    threat_level: ThreatLevel
    risk_score: float = Field(..., ge=0, le=1)
    url_features: Optional[URLFeatures] = None
    gemini_analysis: Optional[GeminiAnalysis] = None
    virustotal_result: Optional[VirusTotalResult] = None
    nlp_score: Optional[float] = None
    ml_score: Optional[float] = None
    ensemble_score: float
    detection_time_ms: float
    is_phishing: bool
    explanation: str
    indicators: List[str]
    recommendations: List[str]


class DashboardStats(BaseModel):
    total_scans: int
    threats_detected: int
    safe_urls: int
    detection_rate: float
    avg_response_time_ms: float
    false_positive_rate: float
    scans_today: int
    threat_breakdown: Dict[str, int]
    recent_scans: List[Dict[str, Any]]
    hourly_activity: List[Dict[str, Any]]


class SystemHealth(BaseModel):
    status: str
    uptime_seconds: float
    models_loaded: bool
    gemini_available: bool
    virustotal_available: bool
    total_scans_processed: int
    avg_detection_time_ms: float
