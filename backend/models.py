"""
SecureLink Guardian - Data Models
Pydantic models for request/response validation
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, HttpUrl, validator
from datetime import datetime
from enum import Enum


class VerdictEnum(str, Enum):
    """Verdict types"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


class ScanRequest(BaseModel):
    """URL scan request"""
    url: str = Field(..., description="URL to scan")
    deep_scan: bool = Field(True, description="Enable deep scanning")
    include_screenshot: bool = Field(False, description="Include page screenshot")
    check_redirects: bool = Field(True, description="Follow and analyze redirects")
    analyze_javascript: bool = Field(True, description="Analyze JavaScript code")
    
    @validator('url')
    def validate_url(cls, v):
        """Validate URL format"""
        if not v.startswith(('http://', 'https://')):
            v = 'https://' + v
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://example.com",
                "deep_scan": True,
                "include_screenshot": False,
                "check_redirects": True,
                "analyze_javascript": True
            }
        }


class DNSAnalysisResult(BaseModel):
    """DNS analysis result"""
    typosquatting: bool = Field(False, description="Typosquatting detected")
    typosquatting_target: Optional[str] = Field(None, description="Target domain being spoofed")
    typosquatting_similarity: Optional[float] = Field(None, description="Similarity score")
    homograph: bool = Field(False, description="Homograph attack detected")
    homograph_details: Optional[str] = Field(None, description="Details of homograph attack")
    domain_age_days: Optional[int] = Field(None, description="Domain age in days")
    domain_age_suspicious: bool = Field(False, description="Domain is suspiciously new")
    whois_privacy: bool = Field(False, description="WHOIS privacy protection enabled")
    ssl_valid: bool = Field(False, description="SSL certificate is valid")
    ssl_issuer: Optional[str] = Field(None, description="SSL certificate issuer")
    ssl_expiry_days: Optional[int] = Field(None, description="Days until SSL expiry")
    dns_reputation_score: Optional[int] = Field(None, description="DNS reputation score (0-100)")
    mx_records_exist: bool = Field(False, description="MX records exist")
    
    class Config:
        schema_extra = {
            "example": {
                "typosquatting": True,
                "typosquatting_target": "amazon.com",
                "typosquatting_similarity": 0.95,
                "homograph": False,
                "domain_age_days": 3,
                "domain_age_suspicious": True,
                "whois_privacy": True,
                "ssl_valid": False,
                "dns_reputation_score": 15
            }
        }


class URLAnalysisResult(BaseModel):
    """URL manipulation analysis result"""
    is_shortener: bool = Field(False, description="URL shortener detected")
    shortener_service: Optional[str] = Field(None, description="Shortener service name")
    expanded_url: Optional[str] = Field(None, description="Expanded URL if shortener")
    redirect_chain: List[str] = Field(default_factory=list, description="Redirect chain")
    redirect_count: int = Field(0, description="Number of redirects")
    suspicious_params: bool = Field(False, description="Suspicious parameters detected")
    suspicious_param_details: Optional[List[str]] = Field(None, description="Details of suspicious params")
    encoding_tricks: bool = Field(False, description="URL encoding tricks detected")
    encoding_details: Optional[str] = Field(None, description="Details of encoding")
    open_redirect: bool = Field(False, description="Open redirect vulnerability detected")
    suspicious_tld: bool = Field(False, description="Suspicious TLD")
    subdomain_count: int = Field(0, description="Number of subdomains")
    subdomain_suspicious: bool = Field(False, description="Suspicious subdomain structure")
    
    class Config:
        schema_extra = {
            "example": {
                "is_shortener": True,
                "shortener_service": "bit.ly",
                "redirect_chain": ["bit.ly/xyz", "malicious.com"],
                "redirect_count": 1,
                "suspicious_params": True,
                "suspicious_tld": False
            }
        }


class WebAnalysisResult(BaseModel):
    """Web content analysis result"""
    brand_impersonation: bool = Field(False, description="Brand impersonation detected")
    impersonated_brand: Optional[str] = Field(None, description="Brand being impersonated")
    visual_similarity_score: Optional[float] = Field(None, description="Visual similarity score")
    credential_forms: bool = Field(False, description="Credential harvesting forms detected")
    form_count: int = Field(0, description="Number of forms")
    password_fields: int = Field(0, description="Number of password fields")
    social_engineering: bool = Field(False, description="Social engineering tactics detected")
    urgency_language: Optional[List[str]] = Field(None, description="Urgency language detected")
    javascript_suspicious: bool = Field(False, description="Suspicious JavaScript detected")
    javascript_threats: Optional[List[str]] = Field(None, description="JavaScript threats found")
    external_resources: int = Field(0, description="Number of external resources")
    suspicious_resources: int = Field(0, description="Number of suspicious external resources")
    favicon_mismatch: bool = Field(False, description="Favicon doesn't match brand")
    
    class Config:
        schema_extra = {
            "example": {
                "brand_impersonation": True,
                "impersonated_brand": "PayPal",
                "visual_similarity_score": 0.92,
                "credential_forms": True,
                "password_fields": 1,
                "social_engineering": True,
                "urgency_language": ["Act now!", "Account will be suspended"]
            }
        }


class GeneticAnalysisResult(BaseModel):
    """Genetic algorithm analysis result"""
    dna_similarity_score: Optional[float] = Field(None, description="DNA sequence similarity score")
    mutation_family: Optional[str] = Field(None, description="Phishing mutation family")
    known_campaign: bool = Field(False, description="Part of known phishing campaign")
    campaign_id: Optional[str] = Field(None, description="Campaign identifier")
    evolutionary_distance: Optional[float] = Field(None, description="Evolutionary distance from legitimate site")
    pattern_match: bool = Field(False, description="Matches known phishing patterns")
    
    class Config:
        schema_extra = {
            "example": {
                "dna_similarity_score": 0.87,
                "mutation_family": "amazon-phishing-2024",
                "known_campaign": True,
                "campaign_id": "APT-2024-001",
                "evolutionary_distance": 2.3
            }
        }


class ScanResult(BaseModel):
    """Complete scan result"""
    scan_id: str = Field(..., description="Unique scan identifier")
    url: str = Field(..., description="Scanned URL")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Scan timestamp")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score (0-100)")
    verdict: VerdictEnum = Field(..., description="Final verdict")
    response_time_ms: int = Field(..., description="Analysis response time in milliseconds")
    
    # Analysis results
    dns_analysis: Optional[DNSAnalysisResult] = None
    url_analysis: Optional[URLAnalysisResult] = None
    web_analysis: Optional[WebAnalysisResult] = None
    genetic_analysis: Optional[GeneticAnalysisResult] = None
    
    # Additional metadata
    screenshot_url: Optional[str] = Field(None, description="URL to page screenshot")
    page_title: Optional[str] = Field(None, description="Page title")
    final_url: Optional[str] = Field(None, description="Final URL after redirects")
    
    class Config:
        schema_extra = {
            "example": {
                "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                "url": "https://amaz0n-secure.com",
                "risk_score": 95,
                "verdict": "blocked",
                "response_time_ms": 1847,
                "dns_analysis": {
                    "typosquatting": True,
                    "domain_age_days": 3
                }
            }
        }


class ReportRequest(BaseModel):
    """False positive report request"""
    url: str = Field(..., description="URL that was flagged")
    scan_id: str = Field(..., description="Scan ID from original scan")
    feedback: str = Field(..., min_length=10, description="User feedback")
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://example.com",
                "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                "feedback": "This is my company's legitimate website"
            }
        }


class StatisticsResponse(BaseModel):
    """System statistics response"""
    total_scans: int = Field(0, description="Total number of scans")
    threats_blocked: int = Field(0, description="Number of threats blocked")
    safe_sites: int = Field(0, description="Number of safe sites")
    avg_response_time: int = Field(0, description="Average response time in ms")
    scans_last_hour: int = Field(0, description="Scans in the last hour")
    scans_last_24h: int = Field(0, description="Scans in the last 24 hours")
    top_threats: List[Dict[str, Any]] = Field(default_factory=list, description="Top threat types")
    
    class Config:
        schema_extra = {
            "example": {
                "total_scans": 15247,
                "threats_blocked": 3421,
                "safe_sites": 11826,
                "avg_response_time": 1523,
                "scans_last_hour": 42,
                "scans_last_24h": 987
            }
        }


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field("healthy", description="System status")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str = Field("1.0.0", description="API version")
    services: Dict[str, bool] = Field(default_factory=dict, description="Service health status")
    
    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2024-12-21T10:30:00Z",
                "version": "1.0.0",
                "services": {
                    "redis": True,
                    "mongodb": True,
                    "ml_models": True
                }
            }
        }


class ErrorResponse(BaseModel):
    """Error response"""
    error: str = Field(..., description="Error message")
    details: Optional[str] = Field(None, description="Error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        schema_extra = {
            "example": {
                "error": "Invalid URL format",
                "details": "URL must start with http:// or https://",
                "timestamp": "2024-12-21T10:30:00Z"
            }
        }