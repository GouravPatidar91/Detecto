from typing import Optional, List, Dict, Any
from pydantic import BaseModel

class ScanRequest(BaseModel):
    url: str
    live_probe: bool = True

class ScanResponse(BaseModel):
    id: Optional[int] = None
    url: str
    original_url: Optional[str] = None
    domain: str
    classification: str  # Safe, Suspicious, Malicious
    risk_score: float    # 0.0 to 100.0
    confidence: float    # 0.0 to 100.0
    status_message: str
    dns_resolved: bool
    resolved_ip: Optional[str] = None
    ssl_valid: bool
    ssl_issuer: Optional[str] = None
    live_probe_status: str
    is_redirected: bool = False
    redirect_hops: int = 0
    is_typosquatting: bool = False
    spoofed_brand: Optional[str] = None
    has_password_input: bool = False
    brand_title_mismatch: bool = False
    page_title: Optional[str] = None
    risk_reasons: List[str]
    features: Dict[str, float]
    scanned_at: str

class HistoryItem(BaseModel):
    id: int
    url: str
    domain: str
    classification: str
    risk_score: float
    confidence: float
    dns_resolved: bool
    ssl_valid: bool
    created_at: str

class StatsResponse(BaseModel):
    total_scans: int
    safe_scans: int
    suspicious_scans: int
    malicious_scans: int
    average_risk: float
