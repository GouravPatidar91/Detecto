from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime
from backend.database import Base

class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    classification = Column(String(50), nullable=False)  # Safe, Suspicious, Malicious
    risk_score = Column(Float, nullable=False)          # 0.0 to 100.0%
    confidence = Column(Float, nullable=False)          # 0.0 to 100.0%
    
    # Live Network Probing Metadata
    dns_resolved = Column(Boolean, default=False)
    resolved_ip = Column(String(100), nullable=True)
    ssl_valid = Column(Boolean, default=False)
    ssl_issuer = Column(String(255), nullable=True)
    live_probe_status = Column(String(50), default="unreachable")
    
    # Explanations and Raw Features (JSON)
    reasons_json = Column(Text, nullable=True)
    features_json = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
