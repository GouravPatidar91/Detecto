import json
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import engine, Base, get_db
from backend.models import ScanRecord
from backend.schemas import ScanRequest, ScanResponse, HistoryItem, StatsResponse
from backend.ml_service import ml_service

# Initialize database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Detecto — AI Malicious URL Detector",
    description="Intelligent real-time detection of phishing, malware, and fraudulent URLs using Machine Learning.",
    version="1.0.0"
)

# Enable CORS for browser access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static frontend
import os
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Detecto API is active. Frontend is loading..."}

@app.post("/api/scan", response_model=ScanResponse)
def scan_url(request: ScanRequest, db: Session = Depends(get_db)):
    raw_url = request.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    try:
        # Run ML analysis + live network probe
        result = ml_service.analyze_url(raw_url, enable_live_probe=request.live_probe)

        # Save record in database
        db_record = ScanRecord(
            url=result["url"],
            domain=result["domain"],
            classification=result["classification"],
            risk_score=result["risk_score"],
            confidence=result["confidence"],
            dns_resolved=result["dns_resolved"],
            resolved_ip=result["resolved_ip"],
            ssl_valid=result["ssl_valid"],
            ssl_issuer=result["ssl_issuer"],
            live_probe_status=result["live_probe_status"],
            reasons_json=json.dumps(result["risk_reasons"]),
            features_json=json.dumps(result["features"]),
            created_at=datetime.utcnow()
        )
        db.add(db_record)
        db.commit()
        db.refresh(db_record)

        result["id"] = db_record.id
        result["scanned_at"] = db_record.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        return result
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/history", response_model=List[HistoryItem])
def get_history(
    limit: int = Query(25, ge=1, le=100),
    filter_class: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ScanRecord)
    if filter_class and filter_class.capitalize() in ["Safe", "Suspicious", "Malicious"]:
        query = query.filter(ScanRecord.classification == filter_class.capitalize())

    records = query.order_by(ScanRecord.created_at.desc()).limit(limit).all()

    items = []
    for r in records:
        items.append(
            HistoryItem(
                id=r.id,
                url=r.url,
                domain=r.domain,
                classification=r.classification,
                risk_score=r.risk_score,
                confidence=r.confidence,
                dns_resolved=r.dns_resolved,
                ssl_valid=r.ssl_valid,
                created_at=r.created_at.strftime("%Y-%m-%d %H:%M:%S")
            )
        )
    return items

@app.get("/api/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    total = db.query(ScanRecord).count()
    safe = db.query(ScanRecord).filter(ScanRecord.classification == "Safe").count()
    suspicious = db.query(ScanRecord).filter(ScanRecord.classification == "Suspicious").count()
    malicious = db.query(ScanRecord).filter(ScanRecord.classification == "Malicious").count()
    
    avg_risk = db.query(func.avg(ScanRecord.risk_score)).scalar() or 0.0

    return StatsResponse(
        total_scans=total,
        safe_scans=safe,
        suspicious_scans=suspicious,
        malicious_scans=malicious,
        average_risk=round(float(avg_risk), 1)
    )

@app.delete("/api/history")
def clear_history(db: Session = Depends(get_db)):
    db.query(ScanRecord).delete()
    db.commit()
    return {"message": "Scan history cleared successfully."}
