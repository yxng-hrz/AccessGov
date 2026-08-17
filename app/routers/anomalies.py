from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import AnomalyOut
from app.services.anomaly_engine import detect_anomalies

router = APIRouter(prefix="/anomalies", tags=["IAM anomalies"])


@router.get("", response_model=list[AnomalyOut])
def list_anomalies(
    severity: str | None = Query(default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    code: str | None = None,
    db: Session = Depends(get_db),
):
    anomalies = detect_anomalies(db)
    if severity:
        anomalies = [item for item in anomalies if item["severity"] == severity]
    if code:
        anomalies = [item for item in anomalies if item["code"] == code]
    return anomalies
