from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import AnomalyOut
from app.security import ANY_ROLE
from app.services.anomaly_engine import detect_anomalies

router = APIRouter(prefix="/anomalies", tags=["IAM risk signals"], dependencies=[Depends(ANY_ROLE)])


@router.get("", response_model=list[AnomalyOut])
def list_anomalies(
    severity: str | None = Query(default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    code: str | None = None,
    include_excepted: bool = False,
    db: Session = Depends(get_db),
):
    anomalies = detect_anomalies(db, include_excepted=include_excepted)
    if severity:
        anomalies = [a for a in anomalies if a["severity"] == severity]
    if code:
        anomalies = [a for a in anomalies if a["code"] == code]
    return anomalies
