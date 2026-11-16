from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import DashboardOut, IdentityRisk, SnapshotOut
from app.security import ADMIN, ANY_ROLE, Principal
from app.services.anomaly_engine import detect_anomalies
from app.services.compliance import coverage
from app.services.dashboard_service import dashboard_summary, identity_ranking, posture_trend, take_snapshot

router = APIRouter(prefix="/dashboard", tags=["Dashboard & posture"], dependencies=[Depends(ANY_ROLE)])


@router.get("/summary", response_model=DashboardOut)
def summary(db: Session = Depends(get_db)):
    return dashboard_summary(db)


@router.get("/compliance")
def compliance(db: Session = Depends(get_db)):
    """ISO 27001:2022 / NIS2 / DORA controls currently put at risk by open IAM signals."""
    return coverage(detect_anomalies(db))


@router.get("/top-identities", response_model=list[IdentityRisk])
def top_identities(limit: int = Query(default=10, ge=1, le=100), db: Session = Depends(get_db)):
    return identity_ranking(db, limit)


@router.post("/snapshots", response_model=SnapshotOut, status_code=201)
def snapshot(label: str = "", db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    return take_snapshot(db, label=label, actor=principal.name)


@router.get("/trend", response_model=list[SnapshotOut])
def trend(limit: int = Query(default=12, ge=1, le=100), db: Session = Depends(get_db)):
    return posture_trend(db, limit)
