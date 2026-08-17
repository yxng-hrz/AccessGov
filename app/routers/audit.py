from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditEvent
from app.schemas import AuditEventOut

router = APIRouter(prefix="/audit", tags=["Audit trail"])


@router.get("", response_model=list[AuditEventOut])
def list_audit_events(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    return db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)).all()
