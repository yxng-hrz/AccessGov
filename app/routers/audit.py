from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditEvent
from app.schemas import AuditEventOut, ChainVerification
from app.security import AUDITOR
from app.services.audit import verify_chain

router = APIRouter(prefix="/audit", tags=["Audit trail"], dependencies=[Depends(AUDITOR)])


@router.get("", response_model=list[AuditEventOut])
def list_audit_events(limit: int = Query(default=100, ge=1, le=500), event_type: str | None = None, db: Session = Depends(get_db)):
    stmt = select(AuditEvent)
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    return db.scalars(stmt.order_by(AuditEvent.id.desc()).limit(limit)).all()


@router.get("/verify", response_model=ChainVerification)
def verify(db: Session = Depends(get_db)):
    """Recompute the SHA-256 hash chain: any edited or deleted event breaks it."""
    return verify_chain(db)
