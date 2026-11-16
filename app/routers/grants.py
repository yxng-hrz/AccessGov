from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import AccessGrant, Application, Identity
from app.schemas import GrantCreate, GrantOut
from app.security import ADMIN, ANY_ROLE, Principal
from app.services.audit import log_event
from app.services.lifecycle import expire_sweep, expiring_soon

router = APIRouter(prefix="/grants", tags=["Access grants"], dependencies=[Depends(ANY_ROLE)])


class RevokeRequest(BaseModel):
    reason: str


@router.get("", response_model=list[GrantOut])
def list_grants(
    active_only: bool = True,
    privileged_only: bool = False,
    identity_id: int | None = None,
    application_id: int | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    stmt = select(AccessGrant)
    if active_only:
        stmt = stmt.where(AccessGrant.active.is_(True))
    if privileged_only:
        stmt = stmt.where(AccessGrant.privileged.is_(True))
    if identity_id is not None:
        stmt = stmt.where(AccessGrant.identity_id == identity_id)
    if application_id is not None:
        stmt = stmt.where(AccessGrant.application_id == application_id)
    return db.scalars(stmt.order_by(AccessGrant.id).limit(limit)).all()


@router.get("/expiring", response_model=list[GrantOut])
def grants_expiring(days: int = Query(default=settings.expiry_warning_days, ge=1, le=365), db: Session = Depends(get_db)):
    """Time-bound grants that will expire within the horizon — renew or let them lapse."""
    return expiring_soon(db, days)


@router.post("/expire-sweep")
def run_expire_sweep(db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    """Deactivate every grant whose end date has passed (scheduled job in production)."""
    return expire_sweep(db, actor=principal.name)


@router.post("", response_model=GrantOut, status_code=201)
def create_grant(payload: GrantCreate, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    identity = db.get(Identity, payload.identity_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    if not db.get(Application, payload.application_id):
        raise HTTPException(status_code=404, detail="Application not found")
    if identity.employment_status == "terminated":
        raise HTTPException(status_code=409, detail="Cannot grant access to a terminated identity")
    if db.scalar(select(AccessGrant).where(
        AccessGrant.identity_id == payload.identity_id,
        AccessGrant.application_id == payload.application_id,
        AccessGrant.entitlement == payload.entitlement,
    )):
        raise HTTPException(status_code=409, detail="Grant already exists")

    grant = AccessGrant(**payload.model_dump())
    db.add(grant)
    db.flush()
    log_event(db, "access_granted", actor=payload.granted_by or principal.name, entity_type="grant", entity_id=str(grant.id),
              details=f"{payload.entitlement}; privileged={payload.privileged}; expires={payload.expires_at}")
    db.commit()
    db.refresh(grant)
    return grant


@router.post("/{grant_id}/revoke", response_model=GrantOut)
def revoke_grant(grant_id: int, payload: RevokeRequest, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    grant = db.get(AccessGrant, grant_id)
    if not grant:
        raise HTTPException(status_code=404, detail="Grant not found")
    if not grant.active:
        raise HTTPException(status_code=409, detail="Grant is already inactive")
    grant.active = False
    grant.revoked_at = datetime.now(timezone.utc)
    grant.revoked_reason = payload.reason
    log_event(db, "access_revoked_direct", actor=principal.name, entity_type="grant", entity_id=str(grant.id), details=payload.reason)
    db.commit()
    db.refresh(grant)
    return grant
