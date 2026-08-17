from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AccessGrant, Application, Identity
from app.schemas import GrantCreate, GrantOut
from app.services.audit import log_event

router = APIRouter(prefix="/grants", tags=["Access grants"])


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


@router.post("", response_model=GrantOut, status_code=201)
def create_grant(payload: GrantCreate, db: Session = Depends(get_db)):
    if not db.get(Identity, payload.identity_id):
        raise HTTPException(status_code=404, detail="Identity not found")
    if not db.get(Application, payload.application_id):
        raise HTTPException(status_code=404, detail="Application not found")

    existing = db.scalar(select(AccessGrant).where(
        AccessGrant.identity_id == payload.identity_id,
        AccessGrant.application_id == payload.application_id,
        AccessGrant.entitlement == payload.entitlement,
    ))
    if existing:
        raise HTTPException(status_code=409, detail="Grant already exists")

    grant = AccessGrant(**payload.model_dump())
    db.add(grant)
    db.flush()
    log_event(db, "access_granted", actor=payload.granted_by or "api", entity_type="grant", entity_id=str(grant.id), details=payload.entitlement)
    db.commit()
    db.refresh(grant)
    return grant
