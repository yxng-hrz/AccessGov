from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Identity
from app.schemas import IdentityCreate, IdentityOut, IdentityProfile, MoveRequest, OffboardRequest, OffboardResult
from app.security import ADMIN, ANY_ROLE, Principal
from app.services.anomaly_engine import detect_anomalies, identity_risk_score
from app.services.audit import log_event
from app.services.lifecycle import move_identity, offboard_identity

router = APIRouter(prefix="/identities", tags=["Identities & lifecycle"], dependencies=[Depends(ANY_ROLE)])


@router.get("", response_model=list[IdentityOut])
def list_identities(db: Session = Depends(get_db)):
    return db.scalars(select(Identity).order_by(Identity.display_name)).all()


@router.get("/{identity_id}", response_model=IdentityOut)
def get_identity(identity_id: int, db: Session = Depends(get_db)):
    identity = db.get(Identity, identity_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity


@router.get("/{identity_id}/profile", response_model=IdentityProfile)
def identity_profile(identity_id: int, db: Session = Depends(get_db)):
    """360° view: entitlements, open risk signals and an explainable identity risk score."""
    identity = db.get(Identity, identity_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    anomalies = [a for a in detect_anomalies(db) if a["identity_id"] == identity_id]
    return {
        "identity": identity,
        "risk_score": identity_risk_score(anomalies),
        "grants": sorted(identity.grants, key=lambda g: (not g.active, g.id)),
        "anomalies": anomalies,
    }


@router.post("", response_model=IdentityOut, status_code=201)
def create_identity(payload: IdentityCreate, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    if db.scalar(select(Identity).where(Identity.email == payload.email)):
        raise HTTPException(status_code=409, detail="Identity email already exists")
    if db.scalar(select(Identity).where(Identity.employee_id == payload.employee_id)):
        raise HTTPException(status_code=409, detail="Employee ID already exists")
    identity = Identity(**payload.model_dump())
    db.add(identity)
    db.flush()
    log_event(db, "identity_created", actor=principal.name, entity_type="identity", entity_id=str(identity.id), details=identity.email)
    db.commit()
    db.refresh(identity)
    return identity


@router.post("/{identity_id}/offboard", response_model=OffboardResult)
def offboard(identity_id: int, payload: OffboardRequest, db: Session = Depends(get_db), _: Principal = Depends(ADMIN)):
    """Leaver workflow: disable the account and revoke every active grant in one auditable step."""
    return offboard_identity(db, identity_id, actor=payload.actor, reason=payload.reason)


@router.post("/{identity_id}/move", response_model=IdentityOut)
def move(identity_id: int, payload: MoveRequest, db: Session = Depends(get_db), _: Principal = Depends(ADMIN)):
    """Mover workflow: record the new role; pre-existing access is flagged until recertified."""
    return move_identity(db, identity_id, payload.department, payload.job_title, payload.manager_email, actor=payload.actor)
