from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Identity
from app.schemas import IdentityCreate, IdentityOut
from app.services.audit import log_event

router = APIRouter(prefix="/identities", tags=["Identities"])


@router.get("", response_model=list[IdentityOut])
def list_identities(db: Session = Depends(get_db)):
    return db.scalars(select(Identity).order_by(Identity.display_name)).all()


@router.get("/{identity_id}", response_model=IdentityOut)
def get_identity(identity_id: int, db: Session = Depends(get_db)):
    identity = db.get(Identity, identity_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity


@router.post("", response_model=IdentityOut, status_code=201)
def create_identity(payload: IdentityCreate, db: Session = Depends(get_db)):
    if db.scalar(select(Identity).where(Identity.email == payload.email)):
        raise HTTPException(status_code=409, detail="Identity email already exists")
    if db.scalar(select(Identity).where(Identity.employee_id == payload.employee_id)):
        raise HTTPException(status_code=409, detail="Employee ID already exists")
    identity = Identity(**payload.model_dump())
    db.add(identity)
    db.flush()
    log_event(db, "identity_created", actor="api", entity_type="identity", entity_id=str(identity.id), details=identity.email)
    db.commit()
    db.refresh(identity)
    return identity
