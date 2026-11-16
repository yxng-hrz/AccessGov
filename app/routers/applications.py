from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Application
from app.schemas import ApplicationCreate, ApplicationOut
from app.security import ADMIN, ANY_ROLE, Principal
from app.services.audit import log_event

router = APIRouter(prefix="/applications", tags=["Applications"], dependencies=[Depends(ANY_ROLE)])


@router.get("", response_model=list[ApplicationOut])
def list_applications(db: Session = Depends(get_db)):
    return db.scalars(select(Application).order_by(Application.name)).all()


@router.post("", response_model=ApplicationOut, status_code=201)
def create_application(payload: ApplicationCreate, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    if db.scalar(select(Application).where(Application.name == payload.name)):
        raise HTTPException(status_code=409, detail="Application already exists")
    application = Application(**payload.model_dump())
    db.add(application)
    db.flush()
    log_event(db, "application_created", actor=principal.name, entity_type="application", entity_id=str(application.id), details=application.name)
    db.commit()
    db.refresh(application)
    return application
