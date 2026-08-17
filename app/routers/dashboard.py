from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import DashboardOut
from app.services.dashboard_service import dashboard_summary

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardOut)
def summary(db: Session = Depends(get_db)):
    return dashboard_summary(db)
