from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import AccessGrant, Identity, RiskException, SodRule
from app.schemas import RiskExceptionCreate, RiskExceptionOut, SodRuleCreate, SodRuleOut
from app.security import ADMIN, ANY_ROLE, Principal
from app.services.anomaly_engine import as_aware
from app.services.audit import log_event
from app.services.compliance import ANOMALY_CONTROLS
from app.services.report_service import executive_report

router = APIRouter(tags=["Governance"], dependencies=[Depends(ANY_ROLE)])


# --- Separation-of-duties policy-as-code -------------------------------------------------

@router.get("/sod-rules", response_model=list[SodRuleOut])
def list_sod_rules(db: Session = Depends(get_db)):
    return db.scalars(select(SodRule).order_by(SodRule.code)).all()


@router.post("/sod-rules", response_model=SodRuleOut, status_code=201)
def create_sod_rule(payload: SodRuleCreate, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    if db.scalar(select(SodRule).where(SodRule.code == payload.code)):
        raise HTTPException(status_code=409, detail="SoD rule code already exists")
    data = payload.model_dump()
    data["left_entitlement"] = data["left_entitlement"].upper()
    data["right_entitlement"] = data["right_entitlement"].upper()
    rule = SodRule(**data)
    db.add(rule)
    db.flush()
    log_event(db, "sod_rule_created", actor=principal.name, entity_type="sod_rule", entity_id=str(rule.id),
              details=f"{rule.code}: {rule.left_entitlement} x {rule.right_entitlement}")
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/sod-rules/{rule_id}/toggle", response_model=SodRuleOut)
def toggle_sod_rule(rule_id: int, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    rule = db.get(SodRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="SoD rule not found")
    rule.enabled = not rule.enabled
    log_event(db, "sod_rule_toggled", actor=principal.name, entity_type="sod_rule", entity_id=str(rule.id), details=f"enabled={rule.enabled}")
    db.commit()
    db.refresh(rule)
    return rule


# --- Time-bound risk exceptions ------------------------------------------------------------

@router.get("/exceptions", response_model=list[RiskExceptionOut])
def list_exceptions(status: str | None = None, db: Session = Depends(get_db)):
    stmt = select(RiskException)
    if status:
        stmt = stmt.where(RiskException.status == status)
    return db.scalars(stmt.order_by(RiskException.expires_at)).all()


@router.post("/exceptions", response_model=RiskExceptionOut, status_code=201, dependencies=[Depends(ADMIN)])
def create_exception(payload: RiskExceptionCreate, db: Session = Depends(get_db)):
    if payload.anomaly_code not in ANOMALY_CONTROLS or payload.anomaly_code == "EXCEPTION_EXPIRED":
        raise HTTPException(status_code=422, detail="Unknown or non-exceptionable anomaly code")
    if payload.anomaly_code in {"LEAVER_ACTIVE", "PRIVILEGED_NON_ACTIVE"}:
        raise HTTPException(status_code=422, detail="Leaver risks cannot be accepted: they must be remediated")
    if not db.get(Identity, payload.identity_id):
        raise HTTPException(status_code=404, detail="Identity not found")
    if payload.grant_id is not None and not db.get(AccessGrant, payload.grant_id):
        raise HTTPException(status_code=404, detail="Grant not found")
    now = datetime.now(timezone.utc)
    expires = as_aware(payload.expires_at)
    if expires <= now:
        raise HTTPException(status_code=422, detail="Expiry date must be in the future")
    if expires > now + timedelta(days=settings.exception_max_days):
        raise HTTPException(status_code=422, detail=f"Exceptions cannot exceed {settings.exception_max_days} days")
    identity = db.get(Identity, payload.identity_id)
    if payload.approved_by.strip().lower() == identity.email.lower():
        raise HTTPException(status_code=403, detail="An identity cannot approve an exception on its own access")

    exception = RiskException(**payload.model_dump())
    db.add(exception)
    db.flush()
    log_event(db, "risk_exception_created", actor=payload.approved_by, entity_type="risk_exception", entity_id=str(exception.id),
              details=f"{payload.anomaly_code}; identity={payload.identity_id}; expires={expires.date().isoformat()}; control={payload.compensating_control}")
    db.commit()
    db.refresh(exception)
    return exception


@router.post("/exceptions/{exception_id}/revoke", response_model=RiskExceptionOut)
def revoke_exception(exception_id: int, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    exception = db.get(RiskException, exception_id)
    if not exception:
        raise HTTPException(status_code=404, detail="Exception not found")
    exception.status = "revoked"
    log_event(db, "risk_exception_revoked", actor=principal.name, entity_type="risk_exception", entity_id=str(exception.id))
    db.commit()
    db.refresh(exception)
    return exception


# --- Executive reporting -------------------------------------------------------------------

@router.get("/reports/executive", response_class=PlainTextResponse)
def get_executive_report(db: Session = Depends(get_db)):
    """COMEX-ready Markdown report: score, trend, top risks, regulatory exposure, decisions requested."""
    return PlainTextResponse(executive_report(db), media_type="text/markdown; charset=utf-8")
