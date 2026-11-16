"""Joiner-Mover-Leaver automation."""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AccessGrant, Identity
from app.services.anomaly_engine import as_aware
from app.services.audit import log_event


def offboard_identity(db: Session, identity_id: int, actor: str, reason: str) -> dict:
    identity = db.get(Identity, identity_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    now = datetime.now(timezone.utc)
    identity.employment_status = "terminated"
    identity.account_enabled = False
    identity.terminated_at = now
    revoked = 0
    for grant in identity.grants:
        if grant.active:
            grant.active = False
            grant.revoked_at = now
            grant.revoked_reason = f"Offboarding: {reason}"
            revoked += 1
    log_event(db, "identity_offboarded", actor=actor, entity_type="identity", entity_id=str(identity.id),
              details=f"grants_revoked={revoked}; reason={reason}")
    db.commit()
    return {"identity_id": identity.id, "account_enabled": False, "grants_revoked": revoked}


def move_identity(db: Session, identity_id: int, department: str, job_title: str, manager_email: str, actor: str) -> Identity:
    identity = db.get(Identity, identity_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    previous = identity.department
    identity.previous_department = previous
    identity.department = department
    if job_title:
        identity.job_title = job_title
    if manager_email:
        identity.manager_email = manager_email
    identity.moved_at = datetime.now(timezone.utc)
    log_event(db, "identity_moved", actor=actor, entity_type="identity", entity_id=str(identity.id),
              details=f"from={previous}; to={department}")
    db.commit()
    db.refresh(identity)
    return identity


def expire_sweep(db: Session, actor: str) -> dict:
    now = datetime.now(timezone.utc)
    grants = db.scalars(select(AccessGrant).where(AccessGrant.active.is_(True), AccessGrant.expires_at.is_not(None))).all()
    expired = [g for g in grants if as_aware(g.expires_at) < now]
    for grant in expired:
        grant.active = False
        grant.revoked_at = now
        grant.revoked_reason = "Automatic expiry of time-bound access"
    log_event(db, "expiry_sweep", actor=actor, details=f"grants_expired={len(expired)}")
    db.commit()
    return {"grants_expired": len(expired), "grant_ids": [g.id for g in expired]}


def expiring_soon(db: Session, days: int) -> list[AccessGrant]:
    now = datetime.now(timezone.utc)
    horizon = now + timedelta(days=days)
    grants = db.scalars(select(AccessGrant).where(AccessGrant.active.is_(True), AccessGrant.expires_at.is_not(None))).all()
    return sorted([g for g in grants if now <= as_aware(g.expires_at) <= horizon], key=lambda g: as_aware(g.expires_at))


def hr_sync(db: Session, rows: list[dict], actor: str = "hr-feed") -> dict:
    """Reconcile the IAM inventory with an HR extract (the authoritative source).

    - status ``terminated`` on an identity still enabled  -> automatic offboarding
    - department change                                    -> mover workflow (residual access flagged)
    - employee_id unknown to IAM                           -> reported as joiner to provision
    """
    by_employee = {i.employee_id: i for i in db.scalars(select(Identity)).all()}
    leavers, movers, joiners, unchanged = [], [], [], 0
    for row in rows:
        employee_id = (row.get("employee_id") or "").strip()
        if not employee_id:
            continue
        identity = by_employee.get(employee_id)
        status = (row.get("employment_status") or "active").strip().lower()
        department = (row.get("department") or "").strip()
        if identity is None:
            if status != "terminated":
                joiners.append(employee_id)
            continue
        if status == "terminated" and (identity.account_enabled or any(g.active for g in identity.grants)):
            result = offboard_identity(db, identity.id, actor=actor, reason="HR status = terminated")
            leavers.append({"employee_id": employee_id, "grants_revoked": result["grants_revoked"]})
        elif status != "terminated" and department and department != identity.department:
            move_identity(db, identity.id, department, (row.get("job_title") or "").strip(),
                          (row.get("manager_email") or "").strip(), actor=actor)
            movers.append({"employee_id": employee_id, "to": department})
        else:
            unchanged += 1
    log_event(db, "hr_sync", actor=actor,
              details=f"leavers={len(leavers)}; movers={len(movers)}; joiners_to_provision={len(joiners)}")
    db.commit()
    return {"leavers_offboarded": leavers, "movers": movers, "joiners_to_provision": joiners, "unchanged": unchanged}
