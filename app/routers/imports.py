import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AccessGrant, Application, Identity
from app.services.audit import log_event

router = APIRouter(prefix="/imports", tags=["CSV imports"])


def _rows_from_upload(file: UploadFile) -> list[dict[str, str]]:
    raw = file.file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded") from exc
    return list(csv.DictReader(io.StringIO(text)))


def _bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _date(value: str) -> datetime | None:
    value = (value or "").strip()
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


@router.post("/applications")
def import_applications(file: UploadFile = File(...), db: Session = Depends(get_db)):
    created = 0
    skipped = 0
    for row in _rows_from_upload(file):
        name = row.get("name", "").strip()
        if not name:
            continue
        if db.scalar(select(Application).where(Application.name == name)):
            skipped += 1
            continue
        db.add(Application(
            name=name,
            owner_email=row.get("owner_email", "").strip(),
            criticality=int(row.get("criticality") or 3),
            contains_sensitive_data=_bool(row.get("contains_sensitive_data", "false")),
            description=row.get("description", "").strip(),
        ))
        created += 1
    log_event(db, "csv_import_applications", actor="api", details=f"created={created}; skipped={skipped}")
    db.commit()
    return {"created": created, "skipped": skipped}


@router.post("/identities")
def import_identities(file: UploadFile = File(...), db: Session = Depends(get_db)):
    created = 0
    skipped = 0
    for row in _rows_from_upload(file):
        email = row.get("email", "").strip()
        employee_id = row.get("employee_id", "").strip()
        if not email or not employee_id:
            continue
        if db.scalar(select(Identity).where((Identity.email == email) | (Identity.employee_id == employee_id))):
            skipped += 1
            continue
        db.add(Identity(
            employee_id=employee_id,
            email=email,
            display_name=row.get("display_name", email).strip(),
            department=row.get("department", "Unknown").strip(),
            job_title=row.get("job_title", "").strip(),
            manager_email=row.get("manager_email", "").strip(),
            employment_status=row.get("employment_status", "active").strip(),
            identity_type=row.get("identity_type", "human").strip(),
            owner_email=row.get("owner_email", "").strip(),
            account_enabled=_bool(row.get("account_enabled", "true")),
            last_login_at=_date(row.get("last_login_at", "")),
        ))
        created += 1
    log_event(db, "csv_import_identities", actor="api", details=f"created={created}; skipped={skipped}")
    db.commit()
    return {"created": created, "skipped": skipped}


@router.post("/grants")
def import_grants(file: UploadFile = File(...), db: Session = Depends(get_db)):
    created = 0
    skipped = 0
    errors: list[str] = []
    for index, row in enumerate(_rows_from_upload(file), start=2):
        email = row.get("identity_email", "").strip()
        app_name = row.get("application", "").strip()
        entitlement = row.get("entitlement", "").strip()
        identity = db.scalar(select(Identity).where(Identity.email == email))
        application = db.scalar(select(Application).where(Application.name == app_name))
        if not identity or not application or not entitlement:
            errors.append(f"row {index}: unknown identity/application or missing entitlement")
            continue
        existing = db.scalar(select(AccessGrant).where(
            AccessGrant.identity_id == identity.id,
            AccessGrant.application_id == application.id,
            AccessGrant.entitlement == entitlement,
        ))
        if existing:
            skipped += 1
            continue
        db.add(AccessGrant(
            identity_id=identity.id,
            application_id=application.id,
            entitlement=entitlement,
            access_level=row.get("access_level", "standard").strip(),
            privileged=_bool(row.get("privileged", "false")),
            granted_by=row.get("granted_by", "").strip(),
            justification=row.get("justification", "").strip(),
            active=_bool(row.get("active", "true")),
        ))
        created += 1
    log_event(db, "csv_import_grants", actor="api", details=f"created={created}; skipped={skipped}; errors={len(errors)}")
    db.commit()
    return {"created": created, "skipped": skipped, "errors": errors}
