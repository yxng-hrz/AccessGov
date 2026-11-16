import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

TEST_DB = Path(__file__).parent / "test_accessgov.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["DORMANT_DAYS"] = "90"
os.environ["EXCESSIVE_ENTITLEMENT_THRESHOLD"] = "3"

from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AccessGrant, Application, Identity  # noqa: E402


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def sample_data(db):
    manager = "manager@demo.local"
    active = Identity(
        employee_id="E1",
        email="active@demo.local",
        display_name="Active User",
        manager_email=manager,
        employment_status="active",
        identity_type="human",
        account_enabled=True,
        last_login_at=datetime(2026, 8, 16, tzinfo=timezone.utc),
    )
    leaver = Identity(
        employee_id="E2",
        email="leaver@demo.local",
        display_name="Leaver User",
        manager_email=manager,
        employment_status="terminated",
        identity_type="human",
        account_enabled=True,
        last_login_at=datetime(2026, 8, 10, tzinfo=timezone.utc),
    )
    service = Identity(
        employee_id="S1",
        email="service@demo.local",
        display_name="Service",
        employment_status="active",
        identity_type="service",
        owner_email="",
        account_enabled=True,
        last_login_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    app_obj = Application(name="Finance ERP", owner_email="owner@demo.local", criticality=5, contains_sensitive_data=True)
    db.add_all([active, leaver, service, app_obj])
    db.commit()
    for obj in [active, leaver, service, app_obj]:
        db.refresh(obj)

    grants = [
        AccessGrant(identity_id=active.id, application_id=app_obj.id, entitlement="AP_INVOICE_CREATE", access_level="elevated", active=True),
        AccessGrant(identity_id=active.id, application_id=app_obj.id, entitlement="AP_PAYMENT_APPROVE", access_level="elevated", privileged=True, justification="Month end", active=True),
        AccessGrant(identity_id=leaver.id, application_id=app_obj.id, entitlement="FINANCE_ADMIN", access_level="admin", privileged=True, justification="", active=True),
        AccessGrant(identity_id=service.id, application_id=app_obj.id, entitlement="BACKUP_OPERATOR", access_level="elevated", privileged=True, justification="Backup", active=True),
    ]
    db.add_all(grants)
    db.commit()
    for grant in grants:
        db.refresh(grant)
    return {"active": active, "leaver": leaver, "service": service, "application": app_obj, "grants": grants}
