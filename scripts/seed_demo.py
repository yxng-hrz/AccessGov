"""Seed a synthetic, deliberately imperfect IAM estate so every governance feature is visible.

Dates in data/*.csv are written relative to REFERENCE_DATE and rebased to "now",
so the demo stays meaningful whenever it is run.
"""
import csv
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import (  # noqa: E402
    AccessGrant, Application, AuditEvent, Identity, PostureSnapshot, ReviewCampaign, ReviewItem, RiskException, SodRule,
)
from app.schemas import CampaignCreate, DelegateRequest, ReviewDecision  # noqa: E402
from app.services.audit import log_event  # noqa: E402
from app.services.campaign_service import create_campaign, decide_review_item, delegate_review_item  # noqa: E402
from app.services.dashboard_service import take_snapshot  # noqa: E402
from app.services.sod_rules import ensure_default_rules  # noqa: E402

REFERENCE_DATE = datetime(2026, 8, 17, tzinfo=timezone.utc)
NOW = datetime.now(timezone.utc)


def rebase(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    return NOW - (REFERENCE_DATE - datetime.fromisoformat(value))


def read_csv(name: str):
    with (ROOT / "data" / name).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def as_bool(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes"}


def seed():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        ensure_default_rules(db)

        for row in read_csv("applications.csv"):
            db.add(Application(name=row["name"], owner_email=row["owner_email"], criticality=int(row["criticality"]),
                               contains_sensitive_data=as_bool(row["contains_sensitive_data"]), description=row["description"]))
        for row in read_csv("identities.csv"):
            db.add(Identity(
                employee_id=row["employee_id"], email=row["email"], display_name=row["display_name"],
                department=row["department"], job_title=row["job_title"], manager_email=row["manager_email"],
                employment_status=row["employment_status"], identity_type=row["identity_type"],
                owner_email=row["owner_email"], account_enabled=as_bool(row["account_enabled"]),
                last_login_at=rebase(row["last_login_at"]),
            ))
        db.commit()

        identities = {i.email: i for i in db.query(Identity).all()}
        applications = {a.name: a for a in db.query(Application).all()}
        for row in read_csv("grants.csv"):
            db.add(AccessGrant(
                identity_id=identities[row["identity_email"]].id, application_id=applications[row["application"]].id,
                entitlement=row["entitlement"], access_level=row["access_level"], privileged=as_bool(row["privileged"]),
                granted_by=row["granted_by"], justification=row["justification"], active=as_bool(row["active"]),
                granted_at=NOW - timedelta(days=400), expires_at=rebase(row.get("expires_at", "")),
            ))
        db.commit()
        log_event(db, "demo_seeded", actor="seed", details="synthetic IAM estate loaded")

        # Mover: Ines moved from Finance to Data 45 days ago and still holds a Finance ERP right.
        ines = identities["ines.michel@demo.local"]
        ines.previous_department, ines.moved_at = "Finance", NOW - timedelta(days=45)
        for grant in ines.grants:
            if grant.entitlement == "BI_ANALYST":  # access granted for the new role, after the move
                grant.granted_at = NOW - timedelta(days=40)
        log_event(db, "identity_moved", actor="hr-feed", entity_type="identity", entity_id=str(ines.id), details="from=Finance; to=Data")

        # Accepted risk: Henry's emergency vendor-payment coverage (SoD) accepted by the CFO for 60 days.
        henry = identities["henry.laurent@demo.local"]
        db.add(RiskException(anomaly_code="SOD_CONFLICT", identity_id=henry.id,
                             justification="Single buyer during the supplier-onboarding freeze",
                             compensating_control="CFO second approval on every vendor payment above 5k EUR",
                             risk_owner="sophie.cfo@demo.local", approved_by="sophie.cfo@demo.local",
                             expires_at=NOW + timedelta(days=60)))
        # Expired acceptance that must resurface: backup service account without owner.
        backup = identities["svc-backup@demo.local"]
        db.add(RiskException(anomaly_code="SERVICE_NO_OWNER", identity_id=backup.id,
                             justification="Owner being appointed after IT reorganisation",
                             compensating_control="Credentials vaulted, interactive logon disabled",
                             risk_owner="paul.it@demo.local", approved_by="lea.ciso@demo.local",
                             expires_at=NOW - timedelta(days=3)))
        db.commit()

        # Demo history so the trend chart is meaningful (synthetic values, clearly labelled).
        for weeks, label, score, crit, high in [(39, "Q4-2025", 26, 9, 14), (26, "Q1-2026", 31, 8, 13), (13, "Q2-2026", 37, 7, 12)]:
            db.add(PostureSnapshot(label=label, governance_score=score, critical=crit, high=high, medium=10,
                                   privileged_grants=17, review_completion=0.0, created_at=NOW - timedelta(weeks=weeks)))
        db.commit()

        campaign = create_campaign(db, CampaignCreate(
            name="Q4 2026 Privileged Access Review",
            description="Quarterly certification of privileged access across critical applications.",
            scope="privileged", created_by="lea.ciso@demo.local",
        ))
        items = sorted(campaign.items, key=lambda i: i.id)
        for item in items:
            if item.grant.entitlement in {"CLOUD_ADMIN", "CI_WRITE", "BACKUP_OPERATOR"}:
                decide_review_item(db, item.id, ReviewDecision(decision="approve", reviewer_email=item.reviewer_email,
                                                               reason="Still required for current role"))
            elif item.grant.entitlement == "ORG_ADMIN":
                decide_review_item(db, item.id, ReviewDecision(decision="revoke", reviewer_email=item.reviewer_email,
                                                               reason="Developer support no longer requires org admin"))
            elif item.grant.entitlement == "SUPPORT_ADMIN" and item.identity.email.startswith("jules"):
                delegate_review_item(db, item.id, DelegateRequest(delegate_to="support-deputy@demo.local",
                                                                  actor=item.reviewer_email, reason="Manager on leave"))

        take_snapshot(db, label="Current", actor="seed")

        print("AccessGov demo seeded successfully.")
        for model in [Identity, Application, AccessGrant, SodRule, RiskException, ReviewItem, PostureSnapshot, AuditEvent]:
            print(f"  {model.__tablename__:<18} {db.query(model).count()}")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
