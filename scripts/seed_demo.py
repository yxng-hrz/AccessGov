import csv
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import AccessGrant, Application, AuditEvent, Identity, ReviewCampaign, ReviewItem  # noqa: E402
from app.schemas import CampaignCreate  # noqa: E402
from app.services.campaign_service import create_campaign  # noqa: E402


def read_csv(name: str):
    with (ROOT / "data" / name).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def as_bool(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes"}


def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for model in [ReviewItem, ReviewCampaign, AuditEvent, AccessGrant, Identity, Application]:
            db.query(model).delete()
        db.commit()

        for row in read_csv("applications.csv"):
            db.add(Application(
                name=row["name"],
                owner_email=row["owner_email"],
                criticality=int(row["criticality"]),
                contains_sensitive_data=as_bool(row["contains_sensitive_data"]),
                description=row["description"],
            ))
        db.commit()

        from datetime import datetime
        for row in read_csv("identities.csv"):
            db.add(Identity(
                employee_id=row["employee_id"],
                email=row["email"],
                display_name=row["display_name"],
                department=row["department"],
                job_title=row["job_title"],
                manager_email=row["manager_email"],
                employment_status=row["employment_status"],
                identity_type=row["identity_type"],
                owner_email=row["owner_email"],
                account_enabled=as_bool(row["account_enabled"]),
                last_login_at=datetime.fromisoformat(row["last_login_at"]),
            ))
        db.commit()

        identities = {identity.email: identity for identity in db.query(Identity).all()}
        applications = {application.name: application for application in db.query(Application).all()}
        for row in read_csv("grants.csv"):
            db.add(AccessGrant(
                identity_id=identities[row["identity_email"]].id,
                application_id=applications[row["application"]].id,
                entitlement=row["entitlement"],
                access_level=row["access_level"],
                privileged=as_bool(row["privileged"]),
                granted_by=row["granted_by"],
                justification=row["justification"],
                active=as_bool(row["active"]),
            ))
        db.commit()

        create_campaign(db, CampaignCreate(
            name="Q3 2026 Privileged Access Review",
            description="Quarterly certification of privileged access across critical applications.",
            scope="privileged",
            created_by="lea.ciso@demo.local",
        ))
        print("AccessGov demo seeded successfully.")
        print(f"Identities: {db.query(Identity).count()}")
        print(f"Applications: {db.query(Application).count()}")
        print(f"Access grants: {db.query(AccessGrant).count()}")
        print(f"Review items: {db.query(ReviewItem).count()}")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
