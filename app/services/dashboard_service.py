from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AccessGrant, Identity, ReviewItem
from app.services.anomaly_engine import detect_anomalies


def dashboard_summary(db: Session) -> dict:
    anomalies = detect_anomalies(db)
    by_code = {}
    for anomaly in anomalies:
        by_code[anomaly["code"]] = by_code.get(anomaly["code"], 0) + 1

    identities = db.scalar(select(func.count()).select_from(Identity)) or 0
    enabled_accounts = db.scalar(select(func.count()).select_from(Identity).where(Identity.account_enabled.is_(True))) or 0
    privileged_grants = db.scalar(
        select(func.count()).select_from(AccessGrant).where(
            AccessGrant.active.is_(True), AccessGrant.privileged.is_(True)
        )
    ) or 0

    pending_reviews = db.scalar(select(func.count()).select_from(ReviewItem).where(ReviewItem.decision == "pending")) or 0
    approved_reviews = db.scalar(select(func.count()).select_from(ReviewItem).where(ReviewItem.decision == "approve")) or 0
    revoked_reviews = db.scalar(select(func.count()).select_from(ReviewItem).where(ReviewItem.decision == "revoke")) or 0

    unique_risks = {(item["identity_id"], item["code"], item["severity"]) for item in anomalies}
    critical = sum(1 for _, _, severity in unique_risks if severity == "CRITICAL")
    high = sum(1 for _, _, severity in unique_risks if severity == "HIGH")
    medium = sum(1 for _, _, severity in unique_risks if severity == "MEDIUM")
    penalty = critical * 6 + high * 3 + medium
    governance_score = max(0, min(100, 100 - penalty))

    return {
        "identities": identities,
        "enabled_accounts": enabled_accounts,
        "privileged_grants": privileged_grants,
        "orphan_identities": by_code.get("MISSING_MANAGER", 0),
        "dormant_accounts": by_code.get("DORMANT_ACCOUNT", 0),
        "terminated_but_enabled": by_code.get("LEAVER_ACTIVE", 0),
        "service_accounts_without_owner": by_code.get("SERVICE_NO_OWNER", 0),
        "sod_conflicts": by_code.get("SOD_CONFLICT", 0),
        "pending_reviews": pending_reviews,
        "approved_reviews": approved_reviews,
        "revoked_reviews": revoked_reviews,
        "governance_score": governance_score,
        "high_risk_anomalies": critical + high,
    }
