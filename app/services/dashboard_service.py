from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AccessGrant, Identity, PostureSnapshot, ReviewItem, RiskException
from app.services.anomaly_engine import as_aware, detect_anomalies, identity_risk_score
from app.services.audit import log_event


def governance_score(anomalies: list[dict]) -> int:
    """Explainable 0-100 score. Penalties are applied per distinct (identity, signal)."""
    unique = {(a["identity_id"], a["code"], a["severity"]) for a in anomalies}
    weights = {"CRITICAL": 6, "HIGH": 3, "MEDIUM": 1, "LOW": 0}
    return max(0, min(100, 100 - sum(weights[sev] for _, _, sev in unique)))


def dashboard_summary(db: Session) -> dict:
    anomalies = detect_anomalies(db)
    by_code = Counter(a["code"] for a in anomalies)
    sev = Counter(a["severity"] for a in {(a["identity_id"], a["code"], a["severity"]): a for a in anomalies}.values())

    def count(stmt) -> int:
        return db.scalar(stmt) or 0

    privileged = count(select(func.count()).select_from(AccessGrant).where(
        AccessGrant.active.is_(True), AccessGrant.privileged.is_(True)))
    standing = count(select(func.count()).select_from(AccessGrant).where(
        AccessGrant.active.is_(True), AccessGrant.privileged.is_(True), AccessGrant.expires_at.is_(None)))
    pending = count(select(func.count()).select_from(ReviewItem).where(ReviewItem.decision == "pending"))
    approved = count(select(func.count()).select_from(ReviewItem).where(ReviewItem.decision == "approve"))
    revoked = count(select(func.count()).select_from(ReviewItem).where(ReviewItem.decision == "revoke"))
    total_reviews = pending + approved + revoked
    now = datetime.now(timezone.utc)
    active_exceptions = sum(
        1 for e in db.scalars(select(RiskException).where(RiskException.status == "active")).all()
        if as_aware(e.expires_at) >= now
    )

    return {
        "identities": count(select(func.count()).select_from(Identity)),
        "enabled_accounts": count(select(func.count()).select_from(Identity).where(Identity.account_enabled.is_(True))),
        "privileged_grants": privileged,
        "standing_privileged_grants": standing,
        "orphan_identities": by_code["MISSING_MANAGER"],
        "dormant_accounts": by_code["DORMANT_ACCOUNT"],
        "terminated_but_enabled": by_code["LEAVER_ACTIVE"],
        "service_accounts_without_owner": by_code["SERVICE_NO_OWNER"],
        "sod_conflicts": by_code["SOD_CONFLICT"],
        "expired_access": by_code["EXPIRED_ACCESS"],
        "mover_residual_access": by_code["MOVER_RESIDUAL_ACCESS"],
        "active_exceptions": active_exceptions,
        "pending_reviews": pending,
        "approved_reviews": approved,
        "revoked_reviews": revoked,
        "review_completion_rate": round(100 * (approved + revoked) / total_reviews, 1) if total_reviews else 0.0,
        "governance_score": governance_score(anomalies),
        "critical_anomalies": sev["CRITICAL"],
        "high_risk_anomalies": sev["CRITICAL"] + sev["HIGH"],
        "medium_anomalies": sev["MEDIUM"],
    }


def take_snapshot(db: Session, label: str = "", actor: str = "system") -> PostureSnapshot:
    s = dashboard_summary(db)
    snapshot = PostureSnapshot(
        label=label,
        governance_score=s["governance_score"],
        critical=s["critical_anomalies"],
        high=s["high_risk_anomalies"] - s["critical_anomalies"],
        medium=s["medium_anomalies"],
        privileged_grants=s["privileged_grants"],
        review_completion=s["review_completion_rate"],
    )
    db.add(snapshot)
    db.flush()
    log_event(db, "posture_snapshot", actor=actor, entity_type="snapshot", entity_id=str(snapshot.id),
              details=f"label={label}; score={snapshot.governance_score}")
    db.commit()
    db.refresh(snapshot)
    return snapshot


def posture_trend(db: Session, limit: int = 12) -> list[PostureSnapshot]:
    rows = db.scalars(select(PostureSnapshot).order_by(PostureSnapshot.id.desc()).limit(limit)).all()
    return list(reversed(rows))


def identity_ranking(db: Session, limit: int = 10) -> list[dict]:
    anomalies = detect_anomalies(db)
    grouped: dict[int, list[dict]] = {}
    for a in anomalies:
        grouped.setdefault(a["identity_id"], []).append(a)
    identities = {i.id: i for i in db.scalars(select(Identity)).all()}
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows = []
    for identity_id, items in grouped.items():
        identity = identities[identity_id]
        rows.append({
            "identity_id": identity_id,
            "identity": identity.email,
            "display_name": identity.display_name,
            "department": identity.department,
            "risk_score": identity_risk_score(items),
            "signals": len(items),
            "top_severity": min((a["severity"] for a in items), key=order.get),
            "codes": sorted({a["code"] for a in items}),
        })
    rows.sort(key=lambda r: (-r["risk_score"], r["identity"]))
    return rows[:limit]
