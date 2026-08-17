from collections import Counter, defaultdict
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.models import AccessGrant, Identity


SOD_CONFLICTS = [
    ("AP_INVOICE_CREATE", "AP_PAYMENT_APPROVE", "Accounts payable creation and payment approval"),
    ("VENDOR_CREATE", "VENDOR_PAYMENT_APPROVE", "Vendor creation and vendor payment approval"),
    ("USER_ADMIN", "SECURITY_AUDITOR", "Identity administration and independent security audit"),
]


def _days_since(value: datetime | None) -> int | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - value).days)


def _anomaly(code, severity, identity, description, recommendation, grant=None):
    return {
        "code": code,
        "severity": severity,
        "identity_id": identity.id,
        "identity": identity.email,
        "application": grant.application.name if grant is not None else None,
        "grant_id": grant.id if grant is not None else None,
        "description": description,
        "recommendation": recommendation,
    }


def detect_anomalies(db: Session) -> list[dict]:
    identities = db.scalars(select(Identity).order_by(Identity.email)).all()
    grants = db.scalars(
        select(AccessGrant)
        .options(joinedload(AccessGrant.identity), joinedload(AccessGrant.application))
        .where(AccessGrant.active.is_(True))
        .order_by(AccessGrant.id)
    ).unique().all()

    anomalies: list[dict] = []
    grants_by_identity: dict[int, list[AccessGrant]] = defaultdict(list)
    entitlement_sets: dict[int, set[str]] = defaultdict(set)
    entitlement_count = Counter()

    for grant in grants:
        grants_by_identity[grant.identity_id].append(grant)
        entitlement_sets[grant.identity_id].add(grant.entitlement.upper())
        entitlement_count[grant.identity_id] += 1

    for identity in identities:
        if identity.identity_type == "human" and identity.account_enabled and not identity.manager_email:
            anomalies.append(_anomaly(
                "MISSING_MANAGER", "MEDIUM", identity,
                "Enabled human identity has no manager assigned.",
                "Assign an accountable manager before the next access review.",
            ))

        if identity.employment_status == "terminated" and identity.account_enabled:
            anomalies.append(_anomaly(
                "LEAVER_ACTIVE", "CRITICAL", identity,
                "Identity is marked terminated but the account remains enabled.",
                "Disable the account immediately and revoke active access grants.",
            ))

        if identity.identity_type == "service" and identity.account_enabled and not identity.owner_email:
            anomalies.append(_anomaly(
                "SERVICE_NO_OWNER", "HIGH", identity,
                "Enabled service account has no accountable owner.",
                "Assign a named owner and define a periodic recertification cadence.",
            ))

        inactive_days = _days_since(identity.last_login_at)
        if identity.account_enabled and inactive_days is not None and inactive_days >= settings.dormant_days:
            anomalies.append(_anomaly(
                "DORMANT_ACCOUNT", "HIGH", identity,
                f"Account has not logged in for {inactive_days} days.",
                "Confirm business need; disable or recertify the account if no longer required.",
            ))

        if entitlement_count[identity.id] > settings.excessive_entitlement_threshold:
            anomalies.append(_anomaly(
                "EXCESSIVE_ACCESS", "MEDIUM", identity,
                f"Identity holds {entitlement_count[identity.id]} active entitlements.",
                "Review accumulated permissions against the user's current role.",
            ))

        held = entitlement_sets[identity.id]
        for left, right, label in SOD_CONFLICTS:
            if left in held and right in held:
                anomalies.append(_anomaly(
                    "SOD_CONFLICT", "CRITICAL", identity,
                    f"Separation-of-duties conflict: {label} ({left} + {right}).",
                    "Remove one conflicting entitlement or document an approved compensating control.",
                ))

    for grant in grants:
        if grant.privileged:
            if not grant.justification.strip():
                anomalies.append(_anomaly(
                    "PRIVILEGED_NO_JUSTIFICATION", "HIGH", grant.identity,
                    f"Privileged entitlement {grant.entitlement} has no business justification.",
                    "Require documented business justification and owner approval.",
                    grant,
                ))
            if grant.identity.employment_status == "terminated":
                anomalies.append(_anomaly(
                    "PRIVILEGED_NON_ACTIVE", "CRITICAL", grant.identity,
                    f"Privileged entitlement {grant.entitlement} belongs to a non-active worker.",
                    "Revoke privileged access immediately and investigate the offboarding process.",
                    grant,
                ))

        if grant.application.criticality >= 4 and grant.identity.identity_type == "human" and not grant.identity.manager_email:
            anomalies.append(_anomaly(
                "CRITICAL_APP_NO_MANAGER", "HIGH", grant.identity,
                f"Access to critical application {grant.application.name} cannot be routed to a manager.",
                "Assign the manager and include this grant in the next certification campaign.",
                grant,
            ))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    anomalies.sort(key=lambda item: (severity_order[item["severity"]], item["identity"], item["code"]))
    return anomalies


def risk_flags_for_grant(db: Session, grant_id: int) -> list[str]:
    return sorted({
        anomaly["code"]
        for anomaly in detect_anomalies(db)
        if anomaly.get("grant_id") == grant_id
        or (
            anomaly.get("grant_id") is None
            and any(g.id == grant_id and g.identity_id == anomaly["identity_id"] for g in db.scalars(select(AccessGrant)).all())
        )
    })
