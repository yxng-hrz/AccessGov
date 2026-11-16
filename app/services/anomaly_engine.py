"""IAM risk-signal detection.

Every signal is explainable (description + recommendation), mapped to
ISO 27001 / NIS2 / DORA controls, and can be suppressed by an active,
time-bound risk exception. Expired exceptions make the signal resurface.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.models import AccessGrant, Identity, RiskException
from app.services.compliance import controls_for
from app.services.sod_rules import active_rules

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3}


def as_aware(value: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; normalise every datetime to UTC-aware."""
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _days_since(value: datetime | None, now: datetime) -> int | None:
    value = as_aware(value)
    return None if value is None else max(0, (now - value).days)


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
        "controls": controls_for(code),
        "excepted": False,
        "exception_id": None,
    }


def _raw_signals(db: Session, now: datetime) -> list[dict]:
    identities = db.scalars(select(Identity).order_by(Identity.email)).all()
    grants = db.scalars(
        select(AccessGrant)
        .options(joinedload(AccessGrant.identity), joinedload(AccessGrant.application))
        .where(AccessGrant.active.is_(True))
        .order_by(AccessGrant.id)
    ).unique().all()

    out: list[dict] = []
    held: dict[int, set[str]] = defaultdict(set)
    count = Counter()
    for grant in grants:
        held[grant.identity_id].add(grant.entitlement.upper())
        count[grant.identity_id] += 1

    sod_rules = active_rules(db)

    # --- Identity-level signals -------------------------------------------------------
    for identity in identities:
        if identity.identity_type == "human" and identity.account_enabled and not identity.manager_email:
            out.append(_anomaly("MISSING_MANAGER", "MEDIUM", identity,
                                "Enabled human identity has no manager assigned.",
                                "Assign an accountable manager before the next access review."))

        if identity.employment_status == "terminated" and identity.account_enabled:
            out.append(_anomaly("LEAVER_ACTIVE", "CRITICAL", identity,
                                "Identity is marked terminated but the account remains enabled.",
                                "Run the offboarding workflow: disable the account and revoke every grant."))

        if identity.identity_type == "service" and identity.account_enabled and not identity.owner_email:
            out.append(_anomaly("SERVICE_NO_OWNER", "HIGH", identity,
                                "Enabled service account has no accountable owner.",
                                "Assign a named owner and define a periodic recertification cadence."))

        inactive = _days_since(identity.last_login_at, now)
        if identity.account_enabled and inactive is not None and inactive >= settings.dormant_days:
            out.append(_anomaly("DORMANT_ACCOUNT", "HIGH", identity,
                                f"Account has not logged in for {inactive} days.",
                                "Confirm business need; disable or recertify the account."))

        if count[identity.id] > settings.excessive_entitlement_threshold:
            out.append(_anomaly("EXCESSIVE_ACCESS", "MEDIUM", identity,
                                f"Identity holds {count[identity.id]} active entitlements.",
                                "Review accumulated permissions against the current role."))

        for code, left, right, label, severity in sod_rules:
            if left in held[identity.id] and right in held[identity.id]:
                out.append(_anomaly("SOD_CONFLICT", severity, identity,
                                    f"[{code}] Separation-of-duties conflict: {label} ({left} + {right}).",
                                    "Remove one entitlement or accept the risk with a compensating control."))

    # --- Grant-level signals ----------------------------------------------------------
    for grant in grants:
        identity = grant.identity
        if grant.privileged:
            if not grant.justification.strip():
                out.append(_anomaly("PRIVILEGED_NO_JUSTIFICATION", "HIGH", identity,
                                    f"Privileged entitlement {grant.entitlement} has no business justification.",
                                    "Require a documented justification and owner approval.", grant))
            if identity.employment_status == "terminated":
                out.append(_anomaly("PRIVILEGED_NON_ACTIVE", "CRITICAL", identity,
                                    f"Privileged entitlement {grant.entitlement} belongs to a non-active worker.",
                                    "Revoke immediately and investigate the offboarding process.", grant))
            elif grant.expires_at is None and identity.employment_status == "active":
                out.append(_anomaly("PRIVILEGED_NO_EXPIRY", "MEDIUM", identity,
                                    f"Standing privileged entitlement {grant.entitlement} has no end date.",
                                    "Convert to time-bound / just-in-time access.", grant))

        expires = as_aware(grant.expires_at)
        if expires is not None and expires < now:
            out.append(_anomaly("EXPIRED_ACCESS", "HIGH", identity,
                                f"{grant.entitlement} expired on {expires.date().isoformat()} but is still active.",
                                "Run the expiry sweep or renew the access with a new approval.", grant))

        moved = as_aware(identity.moved_at)
        certified = as_aware(grant.last_certified_at)
        granted = as_aware(grant.granted_at)
        if moved and granted and granted < moved and (certified is None or certified < moved):
            overdue = (now - moved).days > settings.mover_recertification_days
            out.append(_anomaly("MOVER_RESIDUAL_ACCESS", "HIGH" if overdue else "MEDIUM", identity,
                                f"{grant.entitlement} pre-dates the move from {identity.previous_department or 'previous role'} "
                                f"to {identity.department} and has not been recertified"
                                + (" (recertification window exceeded)." if overdue else "."),
                                f"Recertify or revoke within {settings.mover_recertification_days} days of the move.", grant))

        if grant.application.criticality >= 4 and identity.identity_type == "human" and not identity.manager_email:
            out.append(_anomaly("CRITICAL_APP_NO_MANAGER", "HIGH", identity,
                                f"Access to critical application {grant.application.name} cannot be routed to a manager.",
                                "Assign the manager and include this grant in the next campaign.", grant))
    return out


def detect_anomalies(db: Session, include_excepted: bool = False) -> list[dict]:
    now = datetime.now(timezone.utc)
    signals = _raw_signals(db, now)

    exceptions = db.scalars(select(RiskException).where(RiskException.status == "active")).all()
    valid, expired = [], []
    for exc in exceptions:
        (valid if as_aware(exc.expires_at) >= now else expired).append(exc)

    for signal in signals:
        for exc in valid:
            if (exc.anomaly_code == signal["code"] and exc.identity_id == signal["identity_id"]
                    and (exc.grant_id is None or exc.grant_id == signal["grant_id"])):
                signal["excepted"] = True
                signal["exception_id"] = exc.id
                break

    identities = {i.id: i for i in db.scalars(select(Identity)).all()}
    for exc in expired:
        identity = identities.get(exc.identity_id)
        if identity is None:
            continue
        signal = _anomaly("EXCEPTION_EXPIRED", "HIGH", identity,
                          f"Risk exception #{exc.id} ({exc.anomaly_code}) expired on "
                          f"{as_aware(exc.expires_at).date().isoformat()}; owner: {exc.risk_owner}.",
                          "Remediate the underlying risk or renew the acceptance with the risk owner.")
        signal["exception_id"] = exc.id
        signals.append(signal)

    if not include_excepted:
        signals = [s for s in signals if not s["excepted"]]
    signals.sort(key=lambda s: (SEVERITY_ORDER[s["severity"]], s["identity"], s["code"]))
    return signals


def identity_risk_score(anomalies: list[dict]) -> int:
    """0-100 explainable score: weighted sum of distinct signals, capped."""
    distinct = {(a["code"], a["severity"], a.get("grant_id")) for a in anomalies}
    return min(100, sum(SEVERITY_WEIGHT[sev] for _, sev, _ in distinct))


def expiry_horizon(days: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)
