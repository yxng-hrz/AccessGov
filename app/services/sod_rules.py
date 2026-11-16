from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import SodRule

DEFAULT_SOD_RULES = [
    ("SOD-FIN-01", "AP_INVOICE_CREATE", "AP_PAYMENT_APPROVE", "Accounts payable creation and payment approval"),
    ("SOD-FIN-02", "VENDOR_CREATE", "VENDOR_PAYMENT_APPROVE", "Vendor creation and vendor payment approval"),
    ("SOD-IAM-01", "USER_ADMIN", "SECURITY_AUDITOR", "Identity administration and independent security audit"),
    ("SOD-DEV-01", "REPO_WRITE", "DEPLOY_PROD", "Code change and unsupervised production deployment"),
    ("SOD-HR-01", "HR_SPECIALIST", "PAYROLL_APPROVE", "HR record maintenance and payroll approval"),
]


def ensure_default_rules(db: Session) -> int:
    """Insert the default SoD catalogue if no rule exists yet."""
    if db.scalar(select(SodRule.id).limit(1)) is not None:
        return 0
    for code, left, right, description in DEFAULT_SOD_RULES:
        db.add(SodRule(code=code, left_entitlement=left, right_entitlement=right, description=description))
    db.commit()
    return len(DEFAULT_SOD_RULES)


def active_rules(db: Session) -> list[tuple[str, str, str, str, str]]:
    """Return (code, left, right, description, severity). Falls back to defaults when the table is empty."""
    rules = db.scalars(select(SodRule)).all()
    if not rules:
        return [(code, left, right, desc, "CRITICAL") for code, left, right, desc in DEFAULT_SOD_RULES]
    return [
        (r.code, r.left_entitlement.upper(), r.right_entitlement.upper(), r.description, r.severity)
        for r in rules if r.enabled
    ]
