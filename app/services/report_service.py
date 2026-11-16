"""Executive (COMEX / board) reporting."""
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ReviewCampaign, RiskException
from app.services.anomaly_engine import as_aware, detect_anomalies
from app.services.audit import verify_chain
from app.services.campaign_service import campaign_metrics
from app.services.compliance import coverage
from app.services.dashboard_service import dashboard_summary, posture_trend
from app.services.lifecycle import expiring_soon

CODE_LABELS = {
    "LEAVER_ACTIVE": "Former employees with active accounts",
    "PRIVILEGED_NON_ACTIVE": "Admin rights held by former employees",
    "SOD_CONFLICT": "Separation-of-duties conflicts (fraud risk)",
    "SERVICE_NO_OWNER": "Service accounts without an owner",
    "DORMANT_ACCOUNT": "Dormant accounts",
    "PRIVILEGED_NO_JUSTIFICATION": "Admin rights without justification",
    "CRITICAL_APP_NO_MANAGER": "Critical-app access with no approver",
    "MISSING_MANAGER": "Users without a manager",
    "EXCESSIVE_ACCESS": "Users with excessive entitlements",
    "EXPIRED_ACCESS": "Expired access still active",
    "PRIVILEGED_NO_EXPIRY": "Standing (non time-bound) admin rights",
    "MOVER_RESIDUAL_ACCESS": "Residual access after an internal move",
    "EXCEPTION_EXPIRED": "Expired risk exceptions",
}


def _rating(score: int) -> str:
    if score >= 85:
        return "Controlled"
    if score >= 65:
        return "Needs attention"
    if score >= 40:
        return "Significant exposure"
    return "Critical exposure"


def executive_report(db: Session) -> str:
    now = datetime.now(timezone.utc)
    summary = dashboard_summary(db)
    anomalies = detect_anomalies(db)
    trend = posture_trend(db, limit=6)
    chain = verify_chain(db)
    counts = Counter(a["code"] for a in anomalies)
    critical_codes = Counter(a["code"] for a in anomalies if a["severity"] == "CRITICAL")

    lines = [
        "# IAM Governance — Executive Report",
        "",
        f"_Generated {now.strftime('%Y-%m-%d %H:%M UTC')} by AccessGov. Synthetic demo data._",
        "",
        "## 1. Headline",
        "",
        f"- **IAM Governance Score:** {summary['governance_score']}/100 — **{_rating(summary['governance_score'])}**",
        f"- **Critical signals:** {summary['critical_anomalies']} | **High:** {summary['high_risk_anomalies'] - summary['critical_anomalies']} | **Medium:** {summary['medium_anomalies']}",
        f"- **Privileged access:** {summary['privileged_grants']} active grants, of which {summary['standing_privileged_grants']} are standing (no end date)",
        f"- **Access reviews:** {summary['review_completion_rate']}% completed ({summary['pending_reviews']} decisions pending)",
        f"- **Audit evidence integrity:** {'verified' if chain['valid'] else 'BROKEN — investigate'} ({chain['events_checked']} chained events)",
        "",
    ]

    if len(trend) >= 2:
        delta = trend[-1].governance_score - trend[0].governance_score
        direction = "improved" if delta > 0 else "deteriorated" if delta < 0 else "remained stable"
        lines += [
            "## 2. Trend",
            "",
            f"The score has {direction} by {abs(delta)} points over the last {len(trend)} snapshots.",
            "",
            "| Snapshot | Score | Critical | High | Review completion |",
            "|---|---:|---:|---:|---:|",
        ]
        for snap in trend:
            label = snap.label or as_aware(snap.created_at).strftime("%Y-%m-%d")
            lines.append(f"| {label} | {snap.governance_score} | {snap.critical} | {snap.high} | {snap.review_completion}% |")
        lines.append("")

    lines += ["## 3. Top risks in business terms", ""]
    if counts:
        lines += ["| Risk | Open signals | Critical |", "|---|---:|---:|"]
        for code, count in counts.most_common(8):
            lines.append(f"| {CODE_LABELS.get(code, code)} | {count} | {critical_codes.get(code, 0)} |")
    else:
        lines.append("No open IAM risk signal.")
    lines.append("")

    at_risk = [row for row in coverage(anomalies) if row["status"] != "no_open_signal"]
    lines += ["## 4. Regulatory exposure (ISO 27001 / NIS2 / DORA)", ""]
    if at_risk:
        lines += ["| Control | Status | Open signals |", "|---|---|---:|"]
        for row in at_risk[:8]:
            lines.append(f"| {row['framework']} {row['reference']} — {row['title']} | {row['status'].replace('_', ' ')} | {row['open_signals']} |")
    else:
        lines.append("No framework control currently affected by an open signal.")
    lines.append("")

    campaigns = db.scalars(select(ReviewCampaign).where(ReviewCampaign.status == "open")).all()
    lines += ["## 5. Access certification campaigns", ""]
    if campaigns:
        for campaign in campaigns:
            m = campaign_metrics(db, campaign.id)
            flag = " — **OVERDUE**" if m["is_overdue"] else ""
            lines.append(f"- **{m['name']}**: {m['completion_rate']}% complete, {m['pending_items']} pending, revocation rate {m['revocation_rate']}%{flag}")
    else:
        lines.append("- No open campaign.")
    lines.append("")

    exceptions = db.scalars(select(RiskException).where(RiskException.status == "active")).all()
    soon = now + timedelta(days=30)
    expiring = [e for e in exceptions if now <= as_aware(e.expires_at) <= soon]
    expired = [e for e in exceptions if as_aware(e.expires_at) < now]
    grants_soon = expiring_soon(db, settings.expiry_warning_days)
    lines += [
        "## 6. Accepted risks",
        "",
        f"- Active exceptions: {len(exceptions) - len(expired)} | expiring within 30 days: {len(expiring)} | **expired: {len(expired)}**",
        f"- Time-bound grants expiring within {settings.expiry_warning_days} days: {len(grants_soon)}",
        "",
        "## 7. Decisions requested from the executive committee",
        "",
    ]
    asks = []
    if summary["terminated_but_enabled"]:
        asks.append("Mandate HR-to-IT offboarding within 24h and sponsor HR-feed automation (leaver risk).")
    if summary["sod_conflicts"]:
        asks.append("Business owners to resolve or formally accept each SoD conflict with a compensating control.")
    if summary["standing_privileged_grants"]:
        asks.append("Approve a just-in-time privileged access programme to remove standing admin rights.")
    if expired:
        asks.append("Risk owners to renew or close expired exceptions — accepted risk must stay time-bound.")
    if summary["pending_reviews"]:
        asks.append("Managers to complete pending access reviews before the campaign due date.")
    if not asks:
        asks.append("No decision required this period; maintain the review cadence.")
    lines += [f"{i}. {ask}" for i, ask in enumerate(asks, start=1)]
    lines += ["", "---", "_Scores are explainable portfolio metrics, not an industry standard._", ""]
    return "\n".join(lines)
