"""Access certification campaigns: scoping, reviewer routing, decisions, delegation, metrics, evidence."""
import csv
import hashlib
import io
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.models import AccessGrant, ReviewCampaign, ReviewItem
from app.schemas import BulkDecision, CampaignCreate, DelegateRequest, ReviewDecision
from app.services.anomaly_engine import as_aware, detect_anomalies
from app.services.audit import log_event


def _scope_grants(db: Session, scope: str, anomalies: list[dict]) -> list[AccessGrant]:
    grants = db.scalars(
        select(AccessGrant).options(joinedload(AccessGrant.identity), joinedload(AccessGrant.application))
        .where(AccessGrant.active.is_(True)).order_by(AccessGrant.id)
    ).unique().all()
    if scope == "all":
        return grants
    if scope == "privileged":
        return [g for g in grants if g.privileged]
    if scope == "critical_apps":
        return [g for g in grants if g.application.criticality >= 4]
    if scope == "high_risk":
        severe = [a for a in anomalies if a["severity"] in {"HIGH", "CRITICAL"}]
        risky_grants = {a["grant_id"] for a in severe if a["grant_id"] is not None}
        risky_identities = {a["identity_id"] for a in severe}
        return [g for g in grants if g.id in risky_grants or g.identity_id in risky_identities]
    raise HTTPException(status_code=400, detail="Unknown campaign scope")


def _route_reviewer(grant: AccessGrant, fallback: str) -> str:
    """Manager first, then service-account owner, then application owner, never the identity itself."""
    own = grant.identity.email.lower()
    for candidate in (grant.identity.manager_email, grant.identity.owner_email, grant.application.owner_email, fallback):
        if candidate and candidate.lower() != own:
            return candidate
    return fallback


def create_campaign(db: Session, payload: CampaignCreate) -> ReviewCampaign:
    if db.scalar(select(ReviewCampaign).where(ReviewCampaign.name == payload.name)):
        raise HTTPException(status_code=409, detail="Campaign name already exists")

    anomalies = detect_anomalies(db)
    grants = _scope_grants(db, payload.scope, anomalies)
    if not grants:
        raise HTTPException(status_code=400, detail="Campaign scope contains no active grants")

    data = payload.model_dump()
    data["due_at"] = payload.due_at or datetime.now(timezone.utc) + timedelta(days=settings.campaign_default_duration_days)
    campaign = ReviewCampaign(**data)
    db.add(campaign)
    db.flush()

    by_grant: dict[int, set[str]] = defaultdict(set)
    by_identity: dict[int, set[str]] = defaultdict(set)
    for a in anomalies:
        by_identity[a["identity_id"]].add(a["code"])
        if a["grant_id"] is not None:
            by_grant[a["grant_id"]].add(a["code"])

    for grant in grants:
        db.add(ReviewItem(
            campaign_id=campaign.id,
            grant_id=grant.id,
            identity_id=grant.identity_id,
            reviewer_email=_route_reviewer(grant, payload.created_by),
            risk_flags=",".join(sorted(by_grant[grant.id] | by_identity[grant.identity_id])),
        ))

    log_event(db, "campaign_created", actor=payload.created_by, entity_type="campaign", entity_id=str(campaign.id),
              details=f"scope={payload.scope}; review_items={len(grants)}; due={as_aware(campaign.due_at).date().isoformat()}")
    db.commit()
    db.refresh(campaign)
    return campaign


def _apply_decision(db: Session, item: ReviewItem, decision: str, reviewer: str, reason: str) -> None:
    if item.decision != "pending":
        raise HTTPException(status_code=409, detail=f"Review item {item.id} has already been decided")
    if item.campaign.status != "open":
        raise HTTPException(status_code=409, detail="Campaign is closed")
    if reviewer.strip().lower() == item.identity.email.lower():
        raise HTTPException(status_code=403, detail="Self-certification is not allowed (segregation of duties)")

    now = datetime.now(timezone.utc)
    item.decision = decision
    item.reviewer_email = reviewer
    item.decision_reason = reason
    item.decided_at = now
    grant = item.grant
    if decision == "revoke":
        grant.active = False
        grant.revoked_at = now
        grant.revoked_reason = f"Access review: {reason}"
    else:
        grant.last_certified_at = now

    log_event(db, f"access_{decision}", actor=reviewer, entity_type="review_item", entity_id=str(item.id),
              details=f"grant_id={item.grant_id}; entitlement={grant.entitlement}; reason={reason}")


def _load_item(db: Session, item_id: int) -> ReviewItem:
    item = db.get(ReviewItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Review item not found")
    return item


def decide_review_item(db: Session, item_id: int, payload: ReviewDecision) -> ReviewItem:
    item = _load_item(db, item_id)
    _apply_decision(db, item, payload.decision, payload.reviewer_email, payload.reason)
    db.commit()
    db.refresh(item)
    return item


def bulk_decide(db: Session, payload: BulkDecision) -> dict:
    items = [_load_item(db, item_id) for item_id in payload.item_ids]
    for item in items:  # all-or-nothing: any guardrail violation aborts the batch
        _apply_decision(db, item, payload.decision, payload.reviewer_email, payload.reason)
    db.commit()
    return {"decided": len(items), "decision": payload.decision}


def delegate_review_item(db: Session, item_id: int, payload: DelegateRequest) -> ReviewItem:
    item = _load_item(db, item_id)
    if item.decision != "pending":
        raise HTTPException(status_code=409, detail="Only pending items can be delegated")
    if payload.delegate_to.strip().lower() == item.identity.email.lower():
        raise HTTPException(status_code=403, detail="Cannot delegate a review to the identity under review")
    item.delegated_from = item.reviewer_email
    item.reviewer_email = payload.delegate_to
    log_event(db, "review_delegated", actor=payload.actor, entity_type="review_item", entity_id=str(item.id),
              details=f"from={item.delegated_from}; to={payload.delegate_to}; reason={payload.reason}")
    db.commit()
    db.refresh(item)
    return item


def campaign_metrics(db: Session, campaign_id: int) -> dict:
    campaign = db.get(ReviewCampaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    items = campaign.items
    total = len(items)
    decided = [i for i in items if i.decision != "pending"]
    revoked = [i for i in decided if i.decision == "revoke"]
    flagged = [i for i in items if i.risk_flags]
    reviewers: dict[str, dict] = defaultdict(lambda: {"assigned": 0, "pending": 0, "revoked": 0})
    for item in items:
        r = reviewers[item.reviewer_email or "unassigned"]
        r["assigned"] += 1
        r["pending"] += item.decision == "pending"
        r["revoked"] += item.decision == "revoke"
    due = as_aware(campaign.due_at)
    now = datetime.now(timezone.utc)
    return {
        "campaign_id": campaign.id,
        "name": campaign.name,
        "status": campaign.status,
        "total_items": total,
        "decided_items": len(decided),
        "pending_items": total - len(decided),
        "completion_rate": round(100 * len(decided) / total, 1) if total else 0.0,
        "revocation_rate": round(100 * len(revoked) / len(decided), 1) if decided else 0.0,
        "risk_flagged_items": len(flagged),
        "due_at": due,
        "days_remaining": (due - now).days if due else None,
        "is_overdue": bool(due and due < now and campaign.status == "open" and total != len(decided)),
        "reviewers": sorted(
            [{"reviewer": k, **v} for k, v in reviewers.items()],
            key=lambda r: (-r["pending"], r["reviewer"]),
        ),
    }


def reminders(db: Session, campaign_id: int) -> list[dict]:
    """Pending workload per reviewer — the list a GRC team would e-mail."""
    metrics = campaign_metrics(db, campaign_id)
    return [
        {"reviewer": r["reviewer"], "pending_items": r["pending"], "due_at": metrics["due_at"],
         "message": f"{r['pending']} access decision(s) pending for '{metrics['name']}'"
                    + (" — campaign OVERDUE." if metrics["is_overdue"] else f" — {metrics['days_remaining']} day(s) left.")}
        for r in metrics["reviewers"] if r["pending"]
    ]


def evidence_csv(db: Session, campaign_id: int) -> tuple[str, str]:
    """Audit-ready CSV of every decision, with its SHA-256 fingerprint."""
    campaign = db.get(ReviewCampaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["campaign", "review_item_id", "identity", "application", "entitlement", "privileged",
                     "risk_flags", "reviewer", "delegated_from", "decision", "reason", "decided_at"])
    for item in sorted(campaign.items, key=lambda i: i.id):
        writer.writerow([
            campaign.name, item.id, item.identity.email, item.grant.application.name, item.grant.entitlement,
            item.grant.privileged, item.risk_flags, item.reviewer_email, item.delegated_from, item.decision,
            item.decision_reason, as_aware(item.decided_at).isoformat() if item.decided_at else "",
        ])
    content = buffer.getvalue()
    return content, hashlib.sha256(content.encode("utf-8")).hexdigest()


def close_campaign_if_complete(db: Session, campaign_id: int, actor: str = "system") -> ReviewCampaign:
    campaign = db.get(ReviewCampaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    pending = [i for i in campaign.items if i.decision == "pending"]
    if pending:
        raise HTTPException(status_code=409, detail=f"Campaign still has {len(pending)} pending reviews")
    campaign.status = "closed"
    campaign.closed_at = datetime.now(timezone.utc)
    log_event(db, "campaign_closed", actor=actor, entity_type="campaign", entity_id=str(campaign.id))
    db.commit()
    db.refresh(campaign)
    return campaign
