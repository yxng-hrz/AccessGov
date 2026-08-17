from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AccessGrant, ReviewCampaign, ReviewItem
from app.schemas import CampaignCreate, ReviewDecision
from app.services.anomaly_engine import detect_anomalies
from app.services.audit import log_event


def _scope_grant_ids(db: Session, scope: str) -> set[int]:
    active_grants = db.scalars(select(AccessGrant).where(AccessGrant.active.is_(True))).all()
    if scope == "all":
        return {grant.id for grant in active_grants}
    if scope == "privileged":
        return {grant.id for grant in active_grants if grant.privileged}
    if scope == "high_risk":
        anomaly_grants = {
            anomaly["grant_id"]
            for anomaly in detect_anomalies(db)
            if anomaly["severity"] in {"HIGH", "CRITICAL"} and anomaly.get("grant_id") is not None
        }
        risky_identities = {
            anomaly["identity_id"]
            for anomaly in detect_anomalies(db)
            if anomaly["severity"] in {"HIGH", "CRITICAL"}
        }
        return {
            grant.id for grant in active_grants
            if grant.id in anomaly_grants or grant.identity_id in risky_identities
        }
    raise HTTPException(status_code=400, detail="Unknown campaign scope")


def create_campaign(db: Session, payload: CampaignCreate) -> ReviewCampaign:
    if db.scalar(select(ReviewCampaign).where(ReviewCampaign.name == payload.name)):
        raise HTTPException(status_code=409, detail="Campaign name already exists")

    campaign = ReviewCampaign(**payload.model_dump())
    db.add(campaign)
    db.flush()

    grant_ids = _scope_grant_ids(db, payload.scope)
    if not grant_ids:
        db.rollback()
        raise HTTPException(status_code=400, detail="Campaign scope contains no active grants")

    anomalies = detect_anomalies(db)
    flags_by_grant: dict[int, set[str]] = {grant_id: set() for grant_id in grant_ids}
    flags_by_identity: dict[int, set[str]] = {}
    for anomaly in anomalies:
        flags_by_identity.setdefault(anomaly["identity_id"], set()).add(anomaly["code"])
        if anomaly.get("grant_id") in flags_by_grant:
            flags_by_grant[anomaly["grant_id"]].add(anomaly["code"])

    grants = db.scalars(select(AccessGrant).where(AccessGrant.id.in_(grant_ids))).all()
    for grant in grants:
        flags = flags_by_grant.get(grant.id, set()) | flags_by_identity.get(grant.identity_id, set())
        db.add(ReviewItem(
            campaign_id=campaign.id,
            grant_id=grant.id,
            identity_id=grant.identity_id,
            reviewer_email=grant.identity.manager_email or grant.identity.owner_email or payload.created_by,
            risk_flags=",".join(sorted(flags)),
        ))

    log_event(
        db,
        "campaign_created",
        actor=payload.created_by,
        entity_type="campaign",
        entity_id=str(campaign.id),
        details=f"scope={payload.scope}; review_items={len(grants)}",
    )
    db.commit()
    db.refresh(campaign)
    return campaign


def decide_review_item(db: Session, item_id: int, payload: ReviewDecision) -> ReviewItem:
    item = db.get(ReviewItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Review item not found")
    if item.decision != "pending":
        raise HTTPException(status_code=409, detail="Review item has already been decided")

    item.decision = payload.decision
    item.reviewer_email = payload.reviewer_email
    item.decision_reason = payload.reason
    item.decided_at = datetime.now(timezone.utc)

    if payload.decision == "revoke":
        grant = db.get(AccessGrant, item.grant_id)
        if grant:
            grant.active = False

    log_event(
        db,
        f"access_{payload.decision}",
        actor=payload.reviewer_email,
        entity_type="review_item",
        entity_id=str(item.id),
        details=f"grant_id={item.grant_id}; reason={payload.reason}",
    )
    db.commit()
    db.refresh(item)
    return item


def close_campaign_if_complete(db: Session, campaign_id: int) -> ReviewCampaign:
    campaign = db.get(ReviewCampaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    pending = db.scalars(
        select(ReviewItem).where(
            ReviewItem.campaign_id == campaign_id,
            ReviewItem.decision == "pending",
        )
    ).all()
    if pending:
        raise HTTPException(status_code=409, detail=f"Campaign still has {len(pending)} pending reviews")

    campaign.status = "closed"
    campaign.closed_at = datetime.now(timezone.utc)
    log_event(db, "campaign_closed", actor="system", entity_type="campaign", entity_id=str(campaign.id))
    db.commit()
    db.refresh(campaign)
    return campaign
