from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ReviewCampaign, ReviewItem
from app.schemas import BulkDecision, CampaignCreate, CampaignOut, DelegateRequest, ReviewDecision, ReviewItemOut
from app.security import ADMIN, ANY_ROLE, AUDITOR, REVIEWER, Principal
from app.services.campaign_service import (
    bulk_decide, campaign_metrics, close_campaign_if_complete, create_campaign, decide_review_item,
    delegate_review_item, evidence_csv, reminders,
)

router = APIRouter(prefix="/campaigns", tags=["Access reviews"], dependencies=[Depends(ANY_ROLE)])


@router.get("", response_model=list[CampaignOut])
def list_campaigns(db: Session = Depends(get_db)):
    return db.scalars(select(ReviewCampaign).order_by(ReviewCampaign.created_at.desc(), ReviewCampaign.id.desc())).all()


@router.post("", response_model=CampaignOut, status_code=201, dependencies=[Depends(ADMIN)])
def new_campaign(payload: CampaignCreate, db: Session = Depends(get_db)):
    return create_campaign(db, payload)


@router.get("/{campaign_id}", response_model=CampaignOut)
def get_campaign(campaign_id: int, db: Session = Depends(get_db)):
    campaign = db.get(ReviewCampaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.get("/{campaign_id}/items", response_model=list[ReviewItemOut])
def list_campaign_items(campaign_id: int, decision: str | None = None, reviewer: str | None = None, db: Session = Depends(get_db)):
    if not db.get(ReviewCampaign, campaign_id):
        raise HTTPException(status_code=404, detail="Campaign not found")
    stmt = select(ReviewItem).where(ReviewItem.campaign_id == campaign_id)
    if decision:
        stmt = stmt.where(ReviewItem.decision == decision)
    if reviewer:
        stmt = stmt.where(ReviewItem.reviewer_email == reviewer)
    return db.scalars(stmt.order_by(ReviewItem.id)).all()


@router.get("/{campaign_id}/metrics")
def get_metrics(campaign_id: int, db: Session = Depends(get_db)):
    """Completion, revocation rate, overdue status and per-reviewer workload."""
    return campaign_metrics(db, campaign_id)


@router.get("/{campaign_id}/reminders")
def get_reminders(campaign_id: int, db: Session = Depends(get_db)):
    return reminders(db, campaign_id)


@router.get("/{campaign_id}/evidence", dependencies=[Depends(AUDITOR)])
def get_evidence(campaign_id: int, format: str = Query(default="csv", pattern="^(csv)$"), db: Session = Depends(get_db)):
    """Audit-ready CSV of every decision. The X-Evidence-SHA256 header fingerprints the file."""
    content, digest = evidence_csv(db, campaign_id)
    return PlainTextResponse(content, media_type="text/csv; charset=utf-8", headers={
        "X-Evidence-SHA256": digest,
        "Content-Disposition": f'attachment; filename="campaign-{campaign_id}-evidence.csv"',
    })


@router.post("/items/bulk-decision", dependencies=[Depends(REVIEWER)])
def decide_bulk(payload: BulkDecision, db: Session = Depends(get_db)):
    return bulk_decide(db, payload)


@router.post("/items/{item_id}/decision", response_model=ReviewItemOut, dependencies=[Depends(REVIEWER)])
def decide(item_id: int, payload: ReviewDecision, db: Session = Depends(get_db)):
    return decide_review_item(db, item_id, payload)


@router.post("/items/{item_id}/delegate", response_model=ReviewItemOut, dependencies=[Depends(REVIEWER)])
def delegate(item_id: int, payload: DelegateRequest, db: Session = Depends(get_db)):
    return delegate_review_item(db, item_id, payload)


@router.post("/{campaign_id}/close", response_model=CampaignOut)
def close_campaign(campaign_id: int, db: Session = Depends(get_db), principal: Principal = Depends(ADMIN)):
    return close_campaign_if_complete(db, campaign_id, actor=principal.name)
