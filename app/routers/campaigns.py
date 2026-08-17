from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ReviewCampaign, ReviewItem
from app.schemas import CampaignCreate, CampaignOut, ReviewDecision, ReviewItemOut
from app.services.campaign_service import close_campaign_if_complete, create_campaign, decide_review_item

router = APIRouter(prefix="/campaigns", tags=["Access reviews"])


@router.get("", response_model=list[CampaignOut])
def list_campaigns(db: Session = Depends(get_db)):
    return db.scalars(select(ReviewCampaign).order_by(ReviewCampaign.created_at.desc())).all()


@router.post("", response_model=CampaignOut, status_code=201)
def new_campaign(payload: CampaignCreate, db: Session = Depends(get_db)):
    return create_campaign(db, payload)


@router.get("/{campaign_id}", response_model=CampaignOut)
def get_campaign(campaign_id: int, db: Session = Depends(get_db)):
    campaign = db.get(ReviewCampaign, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.get("/{campaign_id}/items", response_model=list[ReviewItemOut])
def list_campaign_items(campaign_id: int, decision: str | None = None, db: Session = Depends(get_db)):
    if not db.get(ReviewCampaign, campaign_id):
        raise HTTPException(status_code=404, detail="Campaign not found")
    stmt = select(ReviewItem).where(ReviewItem.campaign_id == campaign_id)
    if decision:
        stmt = stmt.where(ReviewItem.decision == decision)
    return db.scalars(stmt.order_by(ReviewItem.id)).all()


@router.post("/items/{item_id}/decision", response_model=ReviewItemOut)
def decide(item_id: int, payload: ReviewDecision, db: Session = Depends(get_db)):
    return decide_review_item(db, item_id, payload)


@router.post("/{campaign_id}/close", response_model=CampaignOut)
def close_campaign(campaign_id: int, db: Session = Depends(get_db)):
    return close_campaign_if_complete(db, campaign_id)
