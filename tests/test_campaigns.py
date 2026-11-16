from sqlalchemy import select

from app.models import ReviewItem
from app.schemas import CampaignCreate, ReviewDecision
from app.services.campaign_service import create_campaign, decide_review_item


def test_privileged_campaign_creates_only_privileged_items(db, sample_data):
    campaign = create_campaign(db, CampaignCreate(name="Privileged Review", scope="privileged"))
    items = db.scalars(select(ReviewItem).where(ReviewItem.campaign_id == campaign.id)).all()
    assert len(items) == 3
    assert all(item.decision == "pending" for item in items)


def test_revoke_decision_deactivates_grant(db, sample_data):
    campaign = create_campaign(db, CampaignCreate(name="All Review", scope="all"))
    item = db.scalar(select(ReviewItem).where(ReviewItem.campaign_id == campaign.id))
    result = decide_review_item(db, item.id, ReviewDecision(decision="revoke", reviewer_email="manager@demo.local", reason="No longer required"))
    db.refresh(result.grant)
    assert result.decision == "revoke"
    assert result.grant.active is False
