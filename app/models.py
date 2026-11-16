from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Identity(Base):
    __tablename__ = "identities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(180), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(180))
    department: Mapped[str] = mapped_column(String(120), default="Unknown")
    job_title: Mapped[str] = mapped_column(String(160), default="")
    manager_email: Mapped[str] = mapped_column(String(180), default="")
    employment_status: Mapped[str] = mapped_column(String(40), default="active", index=True)
    identity_type: Mapped[str] = mapped_column(String(40), default="human", index=True)
    owner_email: Mapped[str] = mapped_column(String(180), default="")
    account_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Joiner-Mover-Leaver lifecycle
    previous_department: Mapped[str] = mapped_column(String(120), default="")
    moved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terminated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    grants: Mapped[list["AccessGrant"]] = relationship(back_populates="identity", cascade="all, delete-orphan")
    review_items: Mapped[list["ReviewItem"]] = relationship(back_populates="identity")


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    owner_email: Mapped[str] = mapped_column(String(180), default="")
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    contains_sensitive_data: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str] = mapped_column(Text, default="")

    grants: Mapped[list["AccessGrant"]] = relationship(back_populates="application", cascade="all, delete-orphan")


class AccessGrant(Base):
    __tablename__ = "access_grants"
    __table_args__ = (
        UniqueConstraint("identity_id", "application_id", "entitlement", name="uq_access_grant"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("applications.id"), index=True)
    entitlement: Mapped[str] = mapped_column(String(180), index=True)
    access_level: Mapped[str] = mapped_column(String(40), default="standard", index=True)
    privileged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    granted_by: Mapped[str] = mapped_column(String(180), default="")
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    justification: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    # Time-bound access and certification history
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_certified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str] = mapped_column(Text, default="")

    identity: Mapped[Identity] = relationship(back_populates="grants")
    application: Mapped[Application] = relationship(back_populates="grants")


class ReviewCampaign(Base):
    __tablename__ = "review_campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(180), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[str] = mapped_column(String(80), default="all")
    status: Mapped[str] = mapped_column(String(40), default="open", index=True)
    created_by: Mapped[str] = mapped_column(String(180), default="security@demo.local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    items: Mapped[list["ReviewItem"]] = relationship(back_populates="campaign", cascade="all, delete-orphan")


class ReviewItem(Base):
    __tablename__ = "review_items"
    __table_args__ = (
        UniqueConstraint("campaign_id", "grant_id", name="uq_campaign_grant"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("review_campaigns.id"), index=True)
    grant_id: Mapped[int] = mapped_column(ForeignKey("access_grants.id"), index=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    reviewer_email: Mapped[str] = mapped_column(String(180), default="")
    delegated_from: Mapped[str] = mapped_column(String(180), default="")
    decision: Mapped[str] = mapped_column(String(40), default="pending", index=True)
    decision_reason: Mapped[str] = mapped_column(Text, default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_flags: Mapped[str] = mapped_column(Text, default="")

    campaign: Mapped[ReviewCampaign] = relationship(back_populates="items")
    identity: Mapped[Identity] = relationship(back_populates="review_items")
    grant: Mapped[AccessGrant] = relationship()


class SodRule(Base):
    """Separation-of-duties rule managed as data (policy-as-code)."""

    __tablename__ = "sod_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    left_entitlement: Mapped[str] = mapped_column(String(180))
    right_entitlement: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="CRITICAL")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RiskException(Base):
    """Time-bound, owner-approved acceptance of an IAM risk signal."""

    __tablename__ = "risk_exceptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    anomaly_code: Mapped[str] = mapped_column(String(60), index=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    grant_id: Mapped[int | None] = mapped_column(ForeignKey("access_grants.id"), nullable=True)
    justification: Mapped[str] = mapped_column(Text)
    compensating_control: Mapped[str] = mapped_column(Text)
    risk_owner: Mapped[str] = mapped_column(String(180))
    approved_by: Mapped[str] = mapped_column(String(180))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PostureSnapshot(Base):
    """Point-in-time copy of the governance KPIs, used for trend reporting."""

    __tablename__ = "posture_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    label: Mapped[str] = mapped_column(String(80), default="")
    governance_score: Mapped[int] = mapped_column(Integer)
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    privileged_grants: Mapped[int] = mapped_column(Integer, default=0)
    review_completion: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    actor: Mapped[str] = mapped_column(String(180), default="system")
    entity_type: Mapped[str] = mapped_column(String(80), default="")
    entity_id: Mapped[str] = mapped_column(String(80), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    # Tamper-evident hash chain
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="", index=True)
