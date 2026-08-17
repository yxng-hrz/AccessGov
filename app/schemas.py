from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class IdentityCreate(BaseModel):
    employee_id: str
    email: str
    display_name: str
    department: str = "Unknown"
    job_title: str = ""
    manager_email: str = ""
    employment_status: Literal["active", "leave", "terminated"] = "active"
    identity_type: Literal["human", "service"] = "human"
    owner_email: str = ""
    account_enabled: bool = True
    last_login_at: datetime | None = None


class IdentityOut(IdentityCreate, ORMModel):
    id: int
    created_at: datetime


class ApplicationCreate(BaseModel):
    name: str
    owner_email: str = ""
    criticality: int = Field(default=3, ge=1, le=5)
    contains_sensitive_data: bool = False
    description: str = ""


class ApplicationOut(ApplicationCreate, ORMModel):
    id: int


class GrantCreate(BaseModel):
    identity_id: int
    application_id: int
    entitlement: str
    access_level: Literal["read", "standard", "elevated", "admin"] = "standard"
    privileged: bool = False
    granted_by: str = ""
    justification: str = ""
    active: bool = True


class GrantOut(GrantCreate, ORMModel):
    id: int
    granted_at: datetime


class CampaignCreate(BaseModel):
    name: str
    description: str = ""
    scope: Literal["all", "privileged", "high_risk"] = "all"
    created_by: str = "security@demo.local"
    due_at: datetime | None = None


class CampaignOut(ORMModel):
    id: int
    name: str
    description: str
    scope: str
    status: str
    created_by: str
    created_at: datetime
    due_at: datetime | None
    closed_at: datetime | None


class ReviewDecision(BaseModel):
    decision: Literal["approve", "revoke"]
    reviewer_email: str
    reason: str = ""


class ReviewItemOut(ORMModel):
    id: int
    campaign_id: int
    grant_id: int
    identity_id: int
    reviewer_email: str
    decision: str
    decision_reason: str
    decided_at: datetime | None
    risk_flags: str


class AnomalyOut(BaseModel):
    code: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    identity_id: int
    identity: str
    application: str | None = None
    grant_id: int | None = None
    description: str
    recommendation: str


class DashboardOut(BaseModel):
    identities: int
    enabled_accounts: int
    privileged_grants: int
    orphan_identities: int
    dormant_accounts: int
    terminated_but_enabled: int
    service_accounts_without_owner: int
    sod_conflicts: int
    pending_reviews: int
    approved_reviews: int
    revoked_reviews: int
    governance_score: int
    high_risk_anomalies: int


class AuditEventOut(ORMModel):
    id: int
    event_type: str
    actor: str
    entity_type: str
    entity_id: str
    details: str
    created_at: datetime
