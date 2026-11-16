from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Inventory ---------------------------------------------------------------------------

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
    previous_department: str = ""
    moved_at: datetime | None = None
    terminated_at: datetime | None = None


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
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def privileged_needs_justification(self):
        # Prevent at the door what the anomaly engine would otherwise detect later.
        if self.privileged and not self.justification.strip():
            raise ValueError("Privileged access requires a business justification")
        return self


class GrantOut(ORMModel):
    id: int
    identity_id: int
    application_id: int
    entitlement: str
    access_level: str
    privileged: bool
    granted_by: str
    justification: str
    active: bool
    granted_at: datetime
    expires_at: datetime | None = None
    last_certified_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str = ""


# --- Joiner / Mover / Leaver -------------------------------------------------------------

class OffboardRequest(BaseModel):
    actor: str = "hr-feed"
    reason: str = "Employment terminated"


class MoveRequest(BaseModel):
    department: str
    job_title: str = ""
    manager_email: str = ""
    actor: str = "hr-feed"


class OffboardResult(BaseModel):
    identity_id: int
    account_enabled: bool
    grants_revoked: int


# --- Access reviews ----------------------------------------------------------------------

class CampaignCreate(BaseModel):
    name: str
    description: str = ""
    scope: Literal["all", "privileged", "high_risk", "critical_apps"] = "all"
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

    @model_validator(mode="after")
    def revoke_needs_reason(self):
        if self.decision == "revoke" and not self.reason.strip():
            raise ValueError("A revocation must be justified for audit evidence")
        return self


class BulkDecision(BaseModel):
    item_ids: list[int] = Field(min_length=1, max_length=200)
    decision: Literal["approve", "revoke"]
    reviewer_email: str
    reason: str = Field(min_length=3)


class DelegateRequest(BaseModel):
    delegate_to: str
    actor: str
    reason: str = ""


class ReviewItemOut(ORMModel):
    id: int
    campaign_id: int
    grant_id: int
    identity_id: int
    reviewer_email: str
    delegated_from: str = ""
    decision: str
    decision_reason: str
    decided_at: datetime | None
    risk_flags: str


# --- Risk signals & governance -----------------------------------------------------------

class AnomalyOut(BaseModel):
    code: str
    severity: Severity
    identity_id: int
    identity: str
    application: str | None = None
    grant_id: int | None = None
    description: str
    recommendation: str
    controls: list[str] = []
    excepted: bool = False
    exception_id: int | None = None


class SodRuleCreate(BaseModel):
    code: str = Field(min_length=3, max_length=40)
    left_entitlement: str
    right_entitlement: str
    description: str = ""
    severity: Severity = "CRITICAL"


class SodRuleOut(SodRuleCreate, ORMModel):
    id: int
    enabled: bool
    created_at: datetime


class RiskExceptionCreate(BaseModel):
    anomaly_code: str
    identity_id: int
    grant_id: int | None = None
    justification: str = Field(min_length=10)
    compensating_control: str = Field(min_length=5)
    risk_owner: str
    approved_by: str
    expires_at: datetime


class RiskExceptionOut(RiskExceptionCreate, ORMModel):
    id: int
    status: str
    created_at: datetime


class DashboardOut(BaseModel):
    identities: int
    enabled_accounts: int
    privileged_grants: int
    standing_privileged_grants: int
    orphan_identities: int
    dormant_accounts: int
    terminated_but_enabled: int
    service_accounts_without_owner: int
    sod_conflicts: int
    expired_access: int
    mover_residual_access: int
    active_exceptions: int
    pending_reviews: int
    approved_reviews: int
    revoked_reviews: int
    review_completion_rate: float
    governance_score: int
    critical_anomalies: int
    high_risk_anomalies: int
    medium_anomalies: int


class SnapshotOut(ORMModel):
    id: int
    label: str
    governance_score: int
    critical: int
    high: int
    medium: int
    privileged_grants: int
    review_completion: float
    created_at: datetime


class IdentityRisk(BaseModel):
    identity_id: int
    identity: str
    display_name: str
    department: str
    risk_score: int
    signals: int
    top_severity: str
    codes: list[str]


class IdentityProfile(BaseModel):
    identity: IdentityOut
    risk_score: int
    grants: list[GrantOut]
    anomalies: list[AnomalyOut]


class AuditEventOut(ORMModel):
    id: int
    event_type: str
    actor: str
    entity_type: str
    entity_id: str
    details: str
    created_at: datetime
    hash: str = ""


class ChainVerification(BaseModel):
    valid: bool
    events_checked: int
    first_broken_event_id: int | None
    head_hash: str
