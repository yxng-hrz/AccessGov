from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.config import settings
from app.models import AccessGrant, AuditEvent, Identity
from app.schemas import CampaignCreate, ReviewDecision
from app.services.anomaly_engine import detect_anomalies
from app.services.audit import log_event, verify_chain
from app.services.campaign_service import create_campaign, decide_review_item

NOW = datetime.now(timezone.utc)


def codes(db, **kwargs):
    return {a["code"] for a in detect_anomalies(db, **kwargs)}


# --- Audit evidence -------------------------------------------------------------------------

def test_audit_chain_is_valid_then_detects_tampering(db):
    for i in range(3):
        log_event(db, "test_event", actor="tester", details=f"event {i}")
    db.commit()
    assert verify_chain(db)["valid"] is True

    second = db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()[1]
    second.details = "tampered"
    db.commit()
    result = verify_chain(db)
    assert result["valid"] is False
    assert result["first_broken_event_id"] == second.id


def test_audit_verify_endpoint(client, sample_data):
    client.post("/api/v1/identities", json={"employee_id": "E77", "email": "x@demo.local", "display_name": "X"})
    body = client.get("/api/v1/audit/verify").json()
    assert body["valid"] is True
    assert body["events_checked"] >= 1


# --- Joiner / Mover / Leaver ----------------------------------------------------------------

def test_offboarding_revokes_everything_and_clears_leaver_risk(client, db, sample_data):
    leaver = sample_data["leaver"]
    assert "LEAVER_ACTIVE" in codes(db)
    response = client.post(f"/api/v1/identities/{leaver.id}/offboard", json={"actor": "hr-feed", "reason": "Resignation"})
    assert response.status_code == 200
    assert response.json()["grants_revoked"] == 1
    db.expire_all()
    assert "LEAVER_ACTIVE" not in codes(db)
    assert "PRIVILEGED_NON_ACTIVE" not in codes(db)


def test_mover_residual_access_until_recertified(client, db, sample_data):
    active = sample_data["active"]
    for grant in sample_data["grants"][:2]:
        grant.granted_at = NOW - timedelta(days=200)
    db.commit()
    client.post(f"/api/v1/identities/{active.id}/move", json={"department": "Sales", "job_title": "Account Manager"})
    db.expire_all()
    assert "MOVER_RESIDUAL_ACCESS" in codes(db)

    campaign = create_campaign(db, CampaignCreate(name="Mover review", scope="all"))
    for item in [i for i in campaign.items if i.identity_id == active.id]:
        decide_review_item(db, item.id, ReviewDecision(decision="approve", reviewer_email="manager@demo.local", reason="Still needed"))
    db.expire_all()
    assert "MOVER_RESIDUAL_ACCESS" not in codes(db)


# --- Time-bound access ----------------------------------------------------------------------

def test_expired_access_detected_and_swept(client, db, sample_data):
    grant = sample_data["grants"][0]
    grant.expires_at = NOW - timedelta(days=2)
    db.commit()
    assert "EXPIRED_ACCESS" in codes(db)

    result = client.post("/api/v1/grants/expire-sweep").json()
    assert grant.id in result["grant_ids"]
    db.expire_all()
    assert "EXPIRED_ACCESS" not in codes(db)
    assert db.get(AccessGrant, grant.id).revoked_reason.startswith("Automatic expiry")


def test_expiring_soon_endpoint(client, db, sample_data):
    grant = sample_data["grants"][1]
    grant.expires_at = NOW + timedelta(days=3)
    db.commit()
    ids = [g["id"] for g in client.get("/api/v1/grants/expiring?days=7").json()]
    assert grant.id in ids


def test_privileged_grant_requires_justification(client, sample_data):
    response = client.post("/api/v1/grants", json={
        "identity_id": sample_data["active"].id, "application_id": sample_data["application"].id,
        "entitlement": "NEW_ADMIN", "access_level": "admin", "privileged": True, "justification": "",
    })
    assert response.status_code == 422


# --- Risk exceptions ------------------------------------------------------------------------

def _exception_payload(sample_data, **overrides):
    payload = {
        "anomaly_code": "SOD_CONFLICT",
        "identity_id": sample_data["active"].id,
        "justification": "Single accountant during month-end close",
        "compensating_control": "CFO reviews every payment above 5k EUR",
        "risk_owner": "cfo@demo.local",
        "approved_by": "cfo@demo.local",
        "expires_at": (NOW + timedelta(days=60)).isoformat(),
    }
    payload.update(overrides)
    return payload


def test_valid_exception_suppresses_signal(client, db, sample_data):
    assert "SOD_CONFLICT" in codes(db)
    response = client.post("/api/v1/exceptions", json=_exception_payload(sample_data))
    assert response.status_code == 201
    assert "SOD_CONFLICT" not in codes(db)
    excepted = [a for a in detect_anomalies(db, include_excepted=True) if a["code"] == "SOD_CONFLICT"]
    assert excepted and excepted[0]["excepted"] is True


def test_expired_exception_resurfaces(client, db, sample_data):
    response = client.post("/api/v1/exceptions", json=_exception_payload(sample_data))
    from app.models import RiskException
    exc = db.get(RiskException, response.json()["id"])
    exc.expires_at = NOW - timedelta(days=1)
    db.commit()
    current = codes(db)
    assert "EXCEPTION_EXPIRED" in current
    assert "SOD_CONFLICT" in current


def test_exception_guardrails(client, sample_data):
    too_long = _exception_payload(sample_data, expires_at=(NOW + timedelta(days=settings.exception_max_days + 10)).isoformat())
    assert client.post("/api/v1/exceptions", json=too_long).status_code == 422
    leaver = _exception_payload(sample_data, anomaly_code="LEAVER_ACTIVE", identity_id=sample_data["leaver"].id)
    assert client.post("/api/v1/exceptions", json=leaver).status_code == 422
    self_approved = _exception_payload(sample_data, approved_by="active@demo.local")
    assert client.post("/api/v1/exceptions", json=self_approved).status_code == 403


# --- Review process controls -----------------------------------------------------------------

def test_self_certification_is_blocked(client, db, sample_data):
    campaign = create_campaign(db, CampaignCreate(name="Self review", scope="all"))
    item = next(i for i in campaign.items if i.identity_id == sample_data["active"].id)
    response = client.post(f"/api/v1/campaigns/items/{item.id}/decision", json={
        "decision": "approve", "reviewer_email": "active@demo.local", "reason": "mine",
    })
    assert response.status_code == 403


def test_revoke_requires_reason(client, db, sample_data):
    campaign = create_campaign(db, CampaignCreate(name="Reason review", scope="all"))
    item = campaign.items[0]
    response = client.post(f"/api/v1/campaigns/items/{item.id}/decision", json={
        "decision": "revoke", "reviewer_email": "manager@demo.local", "reason": "",
    })
    assert response.status_code == 422


def test_delegation_metrics_and_evidence(client, db, sample_data):
    campaign = create_campaign(db, CampaignCreate(name="Q4 Review", scope="privileged"))
    assert campaign.due_at is not None
    item = campaign.items[0]
    delegated = client.post(f"/api/v1/campaigns/items/{item.id}/delegate", json={
        "delegate_to": "deputy@demo.local", "actor": "manager@demo.local", "reason": "Holiday",
    }).json()
    assert delegated["reviewer_email"] == "deputy@demo.local"
    assert delegated["delegated_from"]

    client.post(f"/api/v1/campaigns/items/{item.id}/decision", json={
        "decision": "revoke", "reviewer_email": "deputy@demo.local", "reason": "Not required",
    })
    metrics = client.get(f"/api/v1/campaigns/{campaign.id}/metrics").json()
    assert metrics["decided_items"] == 1
    assert metrics["revocation_rate"] == 100.0
    assert any(r["reviewer"] == "deputy@demo.local" for r in metrics["reviewers"])

    evidence = client.get(f"/api/v1/campaigns/{campaign.id}/evidence?format=csv")
    assert evidence.status_code == 200
    assert len(evidence.headers["x-evidence-sha256"]) == 64
    assert "review_item_id" in evidence.text


# --- Policy-as-code, compliance and reporting ------------------------------------------------

def test_custom_sod_rule_is_enforced(client, db, sample_data):
    rule = client.post("/api/v1/sod-rules", json={
        "code": "SOD-OPS-99", "left_entitlement": "finance_admin", "right_entitlement": "backup_operator",
        "description": "Test rule", "severity": "HIGH",
    })
    assert rule.status_code == 201
    leaver = sample_data["leaver"]
    db.add(AccessGrant(identity_id=leaver.id, application_id=sample_data["application"].id, entitlement="BACKUP_OPERATOR"))
    db.commit()
    hits = [a for a in detect_anomalies(db) if a["code"] == "SOD_CONFLICT" and "SOD-OPS-99" in a["description"]]
    assert hits and hits[0]["severity"] == "HIGH"


def test_compliance_mapping(client, sample_data):
    rows = client.get("/api/v1/dashboard/compliance").json()
    by_id = {r["control_id"]: r for r in rows}
    assert by_id["ISO27001:A.5.3"]["status"] == "at_risk"
    assert "SOD_CONFLICT" in by_id["ISO27001:A.5.3"]["signal_codes"]
    anomaly = client.get("/api/v1/anomalies?code=SOD_CONFLICT").json()[0]
    assert "ISO27001:A.5.3" in anomaly["controls"]


def test_identity_profile_risk_score(client, sample_data):
    body = client.get(f"/api/v1/identities/{sample_data['leaver'].id}/profile").json()
    assert body["risk_score"] > 0
    assert any(a["code"] == "LEAVER_ACTIVE" for a in body["anomalies"])


def test_snapshots_trend_and_executive_report(client, sample_data):
    assert client.post("/api/v1/dashboard/snapshots?label=Q2").status_code == 201
    assert client.post("/api/v1/dashboard/snapshots?label=Q3").status_code == 201
    trend = client.get("/api/v1/dashboard/trend").json()
    assert [s["label"] for s in trend][-2:] == ["Q2", "Q3"]
    report = client.get("/api/v1/reports/executive")
    assert report.status_code == 200
    assert "IAM Governance Score" in report.text
    assert "Decisions requested" in report.text


def test_security_headers(client):
    response = client.get("/health")
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]


# --- RBAC -----------------------------------------------------------------------------------

def test_api_key_rbac(client, monkeypatch, db, sample_data):
    monkeypatch.setattr(settings, "api_keys", "adm:admin,rev:reviewer,aud:auditor")
    assert client.get("/api/v1/identities").status_code == 401
    assert client.get("/api/v1/identities", headers={"X-API-Key": "aud"}).status_code == 200
    assert client.post("/api/v1/identities", headers={"X-API-Key": "aud"}, json={
        "employee_id": "Z1", "email": "z@demo.local", "display_name": "Z"}).status_code == 403
    assert client.post("/api/v1/identities", headers={"X-API-Key": "adm"}, json={
        "employee_id": "Z1", "email": "z@demo.local", "display_name": "Z"}).status_code == 201
    campaign = client.post("/api/v1/campaigns", headers={"X-API-Key": "adm"}, json={"name": "RBAC", "scope": "privileged"}).json()
    item = client.get(f"/api/v1/campaigns/{campaign['id']}/items", headers={"X-API-Key": "rev"}).json()[0]
    decision = client.post(f"/api/v1/campaigns/items/{item['id']}/decision", headers={"X-API-Key": "rev"}, json={
        "decision": "approve", "reviewer_email": "manager@demo.local", "reason": "ok"})
    assert decision.status_code == 200
    assert client.get(f"/api/v1/campaigns/{campaign['id']}/evidence", headers={"X-API-Key": "rev"}).status_code == 403
    assert client.get("/health").json()["auth_mode"] == "api-key"


# --- HR-driven JML, bulk decisions, ranking ---------------------------------------------------

def test_hr_sync_offboards_leavers_flags_movers_and_lists_joiners(client, db, sample_data):
    csv_body = (
        "employee_id,employment_status,department,job_title,manager_email\n"
        "E2,terminated,Finance,,\n"
        "E1,active,Sales,Account Manager,sales.lead@demo.local\n"
        "E999,active,Engineering,Developer,lead@demo.local\n"
    )
    response = client.post("/api/v1/imports/hr-sync", files={"file": ("hr.csv", csv_body, "text/csv")})
    assert response.status_code == 200
    body = response.json()
    assert body["leavers_offboarded"][0]["employee_id"] == "E2"
    assert body["movers"][0]["to"] == "Sales"
    assert body["joiners_to_provision"] == ["E999"]
    db.expire_all()
    assert "LEAVER_ACTIVE" not in codes(db)


def test_bulk_decision_is_all_or_nothing(client, db, sample_data):
    campaign = create_campaign(db, CampaignCreate(name="Bulk", scope="all"))
    ids = [i.id for i in campaign.items]
    # Batch containing the reviewer's own access must be rejected entirely.
    self_item = [i.id for i in campaign.items if i.identity_id == sample_data["active"].id]
    bad = client.post("/api/v1/campaigns/items/bulk-decision", json={
        "item_ids": self_item, "decision": "approve", "reviewer_email": "active@demo.local", "reason": "batch"})
    assert bad.status_code == 403
    ok = client.post("/api/v1/campaigns/items/bulk-decision", json={
        "item_ids": ids, "decision": "approve", "reviewer_email": "manager@demo.local", "reason": "Quarterly confirmation"})
    assert ok.json()["decided"] == len(ids)
    assert client.post(f"/api/v1/campaigns/{campaign.id}/close").json()["status"] == "closed"


def test_reminders_and_top_identities(client, db, sample_data):
    campaign = create_campaign(db, CampaignCreate(name="Reminders", scope="all"))
    reminders = client.get(f"/api/v1/campaigns/{campaign.id}/reminders").json()
    assert reminders and all(r["pending_items"] > 0 for r in reminders)
    top = client.get("/api/v1/dashboard/top-identities").json()
    assert top[0]["risk_score"] >= top[-1]["risk_score"]
    assert top[0]["top_severity"] == "CRITICAL"


def test_terminated_identity_cannot_receive_new_access(client, sample_data):
    response = client.post("/api/v1/grants", json={
        "identity_id": sample_data["leaver"].id, "application_id": sample_data["application"].id,
        "entitlement": "READ_ONLY", "access_level": "read"})
    assert response.status_code == 409
