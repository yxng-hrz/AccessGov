def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_identity_application_and_grant(client):
    identity = client.post("/api/v1/identities", json={
        "employee_id": "E900",
        "email": "new@demo.local",
        "display_name": "New User",
        "manager_email": "manager@demo.local",
        "last_login_at": "2026-08-17T09:00:00Z"
    })
    assert identity.status_code == 201

    application = client.post("/api/v1/applications", json={
        "name": "Cloud Console",
        "owner_email": "cloud@demo.local",
        "criticality": 5,
        "contains_sensitive_data": True
    })
    assert application.status_code == 201

    grant = client.post("/api/v1/grants", json={
        "identity_id": identity.json()["id"],
        "application_id": application.json()["id"],
        "entitlement": "PROD_READ",
        "access_level": "read",
        "justification": "Support duties"
    })
    assert grant.status_code == 201
    assert grant.json()["entitlement"] == "PROD_READ"


def test_dashboard_and_anomalies(client, db, sample_data):
    summary = client.get("/api/v1/dashboard/summary")
    assert summary.status_code == 200
    assert summary.json()["identities"] == 3
    assert summary.json()["terminated_but_enabled"] >= 1

    anomalies = client.get("/api/v1/anomalies?severity=CRITICAL")
    assert anomalies.status_code == 200
    assert len(anomalies.json()) >= 1


def test_campaign_api_review_flow(client, db, sample_data):
    campaign = client.post("/api/v1/campaigns", json={"name": "Q3 Review", "scope": "privileged"})
    assert campaign.status_code == 201
    campaign_id = campaign.json()["id"]

    items = client.get(f"/api/v1/campaigns/{campaign_id}/items")
    assert items.status_code == 200
    item_id = items.json()[0]["id"]

    decision = client.post(f"/api/v1/campaigns/items/{item_id}/decision", json={
        "decision": "approve",
        "reviewer_email": "manager@demo.local",
        "reason": "Access still required"
    })
    assert decision.status_code == 200
    assert decision.json()["decision"] == "approve"
