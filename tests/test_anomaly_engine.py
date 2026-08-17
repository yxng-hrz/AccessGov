from app.services.anomaly_engine import detect_anomalies


def test_detects_leaver_service_owner_and_sod(db, sample_data):
    anomalies = detect_anomalies(db)
    codes = {item["code"] for item in anomalies}
    assert "LEAVER_ACTIVE" in codes
    assert "SERVICE_NO_OWNER" in codes
    assert "SOD_CONFLICT" in codes
    assert "PRIVILEGED_NO_JUSTIFICATION" in codes


def test_critical_anomalies_are_sorted_first(db, sample_data):
    anomalies = detect_anomalies(db)
    severities = [item["severity"] for item in anomalies]
    assert severities[0] == "CRITICAL"
