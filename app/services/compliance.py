"""Mapping of IAM detection rules to governance frameworks.

The references point to ISO/IEC 27001:2022 Annex A controls, the NIS2
Directive (EU 2022/2555, Art. 21 risk-management measures) and DORA
(EU 2022/2554). The mapping is indicative and meant to show how a technical
signal supports a compliance obligation; it is not legal advice.
"""

FRAMEWORK_CONTROLS: dict[str, str] = {
    "ISO27001:A.5.2": "Information security roles and responsibilities",
    "ISO27001:A.5.3": "Segregation of duties",
    "ISO27001:A.5.9": "Inventory of information and other associated assets (ownership)",
    "ISO27001:A.5.15": "Access control",
    "ISO27001:A.5.16": "Identity management",
    "ISO27001:A.5.18": "Access rights (provisioning, review, removal)",
    "ISO27001:A.6.5": "Responsibilities after termination or change of employment",
    "ISO27001:A.8.2": "Privileged access rights",
    "ISO27001:6.1.3": "Information security risk treatment (risk acceptance)",
    "NIS2:Art.21(2)(i)": "Human resources security, access control policies and asset management",
    "NIS2:Art.21(2)(f)": "Policies to assess the effectiveness of risk-management measures",
    "DORA:Art.9": "ICT protection and prevention (least-privilege access, strong authentication)",
}

ANOMALY_CONTROLS: dict[str, list[str]] = {
    "LEAVER_ACTIVE": ["ISO27001:A.5.18", "ISO27001:A.6.5", "NIS2:Art.21(2)(i)"],
    "PRIVILEGED_NON_ACTIVE": ["ISO27001:A.8.2", "ISO27001:A.6.5", "NIS2:Art.21(2)(i)", "DORA:Art.9"],
    "SOD_CONFLICT": ["ISO27001:A.5.3", "DORA:Art.9"],
    "SERVICE_NO_OWNER": ["ISO27001:A.5.9", "ISO27001:A.5.16", "NIS2:Art.21(2)(i)"],
    "DORMANT_ACCOUNT": ["ISO27001:A.5.16", "ISO27001:A.5.18"],
    "PRIVILEGED_NO_JUSTIFICATION": ["ISO27001:A.8.2", "ISO27001:A.5.15", "DORA:Art.9"],
    "CRITICAL_APP_NO_MANAGER": ["ISO27001:A.5.2", "ISO27001:A.5.18"],
    "MISSING_MANAGER": ["ISO27001:A.5.2", "ISO27001:A.5.16"],
    "EXCESSIVE_ACCESS": ["ISO27001:A.5.15", "DORA:Art.9"],
    "EXPIRED_ACCESS": ["ISO27001:A.5.18", "ISO27001:A.8.2"],
    "PRIVILEGED_NO_EXPIRY": ["ISO27001:A.8.2", "DORA:Art.9"],
    "MOVER_RESIDUAL_ACCESS": ["ISO27001:A.5.18", "ISO27001:A.6.5", "NIS2:Art.21(2)(i)"],
    "EXCEPTION_EXPIRED": ["ISO27001:6.1.3", "NIS2:Art.21(2)(f)"],
}


def controls_for(code: str) -> list[str]:
    return ANOMALY_CONTROLS.get(code, [])


def coverage(anomalies: list[dict]) -> list[dict]:
    """Return, for each framework control, the open signals that put it at risk."""
    rows = []
    for control_id, title in FRAMEWORK_CONTROLS.items():
        related = [a for a in anomalies if control_id in a.get("controls", [])]
        severities = {a["severity"] for a in related}
        if "CRITICAL" in severities:
            status = "at_risk"
        elif related:
            status = "needs_attention"
        else:
            status = "no_open_signal"
        framework, _, reference = control_id.partition(":")
        rows.append({
            "control_id": control_id,
            "framework": framework,
            "reference": reference,
            "title": title,
            "open_signals": len(related),
            "status": status,
            "signal_codes": sorted({a["code"] for a in related}),
        })
    order = {"at_risk": 0, "needs_attention": 1, "no_open_signal": 2}
    rows.sort(key=lambda r: (order[r["status"]], -r["open_signals"], r["control_id"]))
    return rows
