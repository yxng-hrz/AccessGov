const api = async (path) => {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${response.status} ${path}`);
  return response.json();
};

const metricLabels = [
  ["identities", "Identities"],
  ["privileged_grants", "Privileged access"],
  ["terminated_but_enabled", "Active leavers"],
  ["dormant_accounts", "Dormant accounts"],
  ["sod_conflicts", "SoD conflicts"],
  ["pending_reviews", "Pending reviews"],
];

const escapeHtml = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

async function load() {
  try {
    const [summary, anomalies, campaigns, audit] = await Promise.all([
      api("/api/v1/dashboard/summary"),
      api("/api/v1/anomalies"),
      api("/api/v1/campaigns"),
      api("/api/v1/audit?limit=8"),
    ]);

    document.getElementById("governance-score").textContent = summary.governance_score;
    document.getElementById("score-message").textContent = summary.high_risk_anomalies
      ? `${summary.high_risk_anomalies} high/critical IAM risk signals require attention.`
      : "No high-risk IAM anomaly detected in the current dataset.";

    document.getElementById("metrics").innerHTML = metricLabels.map(([key, label]) => `
      <div class="metric"><span>${label}</span><strong>${summary[key]}</strong></div>
    `).join("");

    document.getElementById("anomaly-count").textContent = `${anomalies.length} signals`;
    document.getElementById("anomalies").innerHTML = anomalies.slice(0, 12).map(item => `
      <tr>
        <td><span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span></td>
        <td>${escapeHtml(item.identity)}</td>
        <td><strong>${escapeHtml(item.code)}</strong><br><span>${escapeHtml(item.description)}</span></td>
        <td>${escapeHtml(item.application || "—")}</td>
      </tr>
    `).join("");

    const campaign = campaigns[0];
    if (campaign) {
      document.getElementById("campaign-status").textContent = campaign.status;
      document.getElementById("campaign").innerHTML = `<strong>${escapeHtml(campaign.name)}</strong><br>${escapeHtml(campaign.description)}<br>Scope: ${escapeHtml(campaign.scope)}`;
      const items = await api(`/api/v1/campaigns/${campaign.id}/items`);
      document.getElementById("review-items").innerHTML = items.slice(0, 10).map(item => `
        <div class="review-item">
          <div><strong>Grant #${item.grant_id}</strong><span>Reviewer: ${escapeHtml(item.reviewer_email || "unassigned")}</span></div>
          <span class="decision">${escapeHtml(item.decision)}</span>
        </div>
      `).join("");
    } else {
      document.getElementById("campaign-status").textContent = "none";
      document.getElementById("campaign").textContent = "No review campaign. Seed demo data or create one through the API.";
    }

    document.getElementById("audit-events").innerHTML = audit.map(item => `
      <tr><td>${escapeHtml(item.event_type)}</td><td>${escapeHtml(item.actor)}</td><td>${escapeHtml(item.entity_type)} #${escapeHtml(item.entity_id)}</td><td>${escapeHtml(item.details || "—")}</td></tr>
    `).join("");
  } catch (error) {
    document.getElementById("score-message").textContent = `Unable to load dashboard: ${error.message}`;
  }
}

document.getElementById("refresh").addEventListener("click", load);
load();
