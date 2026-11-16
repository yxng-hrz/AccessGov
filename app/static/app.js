const keyInput = document.getElementById("api-key");
try { keyInput.value = sessionStorage.getItem("accessgov-key") || ""; } catch (_) { /* storage unavailable */ }

const api = async (path) => {
  const headers = keyInput.value ? { "X-API-Key": keyInput.value } : {};
  const response = await fetch(path, { headers });
  if (!response.ok) throw new Error(`${response.status} ${path}`);
  return response.json();
};

const escapeHtml = (value) => String(value ?? "")
  .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;").replaceAll("'", "&#039;");

const metricLabels = [
  ["identities", "Identities"],
  ["privileged_grants", "Privileged grants"],
  ["standing_privileged_grants", "Standing admin rights"],
  ["terminated_but_enabled", "Active leavers"],
  ["sod_conflicts", "SoD conflicts"],
  ["expired_access", "Expired access"],
  ["mover_residual_access", "Mover residual access"],
  ["active_exceptions", "Accepted risks"],
];

const rating = (score) => score >= 85 ? "Controlled" : score >= 65 ? "Needs attention" : score >= 40 ? "Significant exposure" : "Critical exposure";

function sparkline(trend) {
  const svg = document.getElementById("sparkline");
  if (trend.length < 2) { svg.innerHTML = ""; return; }
  const w = 320, h = 90, pad = 10;
  const xs = trend.map((_, i) => pad + i * (w - 2 * pad) / (trend.length - 1));
  const ys = trend.map(s => h - pad - (s.governance_score / 100) * (h - 2 * pad));
  const points = xs.map((x, i) => `${x},${ys[i]}`).join(" ");
  svg.innerHTML = `<polyline points="${points}" fill="none" stroke="currentColor" stroke-width="3" stroke-linejoin="round"/>` +
    xs.map((x, i) => `<circle cx="${x}" cy="${ys[i]}" r="4" fill="currentColor"><title>${escapeHtml(trend[i].label)}: ${trend[i].governance_score}</title></circle>`).join("");
  document.getElementById("trend-labels").innerHTML = trend.map(s => `<span>${escapeHtml(s.label || "")}<b>${s.governance_score}</b></span>`).join("");
}

async function load() {
  try {
    const [summary, anomalies, top, campaigns, compliance, exceptions, trend] = await Promise.all([
      api("/api/v1/dashboard/summary"),
      api("/api/v1/anomalies"),
      api("/api/v1/dashboard/top-identities?limit=6"),
      api("/api/v1/campaigns"),
      api("/api/v1/dashboard/compliance"),
      api("/api/v1/exceptions"),
      api("/api/v1/dashboard/trend"),
    ]);

    document.getElementById("governance-score").textContent = summary.governance_score;
    document.getElementById("rating").textContent = rating(summary.governance_score);
    document.getElementById("score-message").textContent =
      `${summary.critical_anomalies} critical and ${summary.high_risk_anomalies - summary.critical_anomalies} high risk signals · ` +
      `${summary.review_completion_rate}% of review decisions completed.`;
    sparkline(trend);

    document.getElementById("metrics").innerHTML = metricLabels.map(([key, label]) =>
      `<div class="metric"><span>${label}</span><strong>${summary[key]}</strong></div>`).join("");

    document.getElementById("anomaly-count").textContent = `${anomalies.length} signals`;
    document.getElementById("anomalies").innerHTML = anomalies.slice(0, 14).map(a => `
      <tr>
        <td><span class="severity ${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span></td>
        <td>${escapeHtml(a.identity)}<br><span class="muted">${escapeHtml(a.application || "")}</span></td>
        <td><strong>${escapeHtml(a.code)}</strong><br><span class="muted">${escapeHtml(a.description)}</span></td>
        <td>${a.controls.map(c => `<span class="chip">${escapeHtml(c)}</span>`).join(" ")}</td>
      </tr>`).join("");

    document.getElementById("top-identities").innerHTML = top.map(i => `
      <div class="row-card">
        <div><strong>${escapeHtml(i.display_name)}</strong><span>${escapeHtml(i.department)} · ${i.signals} signal(s) · ${escapeHtml(i.codes.join(", "))}</span></div>
        <span class="score-badge ${escapeHtml(i.top_severity)}">${i.risk_score}</span>
      </div>`).join("") || `<p class="muted">No risky identity.</p>`;

    const campaign = campaigns[0];
    if (campaign) {
      const m = await api(`/api/v1/campaigns/${campaign.id}/metrics`);
      document.getElementById("campaign-status").textContent = m.is_overdue ? "OVERDUE" : campaign.status;
      document.getElementById("campaign").innerHTML = `
        <strong>${escapeHtml(campaign.name)}</strong> · scope ${escapeHtml(campaign.scope)}<br>
        <progress max="100" value="${m.completion_rate}"></progress>
        ${m.completion_rate}% complete · ${m.pending_items} pending · revocation rate ${m.revocation_rate}% ·
        ${m.risk_flagged_items} risk-flagged items · ${m.days_remaining ?? "–"} day(s) left`;
      document.getElementById("reviewers").innerHTML = m.reviewers.map(r =>
        `<tr><td>${escapeHtml(r.reviewer)}</td><td>${r.assigned}</td><td>${r.pending}</td><td>${r.revoked}</td></tr>`).join("");
    } else {
      document.getElementById("campaign-status").textContent = "none";
      document.getElementById("campaign").textContent = "No review campaign yet. Seed demo data or create one through the API.";
    }

    document.getElementById("compliance").innerHTML = compliance.filter(c => c.status !== "no_open_signal").slice(0, 8).map(c => `
      <div class="row-card">
        <div><strong>${escapeHtml(c.framework)} ${escapeHtml(c.reference)}</strong><span>${escapeHtml(c.title)}</span></div>
        <span class="status ${escapeHtml(c.status)}">${escapeHtml(c.status.replaceAll("_", " "))} · ${c.open_signals}</span>
      </div>`).join("") || `<p class="muted">No framework control affected by an open signal.</p>`;

    const now = Date.now();
    document.getElementById("exceptions").innerHTML = exceptions.map(e => {
      const expired = new Date(e.expires_at).getTime() < now;
      return `<div class="row-card">
        <div><strong>${escapeHtml(e.anomaly_code)} · identity #${e.identity_id}</strong>
        <span>${escapeHtml(e.compensating_control)} — owner ${escapeHtml(e.risk_owner)}</span></div>
        <span class="status ${expired ? "at_risk" : "needs_attention"}">${expired ? "EXPIRED" : "until " + escapeHtml(e.expires_at.slice(0, 10))}</span>
      </div>`;
    }).join("") || `<p class="muted">No accepted risk.</p>`;

    try {
      const [audit, chain] = await Promise.all([api("/api/v1/audit?limit=8"), api("/api/v1/audit/verify")]);
      const status = document.getElementById("chain-status");
      status.textContent = chain.valid ? `✔ chain verified (${chain.events_checked})` : `✖ broken at #${chain.first_broken_event_id}`;
      status.className = `pill ${chain.valid ? "ok" : "ko"}`;
      document.getElementById("audit-events").innerHTML = audit.map(e => `
        <tr><td>${escapeHtml(e.event_type)}</td><td>${escapeHtml(e.actor)}</td><td>${escapeHtml(e.details || "—")}</td>
        <td><code>${escapeHtml(e.hash.slice(0, 10))}…</code></td></tr>`).join("");
    } catch (_) {
      document.getElementById("chain-status").textContent = "auditor role required";
    }
  } catch (error) {
    document.getElementById("score-message").textContent = `Unable to load dashboard: ${error.message}`;
  }
}

keyInput.addEventListener("change", () => {
  try { sessionStorage.setItem("accessgov-key", keyInput.value); } catch (_) { /* storage unavailable */ }
  load();
});
document.getElementById("refresh").addEventListener("click", load);
load();
