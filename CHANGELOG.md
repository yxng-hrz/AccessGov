# Changelog

## 2.0.0 — Identity governance programme

### Added
- Joiner-Mover-Leaver workflows: offboarding (`/identities/{id}/offboard`), mover (`/identities/{id}/move`), HR-feed reconciliation (`/imports/hr-sync`).
- Time-bound access: `expires_at` on grants, `/grants/expiring`, `/grants/expire-sweep`, direct revocation with reason.
- New risk signals: `EXPIRED_ACCESS`, `PRIVILEGED_NO_EXPIRY`, `MOVER_RESIDUAL_ACCESS`, `EXCEPTION_EXPIRED`.
- Separation-of-duties policy-as-code (`/sod-rules`) with five default rules.
- Time-bound risk exceptions (`/exceptions`) with guardrails (max duration, no self-approval, leaver risks not acceptable).
- ISO 27001:2022 / NIS2 / DORA mapping on every signal and `/dashboard/compliance` coverage view.
- Campaigns: `critical_apps` scope, default due date, delegation, bulk decisions, metrics, reminders, CSV evidence with SHA-256 fingerprint.
- Tamper-evident audit trail (hash chain) and `/audit/verify`.
- API-key RBAC (admin / reviewer / auditor), security headers, `auth_mode` in `/health`.
- Executive report (`/reports/executive`), posture snapshots and trend, riskiest identities, identity 360° profile.
- Redesigned dashboard (trend, compliance, exceptions, chain status, light/dark).

### Changed
- Privileged grants require a justification; terminated identities cannot receive access.
- Self-certification is blocked; a revocation requires a reason.
- Demo seed rebased on the current date.

### Tests
- 8 → 31 tests.
