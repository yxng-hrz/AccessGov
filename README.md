# AccessGov

**IAM access review and identity governance platform built for a CISO / security governance portfolio.**

AccessGov turns identity and entitlement data into actionable access-governance decisions. It detects risky access patterns, launches certification campaigns, records manager decisions and preserves an audit trail.

Instead of asking only:

> Who has access to which application?

AccessGov asks:

> Does this person still need the access, is the access risky, who should approve it, and can we prove the decision later?

## What it demonstrates

- Identity Governance & Administration (IGA) concepts
- IAM access reviews / recertification campaigns
- Joiner-Mover-Leaver risk detection
- Privileged access governance
- Separation of Duties (SoD)
- Dormant and orphan account detection
- Service account ownership
- Least-privilege thinking
- Audit evidence and decision traceability
- FastAPI / SQLAlchemy / REST APIs
- SQLite locally and PostgreSQL with Docker
- Automated tests and GitHub Actions
- CISO-oriented governance metrics

## Demo dashboard

After seeding demo data, open:

- Dashboard: `http://127.0.0.1:8000`
- Swagger/OpenAPI: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`

The bundled dataset is entirely synthetic and intentionally contains IAM weaknesses so the dashboard is meaningful immediately after startup.

## Architecture

```text
CSV / API
   |
   v
FastAPI
   |
   +---- Identities
   +---- Applications
   +---- Access grants
   +---- IAM anomalies
   +---- Review campaigns
   +---- Review decisions
   +---- Audit trail
   |
   v
Access Governance Engine
   |
   +---- Joiner / Mover / Leaver signals
   +---- Dormant accounts
   +---- Missing manager / owner
   +---- Privileged access
   +---- Separation of Duties
   +---- Excessive permissions
   |
   v
SQLite (local) / PostgreSQL (Docker)
```

## IAM controls implemented

AccessGov currently detects the following signals:

| Signal | Default severity | Example |
|---|---|---|
| `LEAVER_ACTIVE` | Critical | Terminated employee account is still enabled |
| `PRIVILEGED_NON_ACTIVE` | Critical | Terminated identity retains privileged access |
| `SOD_CONFLICT` | Critical | Conflicting business permissions are held by one identity |
| `SERVICE_NO_OWNER` | High | Service account has no accountable owner |
| `DORMANT_ACCOUNT` | High | Enabled account has not logged in for 90+ days |
| `PRIVILEGED_NO_JUSTIFICATION` | High | Privileged grant has no business justification |
| `CRITICAL_APP_NO_MANAGER` | High | Access to a critical application cannot be routed to a manager |
| `MISSING_MANAGER` | Medium | Human identity has no manager |
| `EXCESSIVE_ACCESS` | Medium | Identity holds more than the configured entitlement threshold |

The thresholds can be changed through environment variables.

## Access review workflow

```text
Identity + Entitlement inventory
            |
            v
       Risk detection
            |
            v
    Review campaign scope
   all / privileged / high-risk
            |
            v
      Reviewer assignment
            |
            v
       APPROVE / REVOKE
            |
            +---- APPROVE -> grant stays active
            |
            +---- REVOKE  -> grant is disabled
            |
            v
        Audit evidence
```

Campaigns automatically assign the identity manager as reviewer when available. Service-account ownership can be used as fallback, then the campaign owner.

## Governance score

The dashboard exposes a simple educational IAM Governance Score from `0` to `100`.

It is based on unique identity-risk signals and applies larger penalties to critical and high-severity issues.

**Important:** this score is intentionally explainable and designed for a portfolio project. It is not an industry standard and should not be treated as a production compliance metric.

## Quick start

### Requirements

- Python 3.11+
- `pip`

### Linux / macOS

```bash
git clone https://github.com/YOUR_USERNAME/accessgov.git
cd accessgov

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

python scripts/seed_demo.py
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

### Windows PowerShell

```powershell
git clone https://github.com/YOUR_USERNAME/accessgov.git
cd accessgov

py -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt

python scripts/seed_demo.py
uvicorn app.main:app --reload
```

## Run tests

```bash
python -m pytest -q
```

Expected result:

```text
8 passed
```

## Docker

Start the API and PostgreSQL:

```bash
docker compose up --build
```

Seed the demonstration dataset:

```bash
docker compose exec api python scripts/seed_demo.py
```

Open:

```text
http://127.0.0.1:8000
```

Stop the stack:

```bash
docker compose down
```

Delete the PostgreSQL volume too:

```bash
docker compose down -v
```

## Demo dataset

The seed creates:

- 12 identities
- 10 applications
- 32 access grants
- 15 privileged-review items
- deliberate Joiner-Mover-Leaver, SoD, dormant-account and ownership anomalies

Files are stored under `data/`:

```text
data/
├── applications.csv
├── identities.csv
└── grants.csv
```

## API examples

### List the IAM posture summary

```bash
curl http://127.0.0.1:8000/api/v1/dashboard/summary
```

### List critical anomalies

```bash
curl "http://127.0.0.1:8000/api/v1/anomalies?severity=CRITICAL"
```

### List privileged access

```bash
curl "http://127.0.0.1:8000/api/v1/grants?privileged_only=true"
```

### Create an identity

```bash
curl -X POST http://127.0.0.1:8000/api/v1/identities \
  -H "Content-Type: application/json" \
  -d '{
    "employee_id": "E100",
    "email": "new.user@example.com",
    "display_name": "New User",
    "department": "Engineering",
    "job_title": "Platform Engineer",
    "manager_email": "manager@example.com",
    "employment_status": "active",
    "identity_type": "human",
    "account_enabled": true,
    "last_login_at": "2026-08-17T09:00:00Z"
  }'
```

### Create an application

```bash
curl -X POST http://127.0.0.1:8000/api/v1/applications \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Cloud",
    "owner_email": "cloud-owner@example.com",
    "criticality": 5,
    "contains_sensitive_data": true,
    "description": "Production cloud administration"
  }'
```

### Create an access grant

```bash
curl -X POST http://127.0.0.1:8000/api/v1/grants \
  -H "Content-Type: application/json" \
  -d '{
    "identity_id": 1,
    "application_id": 1,
    "entitlement": "PROD_READ",
    "access_level": "read",
    "privileged": false,
    "granted_by": "manager@example.com",
    "justification": "Production support duties",
    "active": true
  }'
```

### Launch a privileged access review

```bash
curl -X POST http://127.0.0.1:8000/api/v1/campaigns \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q4 Privileged Review",
    "description": "Quarterly privileged access recertification",
    "scope": "privileged",
    "created_by": "security@example.com"
  }'
```

Available scopes:

- `all`
- `privileged`
- `high_risk`

### List review items

```bash
curl http://127.0.0.1:8000/api/v1/campaigns/1/items
```

### Approve an access review item

```bash
curl -X POST http://127.0.0.1:8000/api/v1/campaigns/items/1/decision \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approve",
    "reviewer_email": "manager@example.com",
    "reason": "Access remains required for current role"
  }'
```

### Revoke an access review item

A revoke decision automatically marks the associated access grant inactive.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/campaigns/items/2/decision \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "revoke",
    "reviewer_email": "manager@example.com",
    "reason": "Permission is no longer required"
  }'
```

### Read the audit trail

```bash
curl http://127.0.0.1:8000/api/v1/audit
```

## CSV imports

Example CSVs are included in `data/`.

Applications:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/imports/applications \
  -F "file=@data/applications.csv"
```

Identities:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/imports/identities \
  -F "file=@data/identities.csv"
```

Access grants:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/imports/grants \
  -F "file=@data/grants.csv"
```

## Project structure

```text
accessgov/
├── .github/workflows/ci.yml
├── app/
│   ├── routers/
│   │   ├── anomalies.py
│   │   ├── applications.py
│   │   ├── audit.py
│   │   ├── campaigns.py
│   │   ├── dashboard.py
│   │   ├── grants.py
│   │   ├── identities.py
│   │   └── imports.py
│   ├── services/
│   │   ├── anomaly_engine.py
│   │   ├── audit.py
│   │   ├── campaign_service.py
│   │   └── dashboard_service.py
│   ├── static/
│   │   ├── app.js
│   │   ├── index.html
│   │   └── style.css
│   ├── config.py
│   ├── database.py
│   ├── main.py
│   ├── models.py
│   └── schemas.py
├── data/
├── scripts/seed_demo.py
├── tests/
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── requirements.txt
```

## Security and production limitations

AccessGov is an educational portfolio implementation. Before any production use, the project would require at minimum:

- authentication and authorization
- SSO / OIDC
- role-based permissions for reviewers and administrators
- database migrations
- secrets management
- CSRF/security controls appropriate to the chosen frontend architecture
- stronger validation and rate limiting
- encrypted transport and hardened deployment
- immutable or externally protected audit evidence
- tenant isolation if used as SaaS
- integration testing against real IAM providers

Do not import real employee or company access data into a public demonstration instance.

## Roadmap

Potential extensions:

- SCIM 2.0 ingestion
- Microsoft Entra ID / Okta connectors
- HR source integration for Joiner-Mover-Leaver workflows
- role mining and RBAC recommendations
- entitlement catalog and business owners
- time-bound privileged access
- access request workflow
- reviewer delegation and reminders
- campaign completion metrics
- PDF/CSV audit evidence export
- application owner certification
- policy-as-code for SoD rules
- risk acceptance with expiration dates
- multi-tenant architecture

## Portfolio talking point

A useful way to explain the project in an interview:

> I wanted to model IAM as a governance process rather than only an account-provisioning problem. AccessGov correlates identities, applications and entitlements, identifies access risks, routes permissions into review campaigns and preserves evidence of approval or revocation. The goal is to show how technical access data becomes an auditable security decision.

## License

MIT — see `LICENSE`.
