# Ubuntu Central Management

A working MVP for centralized Ubuntu host management:

- **FastAPI server** (PostgreSQL-backed) with a simple web UI
- **Go agent** that inventories hosts and executes jobs via REST long-poll
- Package inventory + upgrade flows, service control, user lock/unlock, SSH key deploy approvals

This is intentionally pragmatic: REST + JSON, no gRPC/protoc requirement.

---

## What you get

### Web UI
- Fleet overview + “Attention required” (offline, high disk, high load, security updates, etc.)
- **Morning Brief** card with quick drill-down actions
- **Notification Center** (unread badge, mark-read, snooze by alert kind)
- **Saved Views** for host filters (per-user, shared/team views, default startup view)
- **Create cron from current view** + run-now/runbook quick actions
- Per-host:
  - metrics (CPU/mem/disk), top processes
  - packages list + package details (homepage link opens in new tab)
  - system services (click a service → details)
  - system users (click a user → details)
  - SSH keys: add keys and request deployments with admin approval
- Admin:
  - users list + create/reset/deactivate users
  - audit log (who did what: auth, user lifecycle, MFA, package actions, etc.)

### API
- `/health` for health checks
- `/hosts/*` for host metrics, packages, users, services
- `/jobs/*` to dispatch/inspect jobs
- `/dashboard/notifications` for in-app notification feed
- `/auth/views` for saved views (user/shared)
- `/dashboard/alerts/teams/*` for Teams test + morning brief push

---
![Screenshot](docs/image.png)
## Quick start (server)

### 1) Prereqs
- Docker + Docker Compose
- If needed:
```bash
sudo apt install docker.io docker-compose-v2 ansible-core -y
sudo usermod $USER -a -G docker # log out and log in again.
```

### 2) Clone the code and configure secrets
```bash
git clone https://github.com/impsik/linux-central-management.git
cd linux-central-management

# Configure server env
cd deploy/docker
cp env.example .env
# edit .env and set at least:
#   BOOTSTRAP_PASSWORD
#   AGENT_SHARED_TOKEN
#   MFA_ENCRYPTION_KEY   (required when MFA is enabled; see below)
# optionally:
#   AGENT_TERMINAL_TOKEN (only if you enable terminal)
#   TEAMS_WEBHOOK_URL + TEAMS_ALERTS_ENABLED=true (if you want Teams alerts)
```

### 3) Start
```bash
docker compose up -d --build

# Apply DB migrations (recommended for any deployment with existing DB volume)
docker compose exec server alembic upgrade head

curl -s http://localhost:8000/health
```

Open UI:
- http://localhost:8000/

Login with the bootstrap user you set in `deploy/docker/.env`.

---

## Agent setup (for each Ubuntu host)

### 1) Build (or copy the binary)
```bash
cd ../../agent
sudo apt  install golang-go
go build -o fleet-agent ./cmd/fleet-agent
ssh-copy-id $USER@<to agent IP address/FQDN>
scp fleet-agent IP ADDRESS:/home/USERNAME/fleet-agent
```
### For quick testing
```bash
cd ../
cp hosts.example hosts
# edit hosts
SERVER_URL=http://<SERVER_IP>:8000 AGENT_TOKEN=<AGENT_SHARED_TOKEN> TERM_TOKEN=<AGENT_TERMINAL_TOKEN> TARGETS=all ./script.sh
```

### 2) Run (foreground)
```bash
export FLEET_SERVER_URL=http://<SERVER_IP>:8000
export FLEET_AGENT_ID=<unique-id>        # can be host IP or stable name
export FLEET_LABELS=env=prod,role=web    # Add env and role as you see fit
export FLEET_AGENT_TOKEN=<AGENT_SHARED_TOKEN>
export FLEET_TERMINAL_TOKEN=<AGENT_TERMINAL_TOKEN>

./fleet-agent
```

### 3) Run as a service (recommended)
Create a systemd unit (example):

```ini
# /etc/systemd/system/fleet-agent.service
[Unit]
Description=Fleet Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/fleet-agent/fleet-agent
Environment=FLEET_SERVER_URL=http://<SERVER_IP>:8000
Environment=FLEET_AGENT_ID=<unique-id>
Environment=FLEET_LABELS=env=prod,role=web
Environment=FLEET_AGENT_TOKEN=<AGENT_SHARED_TOKEN>
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fleet-agent
sudo systemctl status fleet-agent
```

---

## Security notes

See also: `docs/security-baseline.md`.

### Bootstrap UI password
The server **does not** ship with a safe default password. You must set:
- `BOOTSTRAP_PASSWORD` in `deploy/docker/.env`

### OIDC SSO (foundation / in progress)
OIDC configuration flags are now available (feature-flagged, disabled by default):
- `AUTH_OIDC_ENABLED=true|false`
- `AUTH_OIDC_ISSUER`
- `AUTH_OIDC_CLIENT_ID`
- `AUTH_OIDC_CLIENT_SECRET`
- `AUTH_OIDC_REDIRECT_URI`
- `AUTH_OIDC_SCOPES` (default `openid profile email`)
- `AUTH_OIDC_ALLOWED_EMAIL_DOMAINS` (optional)
- `AUTH_OIDC_GROUP_ROLE_MAP` (optional JSON map, e.g. `{"fleet-admins":"admin","fleet-ops":"operator"}`)

Current status:
- Login page can show **Sign in with SSO** when OIDC is enabled.
- `/auth/oidc/login` performs OIDC discovery + redirects to IdP.
- `/auth/oidc/callback` now exchanges code, validates `id_token` (issuer/audience/signature/nonce), fetches userinfo, provisions/links user, and creates app session.
- OIDC group->role mapping is supported via `AUTH_OIDC_GROUP_ROLE_MAP`; unmapped users default to `readonly`.

### MFA (TOTP) for privileged users
By default, MFA is **required** for `admin` and `operator` users.
Readonly users can be password-only.

Set an encryption key (Fernet) in `deploy/docker/.env`:
- `MFA_ENCRYPTION_KEY`

Generate one:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

When you log in as a privileged user, the UI will force MFA enrollment and show recovery codes.

You can control MFA behavior via env (server):
- `MFA_REQUIRE_FOR_PRIVILEGED=true|false`
- `MFA_TOTP_ISSUER` (default: `linux-central-management`)

### Agent authentication
All agent endpoints require a shared token (required by default):
- Server: `AGENT_SHARED_TOKEN`
- Agent: `FLEET_AGENT_TOKEN`

For local development only, you can bypass this requirement by setting:
- `ALLOW_INSECURE_NO_AGENT_TOKEN=true`

Do **not** use that on anything exposed beyond a trusted LAN.

### Terminal feature (high risk)
The agent has an optional websocket PTY feature.
Enable only on trusted networks and only with explicit tokens.

### HTTP security headers
The server sets basic security headers by default (e.g. `X-Frame-Options`, `X-Content-Type-Options`).
For internet exposure, run behind HTTPS and set:
- `UI_COOKIE_SECURE=true`

Optional (advanced): set `CONTENT_SECURITY_POLICY` env var to override the default nonce-based CSP.
By default the server emits a restrictive CSP with per-request script nonces and no `unsafe-inline` for scripts.

Token wiring (must match):
- **Server** env: `AGENT_TERMINAL_TOKEN`
- **Agent** env: `FLEET_TERMINAL_TOKEN` (agent also accepts legacy `TERM_TOKEN` / `AGENT_TERMINAL_TOKEN`)

For HTTPS deployments, also set:
- `AGENT_TERMINAL_SCHEME=wss`

### Docker deployment defaults
- Postgres is internal-only by default in `deploy/docker/docker-compose.yml` (not published to host).
- If you need host-local debug access, expose `127.0.0.1:5432:5432` via compose override.

### Maintenance window guardrails (optional)
Use this to block risky actions outside an approved window.

Env settings:
- `MAINTENANCE_WINDOW_ENABLED=true|false`
- `MAINTENANCE_WINDOW_TIMEZONE` (IANA TZ, e.g. `UTC`, `Europe/Tallinn`)
- `MAINTENANCE_WINDOW_START_HHMM` (e.g. `01:00`)
- `MAINTENANCE_WINDOW_END_HHMM` (e.g. `05:00`)
- `MAINTENANCE_WINDOW_GUARDED_ACTIONS` (CSV, default `dist-upgrade,security-campaign`)

When enabled, guarded actions are rejected with HTTP 403 outside the configured window.

### Notification dedupe/cooldown (optional)
Reduce repeated alert noise in Notification Center using server-side cooldowns.

Env settings:
- `NOTIFICATIONS_DEDUPE_ENABLED=true|false`
- `NOTIFICATIONS_DEDUPE_COOLDOWN_SECONDS` (default `1800`)

When enabled, repeated alerts for the same key (e.g., same offline host) are suppressed during cooldown.

### Two-person approvals for high-risk actions (optional)
Require explicit admin approval before execution of selected high-risk actions.

Env settings:
- `HIGH_RISK_APPROVAL_ENABLED=true|false`
- `HIGH_RISK_APPROVAL_ACTIONS` (CSV, default `dist-upgrade,security-campaign`)

When enabled, risky actions return `approval_required=true` and create pending approval requests.
Requester cannot approve/reject own request (enforced two-person rule).
All approval lifecycle steps are written to the audit log.
Admin endpoints:
- `GET /approvals/admin/pending`
- `POST /approvals/admin/{request_id}/approve`
- `POST /approvals/admin/{request_id}/reject`
User endpoint:
- `GET /approvals/my`

---

## Background metrics refresh
The server maintains a cached `host_metrics_snapshots` table for fast attention checks.
A background refresher keeps it updated.

Config via env (server):
- `METRICS_BACKGROUND_REFRESH_SECONDS` (default 60, set 0 to disable)
- `METRICS_BACKGROUND_BATCH_LIMIT` (default 50)

---

## Teams alerts (optional)
You can send alerts to a Microsoft Teams channel via Incoming Webhook.

### Env settings
In `deploy/docker/.env`:
- `TEAMS_WEBHOOK_URL=<incoming webhook url>`
- `TEAMS_ALERTS_ENABLED=true`

### Create webhook in Teams
1. Open target Team + Channel
2. Add **Incoming Webhook** (or Workflow HTTP endpoint, depending on tenant policy)
3. Copy URL and set `TEAMS_WEBHOOK_URL`

### Test from UI
In Fleet Overview → **Data freshness**:
- `Teams: Send test`
- `Teams: Send morning brief`

If your tenant blocks webhook creation, use in-app Notification Center until Teams admin enables it.

---

## Developer workflow

### script.sh (developer convenience)
`./script.sh` is a convenience script that:
- rebuilds/restarts Docker Compose server
- builds the agent
- deploys the agent to hosts via Ansible (from `./hosts`)
- restarts the agent service

To use it:
```bash
cp hosts.example hosts
# edit hosts
SERVER_URL=http://<SERVER_IP>:8000 AGENT_TOKEN=<AGENT_SHARED_TOKEN> TERM_TOKEN=<AGENT_TERMINAL_TOKEN> TARGETS=all ./script.sh
```

### CI
GitHub Actions runs:
- frontend unit tests
- backend smoke tests (overview/notifications/cron)
- full backend test suite

Workflow file: `.github/workflows/ci.yml`

### Release notes
See `CHANGELOG.md` for recent feature additions/fixes.

---
