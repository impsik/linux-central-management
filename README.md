# Fleet Ubuntu MVP

A working MVP for centralized Ubuntu host management:

- **FastAPI server** (PostgreSQL-backed) with a simple web UI
- **Go agent** that inventories hosts and executes jobs via REST long-poll
- Package inventory + upgrade flows, service control, user lock/unlock, SSH key deploy approvals

This is intentionally pragmatic: REST + JSON, no gRPC/protoc requirement.

---

## What you get

### Web UI
- Fleet overview + “Attention required” (offline, high disk, high load, security updates, etc.)
- Per-host:
  - metrics (CPU/mem/disk), top processes
  - packages list + package details (homepage link opens in new tab)
  - system services (click a service → details)
  - system users (click a user → details)
  - SSH keys: add keys and request deployments with admin approval

### API
- `/health` for health checks
- `/hosts/*` for host metrics, packages, users, services
- `/jobs/*` to dispatch/inspect jobs

---

## Quick start (server)

### 1) Prereqs
- Docker + Docker Compose
- sudo apt install docker.io docker-compose

### 2) Configure secrets
```bash
cd deploy/docker
# If your system hides dotfiles, you can use env.example instead.
cp .env.example .env 2>/dev/null || cp env.example .env
# edit .env and set:
# BOOTSTRAP_PASSWORD, AGENT_SHARED_TOKEN, (optional) AGENT_TERMINAL_TOKEN
```

### 3) Start
```bash
cd deploy/docker
docker compose up -d --build
curl -s http://localhost:8000/health
```

Open UI:
- http://localhost:8000/

Login with the bootstrap user you set in `deploy/docker/.env`.

---

## Agent setup (on each Ubuntu host)

### 1) Build (or copy the binary)
```bash
cd agent
go build -o fleet-agent ./cmd/fleet-agent
```

### 2) Run (foreground)
```bash
export FLEET_SERVER_URL=http://<SERVER_IP>:8000
export FLEET_AGENT_ID=<unique-id>        # can be host IP or stable name
export FLEET_LABELS=env=prod,role=web
export FLEET_AGENT_TOKEN=<AGENT_SHARED_TOKEN>

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

### Bootstrap UI password
The server **does not** ship with a safe default password. You must set:
- `BOOTSTRAP_PASSWORD` in `deploy/docker/.env`

### Agent authentication
All agent endpoints require a shared token:
- Server: `AGENT_SHARED_TOKEN`
- Agent: `FLEET_AGENT_TOKEN`

### Terminal feature (high risk)
The agent has an optional websocket PTY feature.
Enable only on trusted networks and only with explicit tokens.

---

## Background metrics refresh
The server maintains a cached `host_metrics_snapshots` table for fast attention checks.
A background refresher keeps it updated.

Config via env (server):
- `METRICS_BACKGROUND_REFRESH_SECONDS` (default 60, set 0 to disable)
- `METRICS_BACKGROUND_BATCH_LIMIT` (default 50)

---

## Developer workflow

### script.sh
`./script.sh` is a convenience script that:
- rebuilds/restarts Docker Compose server
- builds the agent
- copies the agent to the example host via Ansible
- restarts the agent service

It expects local environment variables for tokens if you use the “local agent” portion.

---

## Cleaning for GitHub
This repo should NOT contain real credentials.

Do **not** commit:
- `deploy/docker/.env`
- root `.env`
- any real tokens/passwords/keys
- logs (`ansible_logs/`)
- local build artifacts (agent binary, `.venv`, caches)

See `.gitignore` and `deploy/docker/.env.example` (or `deploy/docker/env.example`).

### Pre-publish checklist
Before you push to a public GitHub repo:

1) **Delete local-only secrets/artifacts**
```bash
./scripts/sanitize.sh --apply
```

2) **Confirm secret env files are gone**
```bash
test ! -f deploy/docker/.env
test ! -f .env
```

3) **Scan the repo for accidental secrets** (tokens/passwords)
```bash
grep -RIn --exclude-dir=.venv --exclude-dir=server/.venv --exclude-dir=node_modules \
  "BOOTSTRAP_PASSWORD\\|AGENT_SHARED_TOKEN\\|AGENT_TERMINAL_TOKEN\\|TERM_TOKEN\\|PASSWORD\\|TOKEN" .
```

4) **(If you already committed secrets)** rotate them and rewrite history
- Rotate the leaked tokens/passwords.
- Use `git filter-repo` (or BFG) to remove the secret file(s) from history.

5) **Double-check you’re not uploading data**
- No DB dumps, exports, or user lists.

Tip: keep `deploy/docker/.env` locally for development, but never commit it.

### Factory reset (wipe local DB)
If you want a truly clean instance (no users/hosts/keys/jobs), you can delete the local Postgres volume.

From `deploy/docker/`:
```bash
docker compose down -v
docker compose up -d --build
```

This removes all local DB contents (including `app_users`, SSH keys, jobs history, metrics snapshots, etc.).
