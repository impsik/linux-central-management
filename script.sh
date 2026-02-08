#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

RUN_SERVER="${RUN_SERVER:-1}"

if [ "$RUN_SERVER" = "1" ]; then
  cd "$ROOT_DIR/deploy/docker"

  # Docker Compose expects a .env next to docker-compose.yml.
  if [ ! -f .env ]; then
    echo "[ERROR] $ROOT_DIR/deploy/docker/.env not found."
    echo "Create it first: cd deploy/docker && cp .env.example .env (or cp env.example .env)"
    echo "Then edit it and set BOOTSTRAP_PASSWORD, AGENT_SHARED_TOKEN, (optional) AGENT_TERMINAL_TOKEN."
    exit 1
  fi

  # Rebuild/restart services without destroying the database container/volume.
  # NOTE: `docker compose down` would remove the DB container; while the volume persists now,
  # keeping the containers up avoids unnecessary churn.
  docker compose up -d --build --remove-orphans
fi

cd "$ROOT_DIR/agent"
go build -o fleet-agent ./cmd/fleet-agent

# Deploy the freshly built agent binary to the remote host(s)
# Targets default to "all" hosts from $ROOT_DIR/hosts. Override with:
#   TARGETS=192.168.100.228 ./script.sh
TARGETS="${TARGETS:-all}"

ansible "$TARGETS" -i "$ROOT_DIR/hosts" -b -m copy -a "src=$ROOT_DIR/agent/fleet-agent dest=/opt/fleet-agent/fleet-agent mode=0755"

# Restart agent service so new binary is actually used
ansible "$TARGETS" -i "$ROOT_DIR/hosts" -b -m shell -a "systemctl restart fleet-agent || true; systemctl is-active fleet-agent || true"

# Kill any stray user-run agent instances (to avoid duplicate heartbeats / confusion)
# (Don't use pkill -f with a pattern that appears in our own command line.)
ansible "$TARGETS" -i "$ROOT_DIR/hosts" -b -m shell -a "pkill -x fleet-agent || true"

AGENT_TOKEN="${AGENT_TOKEN:-}"
TERM_TOKEN="${TERM_TOKEN:-}"


killall -9 fleet-agent >/dev/null 2>&1 || true

# Local dev agent (optional): requires AGENT_TOKEN/TERM_TOKEN in env
if [ -n "$AGENT_TOKEN" ]; then
  FLEET_SERVER_URL=http://localhost:8000 FLEET_AGENT_ID=srv-001 FLEET_LABELS=env=prod,role=postgres FLEET_AGENT_TOKEN="$AGENT_TOKEN" FLEET_TERMINAL_TOKEN="$TERM_TOKEN" nohup ./fleet-agent >/tmp/fleet-agent.log 2>&1 &
else
  echo "AGENT_TOKEN not set; skipping local agent start"
fi
