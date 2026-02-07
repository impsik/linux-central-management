#!/bin/bash
set -euo pipefail

cd /home/imre/fleet_ubuntu_mvp_full/deploy/docker

# Rebuild/restart services without destroying the database container/volume.
# NOTE: `docker compose down` would remove the DB container; while the volume persists now,
# keeping the containers up avoids unnecessary churn.
docker compose up -d --build --remove-orphans

cd /home/imre/fleet_ubuntu_mvp_full/agent
go build -o fleet-agent ./cmd/fleet-agent

# Deploy the freshly built agent binary to the remote host(s)
ansible 192.168.100.216 -m copy -a "src=/home/imre/fleet_ubuntu_mvp_full/agent/fleet-agent dest=/opt/fleet-agent/fleet-agent mode=0755" -i hosts -b

# Restart agent service so new binary is actually used
ansible 192.168.100.216 -i hosts -b -m shell -a "systemctl restart fleet-agent || true; systemctl is-active fleet-agent || true"

# Kill any stray user-run agent instances (to avoid duplicate heartbeats / confusion)
# (Don't use pkill -f with a pattern that appears in our own command line.)
ansible 192.168.100.216 -i hosts -b -m shell -a "pkill -u imre -x fleet-agent || true"

AGENT_TOKEN="${AGENT_TOKEN:-}"
TERM_TOKEN="${TERM_TOKEN:-}"
#ansible 192.168.100.216 \
#  -m shell \
#  -a 'killall -9 fleet-agent >/dev/null 2>&1 || true; \
#      FLEET_SERVER_URL=http://192.168.100.215:8000 \
#      FLEET_AGENT_ID=192.168.100.216 \
#      FLEET_LABELS=env=prod,role=web \
#      FLEET_AGENT_TOKEN="{{ agent_token }}" \
#      FLEET_TERMINAL_TOKEN="{{ term_token }}" \
#      nohup /home/imre/fleet-agent >/tmp/fleet-agent.log 2>&1 &' \
#  -e "agent_token=$AGENT_TOKEN term_token=$TERM_TOKEN" \
#  -i hosts

#ansible 192.168.100.184 \
#  -m shell \
#  -a 'FLEET_SERVER_URL=http://192.168.1.9:8000 \
#      FLEET_AGENT_ID=srv-003 \
#      FLEET_LABELS=env=prod,role=database \
#      FLEET_AGENT_TOKEN="{{ agent_token }}" \
#      FLEET_TERMINAL_TOKEN="{{ term_token }}" \
#      nohup /home/imre/fleet-agent >/tmp/fleet-agent.log 2>&1 &' \
#  -e "agent_token=$AGENT_TOKEN term_token=$TERM_TOKEN" \
#  -i hosts

killall -9 fleet-agent >/dev/null 2>&1 || true

# Local dev agent (optional): requires AGENT_TOKEN/TERM_TOKEN in env
if [ -n "$AGENT_TOKEN" ]; then
  FLEET_SERVER_URL=http://localhost:8000 FLEET_AGENT_ID=srv-001 FLEET_LABELS=env=prod,role=postgres FLEET_AGENT_TOKEN="$AGENT_TOKEN" FLEET_TERMINAL_TOKEN="$TERM_TOKEN" nohup ./fleet-agent >/tmp/fleet-agent.log 2>&1 &
else
  echo "AGENT_TOKEN not set; skipping local agent start"
fi
