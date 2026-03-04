#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_ENV_FILE="$ROOT_DIR/deploy/docker/.env"
ROOT_ENV_FILE="$ROOT_DIR/.env"

log_info() { echo "[INFO] $*"; }
log_warn() { echo "[WARN] $*"; }
log_error() { echo "[ERROR] $*"; }

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Required command not found: $cmd"
    exit 1
  fi
}

secure_random_hex() {
  local bytes="${1:-32}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
  else
    # shellcheck disable=SC2005
    echo "$(head -c "$bytes" /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
}

secure_random_alnum() {
  local len="${1:-32}"
  python3 -c 'import secrets, string, sys; n=int(sys.argv[1]); alpha=string.ascii_letters+string.digits; print("".join(secrets.choice(alpha) for _ in range(n)))' "$len"
}

fernet_key() {
  # 32 random bytes, URL-safe base64 (44 chars incl. padding)
  python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
}

ensure_file_from_template() {
  local file="$1"
  local template="$2"
  if [ ! -f "$file" ]; then
    cp "$template" "$file"
    log_info "Created $file from template"
  else
    log_info "Found existing $file"
  fi
}

get_env_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$0 !~ /^[[:space:]]*#/ && $1 == key {print substr($0, index($0, "=") + 1); exit}' "$file"
}

set_env_value_if_missing() {
  local file="$1"
  local key="$2"
  local value="$3"
  local current
  current="$(get_env_value "$file" "$key" || true)"

  if grep -qE "^[[:space:]]*${key}=" "$file"; then
    if [ -n "$current" ]; then
      log_info "Preserved $key in $(basename "$file")"
      return 0
    fi
    sed -i -E "s|^[[:space:]]*${key}=.*$|${key}=${value}|" "$file"
    log_info "Set empty $key in $(basename "$file")"
  else
    printf "\n%s=%s\n" "$key" "$value" >> "$file"
    log_info "Added $key to $(basename "$file")"
  fi
}

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"

  if grep -qE "^[[:space:]]*${key}=" "$file"; then
    sed -i -E "s|^[[:space:]]*${key}=.*$|${key}=${value}|" "$file"
  else
    printf "\n%s=%s\n" "$key" "$value" >> "$file"
  fi
}

# --- Preflight ---
require_cmd ansible
require_cmd go
require_cmd python3
if [ "${RUN_SERVER:-1}" = "1" ]; then
  require_cmd docker
fi

# --- Ensure env files exist ---
ensure_file_from_template "$DOCKER_ENV_FILE" "$ROOT_DIR/deploy/docker/env.example"
ensure_file_from_template "$ROOT_ENV_FILE" "$ROOT_DIR/env.example"

# --- Generate/preserve server-side secrets ---
set_env_value_if_missing "$DOCKER_ENV_FILE" "BOOTSTRAP_PASSWORD" "$(secure_random_alnum 28)"
set_env_value_if_missing "$DOCKER_ENV_FILE" "AGENT_SHARED_TOKEN" "$(secure_random_hex 32)"
set_env_value_if_missing "$DOCKER_ENV_FILE" "AGENT_TERMINAL_TOKEN" "$(secure_random_hex 32)"
set_env_value_if_missing "$DOCKER_ENV_FILE" "MFA_ENCRYPTION_KEY" "$(fernet_key)"

# Mirror server token values to root .env defaults, but keep user-provided values if present.
DOCKER_SHARED_TOKEN="$(get_env_value "$DOCKER_ENV_FILE" "AGENT_SHARED_TOKEN")"
DOCKER_TERM_TOKEN="$(get_env_value "$DOCKER_ENV_FILE" "AGENT_TERMINAL_TOKEN")"

set_env_value_if_missing "$ROOT_ENV_FILE" "AGENT_TOKEN" "$DOCKER_SHARED_TOKEN"
set_env_value_if_missing "$ROOT_ENV_FILE" "TERM_TOKEN" "$DOCKER_TERM_TOKEN"
set_env_value_if_missing "$ROOT_ENV_FILE" "SERVER_URL" "http://192.168.100.240:8000"

chmod 600 "$DOCKER_ENV_FILE" "$ROOT_ENV_FILE"
log_info "Applied secure permissions (chmod 600) to env files"

# Load local env defaults if present.
# NOTE: This script relies on environment variables (SERVER_URL, AGENT_TOKEN, TERM_TOKEN).
if [ -f "$ROOT_ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ROOT_ENV_FILE"
  set +a
fi

# Also load docker env so AGENT_SHARED_TOKEN/AGENT_TERMINAL_TOKEN are available if needed.
if [ -f "$DOCKER_ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$DOCKER_ENV_FILE"
  set +a
fi

# Back-compat / convenience mapping:
# docker/.env uses AGENT_SHARED_TOKEN + AGENT_TERMINAL_TOKEN; the agent deploy expects AGENT_TOKEN + TERM_TOKEN.
# Prefer server-side shared tokens when present to avoid accidental drift from shell env leftovers.
if [ -n "${AGENT_SHARED_TOKEN:-}" ]; then
  AGENT_TOKEN="$AGENT_SHARED_TOKEN"
fi
if [ -n "${AGENT_TERMINAL_TOKEN:-}" ]; then
  TERM_TOKEN="$AGENT_TERMINAL_TOKEN"
fi

# Default server URL for this environment (override by exporting SERVER_URL or setting it in .env).
SERVER_URL="${SERVER_URL:-http://192.168.100.240:8000}"

RUN_SERVER="${RUN_SERVER:-1}"

if [ "$RUN_SERVER" = "1" ]; then
  cd "$ROOT_DIR/deploy/docker"

  # Rebuild/restart services without destroying the database container/volume.
  # NOTE: `docker compose down` would remove the DB container; while the volume persists now,
  # keeping the containers up avoids unnecessary churn.
  log_info "Starting/updating Docker services"
  docker compose up -d --build --remove-orphans
fi

cd "$ROOT_DIR/agent"
log_info "Building fleet-agent binary"
go build -o fleet-agent ./cmd/fleet-agent

# Deploy the freshly built agent binary to the remote host(s)
# Targets default to "all" hosts from $ROOT_DIR/hosts. Override with:
#   TARGETS=192.168.1.10 ./script.sh
TARGETS="${TARGETS:-all}"

# SSH auth helpers (optional)
ANSIBLE_USER="${ANSIBLE_USER:-}"
ANSIBLE_PASS="${ANSIBLE_PASS:-}"

ANSIBLE_COMMON_ARGS=()
if [ -n "$ANSIBLE_USER" ]; then
  ANSIBLE_COMMON_ARGS+=("-u" "$ANSIBLE_USER")
fi
if [ -n "$ANSIBLE_PASS" ]; then
  ANSIBLE_COMMON_ARGS+=("--extra-vars" "ansible_ssh_pass=$ANSIBLE_PASS ansible_become_pass=$ANSIBLE_PASS")
fi
ANSIBLE_COMMON_ARGS+=("--ssh-common-args=-o StrictHostKeyChecking=no")

# Ensure install dir exists
ansible "$TARGETS" -i "$ROOT_DIR/hosts" -b "${ANSIBLE_COMMON_ARGS[@]}" -m file -a "path=/opt/fleet-agent state=directory mode=0755" \
  || log_warn "Agent deploy: could not reach some hosts (dir create step)"

# Copy agent binary
ansible "$TARGETS" -i "$ROOT_DIR/hosts" -b "${ANSIBLE_COMMON_ARGS[@]}" -m copy -a "src=$ROOT_DIR/agent/fleet-agent dest=/opt/fleet-agent/fleet-agent mode=0755" \
  || log_warn "Agent deploy: could not reach some hosts (copy step)"

# Optional: bootstrap a systemd service on targets.
# Provide at least SERVER_URL + AGENT_TOKEN for a working agent:
#   SERVER_URL=http://<SERVER_IP>:8000 AGENT_TOKEN=<shared> ./script.sh
SERVER_URL="${SERVER_URL:-}"
REMOTE_AGENT_TOKEN="${AGENT_TOKEN:-}"
REMOTE_TERMINAL_TOKEN="${TERM_TOKEN:-}"

if [ -n "$SERVER_URL" ] && [ -n "$REMOTE_AGENT_TOKEN" ]; then
  log_info "Installing/updating fleet-agent systemd service on targets"

  # Write env file on the REMOTE host (so hostname is correct)
  ansible "$TARGETS" -i "$ROOT_DIR/hosts" -b "${ANSIBLE_COMMON_ARGS[@]}" -m shell -a "umask 077; HOSTID=\"\$(hostname -s)\"; SERVER_URL=\"$SERVER_URL\"; TOKEN=\"$REMOTE_AGENT_TOKEN\"; TERM_TOKEN=\"$REMOTE_TERMINAL_TOKEN\"; cat > /etc/fleet-agent.env <<EOF
FLEET_SERVER_URL=\$SERVER_URL
FLEET_AGENT_ID=\$HOSTID
FLEET_LABELS=\$LABELS
FLEET_AGENT_TOKEN=\$TOKEN
FLEET_TERMINAL_TOKEN=\$TERM_TOKEN
EOF" || log_warn "Agent deploy: could not reach some hosts (env file step)"

  # Write systemd unit (use shell heredoc; ad-hoc copy module is awkward with spaces/newlines)
  ansible "$TARGETS" -i "$ROOT_DIR/hosts" -b "${ANSIBLE_COMMON_ARGS[@]}" -m shell -a "cat > /etc/systemd/system/fleet-agent.service <<'EOF'
[Unit]
Description=Fleet Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple

# Keep an EnvironmentFile for easy inspection/editing on the host...
EnvironmentFile=/etc/fleet-agent.env
# ...but also include explicit Environment= lines so it's obvious what variables the agent uses.
# Values are resolved on the host via systemd's %H (hostname) specifier.
Environment=FLEET_SERVER_URL=$SERVER_URL
Environment=FLEET_AGENT_ID=%H
Environment=FLEET_AGENT_TOKEN=$REMOTE_AGENT_TOKEN
Environment=FLEET_TERMINAL_TOKEN=$REMOTE_TERMINAL_TOKEN

ExecStart=/opt/fleet-agent/fleet-agent
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/fleet-agent.service" \
    || log_warn "Agent deploy: could not reach some hosts (systemd unit step)"

  ansible "$TARGETS" -i "$ROOT_DIR/hosts" -b "${ANSIBLE_COMMON_ARGS[@]}" -m shell -a "systemctl daemon-reload && systemctl enable --now fleet-agent && systemctl is-active fleet-agent" \
    || log_warn "Agent deploy: could not reach some hosts (systemd enable/restart step)"
else
  log_warn "SERVER_URL and/or AGENT_TOKEN not set; skipping systemd service setup. Binary copied only."
fi

# Kill any stray user-run agent instances (to avoid duplicate heartbeats / confusion)
# (Don't use pkill -f with a pattern that appears in our own command line.)
ansible "$TARGETS" -i "$ROOT_DIR/hosts" -b "${ANSIBLE_COMMON_ARGS[@]}" -m shell -a "pkill -x fleet-agent || true" \
  || log_warn "Agent deploy: could not reach some hosts (pkill step)"

AGENT_TOKEN="${AGENT_TOKEN:-}"
TERM_TOKEN="${TERM_TOKEN:-}"

killall -9 fleet-agent >/dev/null 2>&1 || true

# Local dev agent (optional): requires AGENT_TOKEN/TERM_TOKEN in env
#if [ -n "$AGENT_TOKEN" ]; then
#  FLEET_SERVER_URL=http://localhost:8000 FLEET_AGENT_ID=srv-001 FLEET_LABELS=env=prod,role=postgres FLEET_AGENT_TOKEN="$AGENT_TOKEN" FLEET_TERMINAL_TOKEN="$TERM_TOKEN" nohup ./fleet-agent >/tmp/fleet-agent.log 2>&1 &
#else
#  echo "AGENT_TOKEN not set; skipping local agent start"
#fi
