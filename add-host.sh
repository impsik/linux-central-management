#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DOCKER_ENV_FILE="$ROOT_DIR/deploy/docker/.env"
ROOT_ENV_FILE="$ROOT_DIR/.env"
HOSTS_FILE="$ROOT_DIR/hosts"
INVENTORY_FILE="$ROOT_DIR/ansible/inventory.yml"

say() { printf '%s\n' "$*"; }
info() { say "[INFO] $*"; }
warn() { say "[WARN] $*" >&2; }
err() { say "[ERROR] $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
is_tty() { [ -r /dev/tty ] && [ -w /dev/tty ]; }

prompt() {
  question="$1"
  default="$2"
  if is_tty; then
    if [ -n "$default" ]; then
      printf '%s [%s]: ' "$question" "$default" > /dev/tty
    else
      printf '%s: ' "$question" > /dev/tty
    fi
    IFS= read -r answer < /dev/tty || answer=""
    if [ -n "$answer" ]; then printf '%s' "$answer"; else printf '%s' "$default"; fi
  else
    printf '%s' "$default"
  fi
}

prompt_secret() {
  question="$1"
  if is_tty; then
    printf '%s [blank for SSH key auth]: ' "$question" > /dev/tty
    old_stty="$(stty -g < /dev/tty 2>/dev/null || true)"
    stty -echo < /dev/tty 2>/dev/null || true
    IFS= read -r answer < /dev/tty || answer=""
    [ -n "$old_stty" ] && stty "$old_stty" < /dev/tty 2>/dev/null || true
    printf '\n' > /dev/tty
    printf '%s' "$answer"
  else
    printf ''
  fi
}

run_ansible() {
  if [ -n "${ansible_pass:-}" ]; then
    ansible "$target_pattern" -i "$HOSTS_FILE" -b -u "$ansible_user" \
      --extra-vars "ansible_ssh_pass=$ansible_pass ansible_become_pass=$ansible_pass" \
      --ssh-common-args='-o StrictHostKeyChecking=accept-new' "$@"
  else
    ansible "$target_pattern" -i "$HOSTS_FILE" -b -u "$ansible_user" \
      --ssh-common-args='-o StrictHostKeyChecking=accept-new' "$@"
  fi
}

deploy_agent() {
  server_url="$1"
  agent_token="$2"
  term_token="$3"
  server_ip="$4"
  ca_cert="$5"

  case "$server_url" in
    https://*)
      [ -n "$ca_cert" ] || err "FLEET_CA_CERT is required for HTTPS agent deployment"
      [ -r "$ca_cert" ] || err "CA certificate is not readable: $ca_cert"
      ;;
  esac

  server_host="${server_url#http://}"
  server_host="${server_host#https://}"
  server_host="${server_host%%/*}"
  server_host="${server_host%%:*}"
  case "$server_url" in
    https://*) terminal_listen="127.0.0.1:18081" ;;
    *) terminal_listen="auto:18080" ;;
  esac

  info "Building fleet-agent"
  (cd "$ROOT_DIR/agent" && go build -o fleet-agent ./cmd/fleet-agent)

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
  cat > "$tmp_dir/fleet-agent.env" <<EOF
FLEET_SERVER_URL=$server_url
FLEET_AGENT_TOKEN=$agent_token
FLEET_AGENT_TOKEN_FILE=/var/lib/fleet-agent/agent-token
FLEET_TERMINAL_TOKEN=$term_token
FLEET_TERMINAL_LISTEN=$terminal_listen
FLEET_TERMINAL_BACKEND=auto
EOF
  cat > "$tmp_dir/fleet-agent.service" <<EOF
[Unit]
Description=Fleet Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/fleet-agent.env
Environment=FLEET_AGENT_ID=%H
ExecStart=/opt/fleet-agent/fleet-agent
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  chmod 600 "$tmp_dir/fleet-agent.env"

  run_ansible -m file -a 'path=/opt/fleet-agent state=directory mode=0755'
  run_ansible -m file -a 'path=/var/lib/fleet-agent state=directory mode=0700'
  run_ansible -m copy -a "src=$ROOT_DIR/agent/fleet-agent dest=/opt/fleet-agent/fleet-agent mode=0755"
  run_ansible -m copy -a "src=$tmp_dir/fleet-agent.env dest=/etc/fleet-agent.env mode=0600"
  run_ansible -m copy -a "src=$tmp_dir/fleet-agent.service dest=/etc/systemd/system/fleet-agent.service mode=0644"

  if [ -n "$ca_cert" ]; then
    info "Installing the fleet internal CA on managed hosts"
    run_ansible -m copy -a "src=$ca_cert dest=/usr/local/share/ca-certificates/fleet-internal-ca.crt mode=0644"
    run_ansible -m command -a update-ca-certificates
  fi

  if [ -n "$server_ip" ] && [ "$server_host" != "$server_ip" ]; then
    info "Ensuring $server_host resolves to $server_ip on managed hosts"
    run_ansible -m blockinfile -a "path=/etc/hosts marker='# {mark} FLEET SERVER' block='$server_ip $server_host'"
  fi

  case "$server_url" in
    https://*)
      info "Verifying HTTPS trust and hostname before starting agents"
      run_ansible -m uri -a "url=$server_url/health method=GET status_code=200 validate_certs=true return_content=false"
      ;;
  esac

  run_ansible -m shell -a 'systemctl daemon-reload && systemctl enable --now fleet-agent && systemctl restart fleet-agent && systemctl is-active fleet-agent'
}

get_env_value() {
  file="$1"
  key="$2"
  awk -F= -v key="$key" '$0 !~ /^[[:space:]]*#/ && $1 == key {print substr($0, index($0, "=") + 1); exit}' "$file" 2>/dev/null || true
}

require_file() {
  file="$1"
  hint="$2"
  [ -f "$file" ] || err "$file not found. $hint"
}

normalize_hosts() {
  printf '%s' "$1" | tr ',;' '  '
}

ensure_inventory() {
  mkdir -p "$(dirname "$INVENTORY_FILE")"
  if [ ! -f "$INVENTORY_FILE" ]; then
    {
      printf 'all:\n'
      printf '  hosts:\n'
    } > "$INVENTORY_FILE"
  fi
}

add_host_files() {
  host="$1"
  ansible_user="$2"

  touch "$HOSTS_FILE"
  if awk -v host="$host" '$1 == host {found=1} END {exit !found}' "$HOSTS_FILE"; then
    info "Preserved existing $host in hosts"
  elif [ -n "$ansible_user" ]; then
    printf '%s ansible_user=%s\n' "$host" "$ansible_user" >> "$HOSTS_FILE"
    info "Added $host to hosts"
  else
    printf '%s\n' "$host" >> "$HOSTS_FILE"
    info "Added $host to hosts"
  fi

  ensure_inventory
  if awk -v host="$host:" '$1 == host {found=1} END {exit !found}' "$INVENTORY_FILE"; then
    info "Preserved existing $host in ansible/inventory.yml"
  elif [ -n "$ansible_user" ]; then
    {
      printf '    %s:\n' "$host"
      printf '      ansible_user: %s\n' "$ansible_user"
    } >> "$INVENTORY_FILE"
    info "Added $host to ansible/inventory.yml"
  else
    printf '    %s: {}\n' "$host" >> "$INVENTORY_FILE"
    info "Added $host to ansible/inventory.yml"
  fi
}

main() {
  say "Linux Central Management host attach helper"
  say "-------------------------------------------"

  require_file "$ROOT_ENV_FILE" "Run install.sh first."
  require_file "$DOCKER_ENV_FILE" "Run install.sh first."
  have ansible || err "ansible is required. Install it or rerun install.sh on the admin node."
  have go || err "go is required to build the fleet-agent. Install it or rerun install.sh on the admin node."

  server_url="$(get_env_value "$ROOT_ENV_FILE" "SERVER_URL")"
  [ -n "$server_url" ] || server_url="$(prompt "Server URL agents should use" "")"
  [ -n "$server_url" ] || err "SERVER_URL is missing in $ROOT_ENV_FILE"

  agent_token="$(get_env_value "$ROOT_ENV_FILE" "AGENT_TOKEN")"
  [ -n "$agent_token" ] || agent_token="$(get_env_value "$DOCKER_ENV_FILE" "AGENT_SHARED_TOKEN")"
  [ -n "$agent_token" ] || err "Agent token is missing in $ROOT_ENV_FILE and $DOCKER_ENV_FILE"

  term_token="$(get_env_value "$ROOT_ENV_FILE" "TERM_TOKEN")"
  [ -n "$term_token" ] || term_token="$(get_env_value "$DOCKER_ENV_FILE" "AGENT_TERMINAL_TOKEN")"

  hosts_input="${ATTACH_HOSTS:-$(prompt "New host(s) to attach (space/comma separated)" "")}"
  [ -n "$hosts_input" ] || err "No hosts provided"

  ansible_user="${ANSIBLE_USER:-$(prompt "SSH username for new host(s)" "$(id -un 2>/dev/null || printf ubuntu)")}"
  ansible_pass="${ANSIBLE_PASS:-$(prompt_secret "SSH password")}"

  target_pattern=""
  for host in $(normalize_hosts "$hosts_input"); do
    [ -n "$host" ] || continue
    add_host_files "$host" "$ansible_user"
    if [ -n "$target_pattern" ]; then
      target_pattern="$target_pattern:$host"
    else
      target_pattern="$host"
    fi
  done
  [ -n "$target_pattern" ] || err "No valid hosts provided"

  chmod 600 "$ROOT_ENV_FILE" "$DOCKER_ENV_FILE"

  info "Deploying fleet-agent to: $target_pattern"
  fleet_server_ip="${FLEET_SERVER_IP:-$(get_env_value "$ROOT_ENV_FILE" "FLEET_SERVER_IP")}"
  fleet_ca_cert="${FLEET_CA_CERT:-$(get_env_value "$ROOT_ENV_FILE" "FLEET_CA_CERT")}"
  deploy_agent "$server_url" "$agent_token" "$term_token" "$fleet_server_ip" "$fleet_ca_cert"

  say ""
  say "Host attach complete."
  say "Attached: $target_pattern"
  say "Server: $server_url"
}

main "$@"
