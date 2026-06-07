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

  hosts_input="$(prompt "New host(s) to attach (space/comma separated)" "")"
  [ -n "$hosts_input" ] || err "No hosts provided"

  ansible_user="$(prompt "SSH username for new host(s)" "$(id -un 2>/dev/null || printf ubuntu)")"
  ansible_pass="$(prompt_secret "SSH password")"

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
  if [ -n "$ansible_pass" ]; then
    RUN_SERVER=0 SERVER_URL="$server_url" AGENT_TOKEN="$agent_token" TERM_TOKEN="$term_token" TARGETS="$target_pattern" ANSIBLE_USER="$ansible_user" ANSIBLE_PASS="$ansible_pass" "$ROOT_DIR/script.sh"
  else
    RUN_SERVER=0 SERVER_URL="$server_url" AGENT_TOKEN="$agent_token" TERM_TOKEN="$term_token" TARGETS="$target_pattern" ANSIBLE_USER="$ansible_user" "$ROOT_DIR/script.sh"
  fi

  say ""
  say "Host attach complete."
  say "Attached: $target_pattern"
  say "Server: $server_url"
}

main "$@"
