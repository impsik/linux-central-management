#!/bin/sh
set -eu

REPO_URL="${REPO_URL:-https://github.com/impsik/linux-central-management.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/linux-central-management}"
INSTALL_REF="${INSTALL_REF:-main}"

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

prompt_secret_or_generate() {
  question="$1"
  generated="$2"
  if is_tty; then
    printf '%s [leave blank to generate]: ' "$question" > /dev/tty
    old_stty="$(stty -g < /dev/tty 2>/dev/null || true)"
    stty -echo < /dev/tty 2>/dev/null || true
    IFS= read -r answer < /dev/tty || answer=""
    [ -n "$old_stty" ] && stty "$old_stty" < /dev/tty 2>/dev/null || true
    printf '\n' > /dev/tty
    if [ -n "$answer" ]; then printf '%s' "$answer"; else printf '%s' "$generated"; fi
  else
    printf '%s' "$generated"
  fi
}

confirm() {
  question="$1"
  default="${2:-n}"
  answer="$(prompt "$question" "$default")"
  case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
    y|yes) return 0 ;;
    *) return 1 ;;
  esac
}

sudo_cmd() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    err "This step needs root privileges. Install sudo or run as root."
  fi
}

random_hex() {
  bytes="${1:-32}"
  if have openssl; then
    openssl rand -hex "$bytes"
  else
    python3 -c 'import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))' "$bytes"
  fi
}

random_password() {
  python3 -c 'import secrets,string; a=string.ascii_letters+string.digits+"-_.!"; print("".join(secrets.choice(a) for _ in range(28)))'
}

fernet_key() {
  python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
}

primary_ip() {
  if have hostname; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -n "$ip" ] && { printf '%s' "$ip"; return; }
  fi
  printf '127.0.0.1'
}

install_packages() {
  if ! have apt-get; then
    warn "apt-get not found. Please install: git curl ca-certificates docker docker-compose plugin python3 openssl ansible-core golang-go"
    return
  fi

  info "Installing OS packages"
  sudo_cmd apt-get update

  compose_pkg=""
  if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
    compose_pkg="docker-compose-v2"
  elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
    compose_pkg="docker-compose-plugin"
  elif apt-cache show docker-compose >/dev/null 2>&1; then
    compose_pkg="docker-compose"
  fi

  ansible_pkg="ansible-core"
  if ! apt-cache show ansible-core >/dev/null 2>&1 && apt-cache show ansible >/dev/null 2>&1; then
    ansible_pkg="ansible"
  fi

  # ansible-core and golang-go are used by optional agent deployment.
  sudo_cmd apt-get install -y git curl ca-certificates openssl python3 docker.io "$ansible_pkg" golang-go $compose_pkg

  if have systemctl; then
    sudo_cmd systemctl enable --now docker >/dev/null 2>&1 || true
  fi
}

ensure_repo() {
  if [ -f "server/app/main.py" ] && [ -f "deploy/docker/docker-compose.yml" ]; then
    APP_DIR="$(pwd)"
    info "Using existing checkout: $APP_DIR"
    return
  fi

  if [ -d "$INSTALL_DIR/.git" ]; then
    APP_DIR="$INSTALL_DIR"
    info "Updating existing checkout: $APP_DIR"
    git -C "$APP_DIR" fetch origin --prune
    git -C "$APP_DIR" checkout "$INSTALL_REF"
    git -C "$APP_DIR" pull --ff-only origin "$INSTALL_REF"
    return
  fi

  info "Cloning $REPO_URL to $INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  git clone --branch "$INSTALL_REF" "$REPO_URL" "$INSTALL_DIR"
  APP_DIR="$INSTALL_DIR"
}

get_env_value() {
  file="$1"
  key="$2"
  awk -F= -v key="$key" '$0 !~ /^[[:space:]]*#/ && $1 == key {print substr($0, index($0, "=") + 1); exit}' "$file" 2>/dev/null || true
}

is_placeholder_value() {
  value="$1"
  case "$value" in
    ""|change-me*|changeme|fleet|password|admin|token) return 0 ;;
    *) return 1 ;;
  esac
}

set_env_value() {
  file="$1"
  key="$2"
  value="$3"
  tmp="${file}.tmp.$$"
  if [ -f "$file" ] && grep -q "^[[:space:]]*$key=" "$file"; then
    awk -v key="$key" -v val="$value" 'BEGIN{done=0} $0 ~ "^[[:space:]]*" key "=" && done==0 {print key "=" val; done=1; next} {print}' "$file" > "$tmp"
    mv "$tmp" "$file"
  else
    printf '\n%s=%s\n' "$key" "$value" >> "$file"
  fi
}

set_env_if_blank_or_placeholder() {
  file="$1"
  key="$2"
  value="$3"
  current="$(get_env_value "$file" "$key")"
  if is_placeholder_value "$current"; then
    set_env_value "$file" "$key" "$value"
  else
    info "Preserved existing $key"
  fi
}

write_inventory() {
  hosts_input="$1"
  ansible_user="$2"

  [ -n "$hosts_input" ] || return 0

  hosts_file="$APP_DIR/hosts"
  inventory_file="$APP_DIR/ansible/inventory.yml"
  tmp_hosts="${hosts_file}.tmp.$$"
  tmp_inv="${inventory_file}.tmp.$$"

  : > "$tmp_hosts"
  {
    printf 'all:\n'
    printf '  hosts:\n'
  } > "$tmp_inv"

  # shellcheck disable=SC2086
  for host in $(printf '%s' "$hosts_input" | tr ',;' '  '); do
    [ -n "$host" ] || continue
    if [ -n "$ansible_user" ]; then
      printf '%s ansible_user=%s\n' "$host" "$ansible_user" >> "$tmp_hosts"
      printf '    %s:\n      ansible_user: %s\n' "$host" "$ansible_user" >> "$tmp_inv"
    else
      printf '%s\n' "$host" >> "$tmp_hosts"
      printf '    %s: {}\n' "$host" >> "$tmp_inv"
    fi
  done

  mv "$tmp_hosts" "$hosts_file"
  mv "$tmp_inv" "$inventory_file"
  info "Wrote $hosts_file"
  info "Wrote $inventory_file"
}

docker_compose() {
  if [ "$(id -u)" -eq 0 ] && docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif [ "$(id -u)" -eq 0 ] && have docker-compose; then
    docker-compose "$@"
  elif docker ps >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif docker ps >/dev/null 2>&1 && have docker-compose; then
    docker-compose "$@"
  elif have sudo && sudo docker compose version >/dev/null 2>&1; then
    sudo docker compose "$@"
  elif have sudo && sudo docker-compose version >/dev/null 2>&1; then
    sudo docker-compose "$@"
  else
    err "Cannot access Docker. Add your user to the docker group or run with sudo."
  fi
}

sync_postgres_password() {
  password="$1"
  escaped_password="$(printf '%s' "$password" | sed "s/'/''/g")"
  info "Synchronizing bundled Postgres role password"
  i=0
  while [ "$i" -lt 60 ]; do
    if docker_compose exec -T db pg_isready -U fleet -d fleet >/dev/null 2>&1; then
      break
    fi
    i=$((i + 1))
    sleep 2
  done

  if [ "$i" -ge 60 ]; then
    warn "Bundled Postgres did not become ready; skipping password sync"
    return 1
  fi

  if printf "ALTER USER fleet WITH PASSWORD '%s';\n" "$escaped_password" | docker_compose exec -T db psql -v ON_ERROR_STOP=1 -U fleet -d fleet >/dev/null; then
    info "Bundled Postgres role password is in sync"
  else
    warn "Could not synchronize bundled Postgres password. Check: cd $APP_DIR/deploy/docker && docker compose logs db"
    return 1
  fi
}

wait_for_health() {
  url="$1"
  info "Waiting for $url/health"
  i=0
  while [ "$i" -lt 60 ]; do
    if curl -fsS "$url/health" >/dev/null 2>&1; then
      info "Server health check passed"
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  warn "Server did not answer $url/health yet. Check: cd $APP_DIR/deploy/docker && docker compose logs server"
}

main() {
  say "Linux Central Management installer"
  say "----------------------------------"

  install_packages
  ensure_repo
  cd "$APP_DIR"

  docker_env="$APP_DIR/deploy/docker/.env"
  root_env="$APP_DIR/.env"
  docker_env_existing="false"
  [ -f "$docker_env" ] && docker_env_existing="true"
  [ -f "$docker_env" ] || cp "$APP_DIR/deploy/docker/env.example" "$docker_env"
  [ -f "$root_env" ] || cp "$APP_DIR/env.example" "$root_env"

  default_url="$(get_env_value "$root_env" "SERVER_URL")"
  [ -n "$default_url" ] || default_url="http://$(primary_ip):8000"
  server_url="$(prompt "Server URL agents and browser should use" "$default_url")"

  current_bootstrap_user="$(get_env_value "$docker_env" "BOOTSTRAP_USERNAME")"
  [ -n "$current_bootstrap_user" ] || current_bootstrap_user="admin"
  bootstrap_user="$(prompt "Bootstrap admin username" "$current_bootstrap_user")"

  current_bootstrap_password="$(get_env_value "$docker_env" "BOOTSTRAP_PASSWORD")"
  bootstrap_password_display=""
  if is_placeholder_value "$current_bootstrap_password"; then
    bootstrap_password="$(prompt_secret_or_generate "Bootstrap admin password" "$(random_password)")"
    bootstrap_password_display="$bootstrap_password"
  elif confirm "Bootstrap admin password already exists. Rotate it now?" "n"; then
    bootstrap_password="$(prompt_secret_or_generate "New bootstrap admin password" "$(random_password)")"
    bootstrap_password_display="$bootstrap_password"
  else
    bootstrap_password="$current_bootstrap_password"
    bootstrap_password_display="preserved existing value in $docker_env"
    info "Preserved existing BOOTSTRAP_PASSWORD"
  fi

  current_agent_token="$(get_env_value "$docker_env" "AGENT_SHARED_TOKEN")"
  if is_placeholder_value "$current_agent_token"; then
    agent_token="$(random_hex 32)"
  elif confirm "Agent shared token already exists. Rotate it now? Existing agents must be redeployed if rotated." "n"; then
    agent_token="$(random_hex 32)"
  else
    agent_token="$current_agent_token"
    info "Preserved existing AGENT_SHARED_TOKEN"
  fi

  current_mfa_key="$(get_env_value "$docker_env" "MFA_ENCRYPTION_KEY")"
  if is_placeholder_value "$current_mfa_key"; then
    mfa_key="$(fernet_key)"
  elif confirm "MFA encryption key already exists. Rotate it now? Existing MFA enrollments may need to be reset." "n"; then
    mfa_key="$(fernet_key)"
  else
    mfa_key="$current_mfa_key"
    info "Preserved existing MFA_ENCRYPTION_KEY"
  fi

  current_terminal_token="$(get_env_value "$docker_env" "AGENT_TERMINAL_TOKEN")"
  terminal_token=""
  if is_placeholder_value "$current_terminal_token"; then
    if confirm "Enable browser terminal proxy token now? (higher risk)" "n"; then
      terminal_token="$(random_hex 32)"
    fi
  elif confirm "Browser terminal proxy token already exists. Rotate it now? Existing agents must be redeployed if rotated." "n"; then
    terminal_token="$(random_hex 32)"
  else
    terminal_token="$current_terminal_token"
    info "Preserved existing AGENT_TERMINAL_TOKEN"
  fi

  current_postgres_password="$(get_env_value "$docker_env" "POSTGRES_PASSWORD")"
  current_database_url="$(get_env_value "$docker_env" "DATABASE_URL")"
  if [ "$docker_env_existing" = "true" ] && [ -z "$current_postgres_password" ] && [ -z "$current_database_url" ]; then
    postgres_password="fleet"
    warn "Existing Docker env has no POSTGRES_PASSWORD; preserving legacy database password. Rotate it before production/non-local use."
  elif is_placeholder_value "$current_postgres_password"; then
    postgres_password="$(random_hex 24)"
  elif confirm "Postgres password already exists. Rotate it now? Existing database volume may need manual migration if rotated." "n"; then
    postgres_password="$(random_hex 24)"
  else
    postgres_password="$current_postgres_password"
    info "Preserved existing POSTGRES_PASSWORD"
  fi

  case "$current_database_url" in
    ""|*fleet:fleet@db*|*change-me*@db*)
      database_url="postgresql+psycopg://fleet:${postgres_password}@db:5432/fleet"
      ;;
    *)
      database_url="$current_database_url"
      info "Preserved existing DATABASE_URL"
      ;;
  esac

  deploy_hosts="$(prompt "Managed hosts to deploy agent to now (space/comma separated, blank to skip)" "")"
  ansible_user=""
  if [ -n "$deploy_hosts" ]; then
    ansible_user="$(prompt "SSH username for managed hosts" "$(id -un 2>/dev/null || printf ubuntu)")"
  fi

  case "$server_url" in
    https://*)
      ui_cookie_secure="true"
      agent_terminal_scheme="wss"
      allow_insecure_no_agent_token="false"
      db_auto_create_tables="false"
      ;;
    *)
      ui_cookie_secure="false"
      agent_terminal_scheme="ws"
      allow_insecure_no_agent_token="true"
      db_auto_create_tables="true"
      warn "Using HTTP/LAN mode. For internet-facing installs, use HTTPS so production guardrails stay enabled."
      ;;
  esac

  set_env_value "$docker_env" "BOOTSTRAP_USERNAME" "$bootstrap_user"
  set_env_value "$docker_env" "BOOTSTRAP_PASSWORD" "$bootstrap_password"
  set_env_value "$docker_env" "AGENT_SHARED_TOKEN" "$agent_token"
  set_env_value "$docker_env" "AGENT_SHARED_TOKEN_ALLOW_RUNTIME" "false"
  set_env_value "$docker_env" "AGENT_SHARED_TOKEN_ALLOW_REBIND" "false"
  set_env_value "$docker_env" "AGENT_HMAC_REQUIRED" "true"
  set_env_value "$docker_env" "AGENT_HMAC_MAX_SKEW_SECONDS" "300"
  set_env_value "$docker_env" "MFA_ENCRYPTION_KEY" "$mfa_key"
  set_env_value "$docker_env" "UI_COOKIE_SECURE" "$ui_cookie_secure"
  set_env_value "$docker_env" "ALLOW_INSECURE_NO_AGENT_TOKEN" "$allow_insecure_no_agent_token"
  set_env_value "$docker_env" "DB_AUTO_CREATE_TABLES" "$db_auto_create_tables"
  set_env_value "$docker_env" "DB_REQUIRE_MIGRATIONS_UP_TO_DATE" "true"
  set_env_value "$docker_env" "POSTGRES_PASSWORD" "$postgres_password"
  set_env_value "$docker_env" "DATABASE_URL" "$database_url"
  set_env_value "$docker_env" "AGENT_TERMINAL_TOKEN" "$terminal_token"
  set_env_value "$docker_env" "AGENT_TERMINAL_SCHEME" "$agent_terminal_scheme"
  set_env_value "$docker_env" "HIGH_RISK_APPROVAL_ENABLED" "true"
  set_env_value "$docker_env" "HIGH_RISK_APPROVAL_ACTIONS" "dist-upgrade,security-campaign"

  final_agent_token="$(get_env_value "$docker_env" "AGENT_SHARED_TOKEN")"
  final_terminal_token="$(get_env_value "$docker_env" "AGENT_TERMINAL_TOKEN")"
  set_env_value "$root_env" "SERVER_URL" "$server_url"
  set_env_value "$root_env" "AGENT_TOKEN" "$final_agent_token"
  set_env_value "$root_env" "TERM_TOKEN" "$final_terminal_token"
  set_env_value "$root_env" "TERM_LISTEN" "auto:18080"

  chmod 600 "$docker_env" "$root_env"

  write_inventory "$deploy_hosts" "$ansible_user"

  info "Starting server with Docker Compose"
  (
    cd "$APP_DIR/deploy/docker"
    docker_compose up -d db
    sync_postgres_password "$postgres_password"
    docker_compose up -d --build --remove-orphans
  )
  wait_for_health "$server_url"

  if [ -n "$deploy_hosts" ]; then
    if confirm "Build and deploy fleet-agent to listed hosts now?" "y"; then
      info "Deploying agent with script.sh"
      (cd "$APP_DIR" && RUN_SERVER=0 SERVER_URL="$server_url" AGENT_TOKEN="$final_agent_token" TERM_TOKEN="$final_terminal_token" TARGETS=all ./script.sh)
    else
      warn "Skipped agent deploy. You can run it later:"
      say "  cd $APP_DIR && RUN_SERVER=0 SERVER_URL=\"$server_url\" TARGETS=all ./script.sh"
    fi
  fi

  say ""
  say "Install complete."
  say "Open: $server_url/"
  say "Login: $bootstrap_user"
  say "Password: $bootstrap_password_display"
  say ""
  say "Config files:"
  say "  $docker_env"
  say "  $root_env"
  [ -n "$deploy_hosts" ] && say "  $APP_DIR/hosts"
}

main "$@"
