#!/bin/sh
set -eu

REPO_URL="${REPO_URL:-https://github.com/impsik/linux-central-management.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/linux-central-management}"
INSTALL_REF="${INSTALL_REF:-main}"

say() { printf '%s\n' "$*"; }
if [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
  [ -t 1 ] && INFO_COLOR='\033[32m' || INFO_COLOR=''
  [ -t 2 ] && WARN_COLOR='\033[33m' ERROR_COLOR='\033[31m' || {
    WARN_COLOR=''
    ERROR_COLOR=''
  }
else
  INFO_COLOR=''
  WARN_COLOR=''
  ERROR_COLOR=''
fi
[ -n "$INFO_COLOR" ] && INFO_RESET='\033[0m' || INFO_RESET=''
[ -n "$WARN_COLOR" ] && WARN_RESET='\033[0m' || WARN_RESET=''
[ -n "$ERROR_COLOR" ] && ERROR_RESET='\033[0m' || ERROR_RESET=''
info() { printf '%b[INFO]%b %s\n' "$INFO_COLOR" "$INFO_RESET" "$*"; }
warn() { printf '%b[WARNING]%b %s\n' "$WARN_COLOR" "$WARN_RESET" "$*" >&2; }
err() { printf '%b[ERROR]%b %s\n' "$ERROR_COLOR" "$ERROR_RESET" "$*" >&2; exit 1; }
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

url_host() {
  value="$1"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  value="${value%%:*}"
  printf '%s' "$value"
}

validate_hostname() {
  value="$1"
  printf '%s' "$value" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$' \
    || err "Invalid application hostname: $value"
}

validate_ipv4() {
  value="$1"
  printf '%s\n' "$value" | awk -F. '
    NF != 4 {exit 1}
    {for (i=1; i<=4; i++) if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1}
  ' || err "Invalid Fleet server IPv4 address: $value"
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
  ca_cert="${2:-}"
  info "Waiting for $url/health"
  i=0
  while [ "$i" -lt 60 ]; do
    if [ -n "$ca_cert" ]; then
      health_ok="$(curl -fsS --cacert "$ca_cert" "$url/health" 2>/dev/null || true)"
    else
      health_ok="$(curl -fsS "$url/health" 2>/dev/null || true)"
    fi
    if [ -n "$health_ok" ]; then
      info "Server health check passed"
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  warn "Server did not answer $url/health yet. Check: cd $APP_DIR/deploy/docker && docker compose logs server"
  warn "TLS/connectivity diagnostic:"
  # Keep certificate verification enabled and expose the actual final error.
  if [ -n "$ca_cert" ]; then
    curl -sS --cacert "$ca_cert" --connect-timeout 10 "$url/health" >/dev/null || true
  else
    curl -sS --connect-timeout 10 "$url/health" >/dev/null || true
  fi
  return 1
}

prepare_https() {
  server_url="$1"
  server_ip="$2"
  ca_cert="$3"
  install_nginx="$4"

  case "$server_url" in
    https://*) ;;
    *) return 0 ;;
  esac

  server_host="${server_url#https://}"
  server_host="${server_host%%/*}"
  server_host="${server_host%%:*}"
  ca_key="${ca_cert%.crt}.key"
  pki_dir="$(dirname "$ca_cert")"
  work_dir="$(mktemp -d)"
  trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

  sudo_cmd mkdir -p "$pki_dir"
  sudo_cmd chmod 755 "$pki_dir"
  if ! sudo_cmd test -f "$ca_cert"; then
    info "Creating the fleet internal CA"
    sudo_cmd openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
      -keyout "$ca_key" -out "$ca_cert" -subj '/CN=Fleet Internal CA' \
      -addext 'basicConstraints=critical,CA:TRUE' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign'
    sudo_cmd chmod 600 "$ca_key"
    sudo_cmd chmod 644 "$ca_cert"
  fi
  sudo_cmd test -f "$ca_key" || err "CA private key is required to issue the server certificate: $ca_key"

  sudo_cmd install -m 0644 "$ca_cert" /usr/local/share/ca-certificates/fleet-internal-ca.crt
  sudo_cmd update-ca-certificates
  if ! getent hosts "$server_host" 2>/dev/null | awk -v ip="$server_ip" '$1 == ip {found=1} END {exit !found}'; then
    info "Adding local fallback resolution for $server_host"
    printf '%s %s\n' "$server_ip" "$server_host" | sudo_cmd tee -a /etc/hosts >/dev/null
  fi

  cat > "$work_dir/server-ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$server_host,IP:$server_ip
EOF
  info "Issuing an HTTPS certificate for $server_host"
  sudo_cmd openssl req -new -newkey rsa:3072 -nodes \
    -keyout "$pki_dir/fleet-server.key" -out "$work_dir/fleet-server.csr" \
    -subj "/CN=$server_host"
  sudo_cmd openssl x509 -req -sha256 -days 397 \
    -in "$work_dir/fleet-server.csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
    -out "$pki_dir/fleet-server.crt" -extfile "$work_dir/server-ext.cnf"
  sudo_cmd chmod 600 "$pki_dir/fleet-server.key"
  sudo_cmd chmod 644 "$pki_dir/fleet-server.crt"

  say "HTTPS certificate files:"
  say "  CA certificate:     $ca_cert"
  say "  Server certificate: $pki_dir/fleet-server.crt"
  say "  Server private key: $pki_dir/fleet-server.key"

  if [ "$install_nginx" != "true" ]; then
    warn "Automatic nginx setup was declined. Configure Apache, nginx, Caddy, or another reverse proxy to terminate HTTPS for $server_url and proxy to http://127.0.0.1:18000."
    warn "After the HTTPS endpoint works, run: cd $APP_DIR && ./add-host.sh"
    return 0
  fi

  info "Installing and configuring nginx"
  if have ss && ss -ltn 2>/dev/null | awk '$4 ~ /:443$/ {found=1} END {exit !found}'; then
    if ! have systemctl || ! systemctl is-active --quiet nginx 2>/dev/null; then
      err "TCP port 443 is already in use by another service. Choose the externally managed reverse proxy option."
    fi
  fi
  if have apt-get; then
    sudo_cmd apt-get install -y nginx
  elif ! have nginx; then
    err "nginx is not installed and apt-get is unavailable"
  fi
  sudo_cmd mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

  cat > "$work_dir/nginx-fleet" <<EOF
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $server_host $server_ip _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name $server_host $server_ip _;

    ssl_certificate $pki_dir/fleet-server.crt;
    ssl_certificate_key $pki_dir/fleet-server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_timeout 1d;
    ssl_session_cache shared:FleetTLS:10m;
    ssl_session_tickets off;

    client_max_body_size 20m;
    location / {
        proxy_pass http://127.0.0.1:18000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF
  sudo_cmd install -m 0644 "$work_dir/nginx-fleet" /etc/nginx/sites-available/fleet
  [ ! -L /etc/nginx/sites-enabled/default ] || sudo_cmd unlink /etc/nginx/sites-enabled/default
  if [ -e /etc/nginx/sites-enabled/fleet ] || [ -L /etc/nginx/sites-enabled/fleet ]; then
    active_target="$(readlink /etc/nginx/sites-enabled/fleet 2>/dev/null || true)"
    if [ "$active_target" != "/etc/nginx/sites-available/fleet" ]; then
      backup_path="/etc/nginx/sites-available/fleet.previous.$(date +%Y%m%d%H%M%S)"
      info "Backing up existing active nginx site to $backup_path"
      sudo_cmd cp -a /etc/nginx/sites-enabled/fleet "$backup_path"
      sudo_cmd unlink /etc/nginx/sites-enabled/fleet
      sudo_cmd ln -s /etc/nginx/sites-available/fleet /etc/nginx/sites-enabled/fleet
    fi
  else
    sudo_cmd ln -s /etc/nginx/sites-available/fleet /etc/nginx/sites-enabled/fleet
  fi
  sudo_cmd nginx -t
  sudo_cmd systemctl enable --now nginx
  sudo_cmd systemctl reload nginx
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

  existing_url="$(get_env_value "$root_env" "SERVER_URL")"
  default_host="$(url_host "$existing_url")"
  [ -n "$default_host" ] || default_host="fleet.local"
  application_host="${FLEET_HOSTNAME:-$(prompt "Application hostname (without https:// or a path)" "$default_host")}"
  validate_hostname "$application_host"
  server_url="https://$application_host"

  fleet_server_ip="$(get_env_value "$root_env" "FLEET_SERVER_IP")"
  [ -n "$fleet_server_ip" ] || fleet_server_ip="$(primary_ip)"
  fleet_server_ip="${FLEET_SERVER_IP:-$(prompt "Fleet server IPv4 address" "$fleet_server_ip")}"
  validate_ipv4 "$fleet_server_ip"

  fleet_ca_cert="$(get_env_value "$root_env" "FLEET_CA_CERT")"
  [ -n "$fleet_ca_cert" ] || fleet_ca_cert="/etc/fleet-pki/fleet-ca.crt"
  fleet_ca_cert="${FLEET_CA_CERT:-$(prompt "Internal CA certificate path" "$fleet_ca_cert")}"

  terminal_ca_cert="$(get_env_value "$root_env" "FLEET_TERMINAL_CA_CERT")"
  if [ -z "$terminal_ca_cert" ] && sudo_cmd test -f /etc/fleet-pki/terminal-ca.crt; then
    terminal_ca_cert="/etc/fleet-pki/terminal-ca.crt"
  fi
  [ -n "$terminal_ca_cert" ] || terminal_ca_cert="$fleet_ca_cert"

  install_nginx="false"
  if [ -n "${INSTALL_NGINX:-}" ]; then
    case "$(printf '%s' "$INSTALL_NGINX" | tr '[:upper:]' '[:lower:]')" in
      y|yes|true|1) install_nginx="true" ;;
      n|no|false|0) install_nginx="false" ;;
      *) err "INSTALL_NGINX must be yes/no, true/false, or 1/0" ;;
    esac
  elif confirm "Install and configure nginx as the HTTPS reverse proxy?" "n"; then
    install_nginx="true"
  else
    warn "nginx setup skipped; you must configure a reverse proxy before attaching agents."
  fi

  say ""
  say "Installation endpoint summary:"
  say "  Application URL: $server_url"
  say "  Server IP:       $fleet_server_ip"
  say "  Internal CA:     $fleet_ca_cert"
  if [ "$install_nginx" = "true" ]; then
    say "  Reverse proxy:   nginx (installer managed)"
  else
    say "  Reverse proxy:   externally managed"
  fi
  say ""

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
  set_env_value "$root_env" "FLEET_HOSTNAME" "$application_host"
  set_env_value "$root_env" "FLEET_SERVER_IP" "$fleet_server_ip"
  set_env_value "$root_env" "FLEET_CA_CERT" "$fleet_ca_cert"
  set_env_value "$root_env" "FLEET_TERMINAL_CA_CERT" "$terminal_ca_cert"
  set_env_value "$root_env" "AGENT_TOKEN" "$final_agent_token"
  set_env_value "$root_env" "TERM_TOKEN" "$final_terminal_token"
  set_env_value "$root_env" "TERM_LISTEN" "auto:18080"

  prepare_https "$server_url" "$fleet_server_ip" "$fleet_ca_cert" "$install_nginx"
  terminal_ca_b64="$(sudo_cmd base64 "$terminal_ca_cert" | tr -d '\r\n')"
  set_env_value "$docker_env" "AGENT_TERMINAL_TLS_CA_B64" "$terminal_ca_b64"

  chmod 600 "$docker_env" "$root_env"

  write_inventory "$deploy_hosts" "$ansible_user"

  info "Starting server with Docker Compose"
  (
    cd "$APP_DIR/deploy/docker"
    docker_compose up -d db
    sync_postgres_password "$postgres_password"
    docker_compose up -d --build --remove-orphans
  )
  server_ready="true"
  if ! wait_for_health "$server_url" "$fleet_ca_cert"; then
    server_ready="false"
    warn "Agent deployment is deferred until $server_url is reachable with a trusted certificate."
  fi

  if [ -n "$deploy_hosts" ]; then
    if [ "$server_ready" != "true" ]; then
      warn "Skipped agent deployment. Finish the reverse proxy setup, then run: cd $APP_DIR && ./add-host.sh"
    elif confirm "Build and deploy fleet-agent to listed hosts now?" "y"; then
      info "Deploying agents with add-host.sh"
      (cd "$APP_DIR" && ATTACH_HOSTS="$deploy_hosts" ANSIBLE_USER="$ansible_user" FLEET_SERVER_IP="$fleet_server_ip" FLEET_CA_CERT="$fleet_ca_cert" ./add-host.sh)
    else
      warn "Skipped agent deploy. You can run it later:"
      say "  cd $APP_DIR && ./add-host.sh"
    fi
  fi

  say ""
  say "Install complete."
  if [ "$server_ready" = "true" ]; then
    say "Status: ready"
    say "Open: $server_url/"
  else
    say "Status: waiting for reverse proxy configuration"
    say "Expected URL: $server_url/"
    say "Proxy upstream: http://127.0.0.1:18000"
  fi
  say "Login: $bootstrap_user"
  say "Password: $bootstrap_password_display"
  say ""
  say "Config files:"
  say "  $docker_env"
  say "  $root_env"
  say "  CA certificate: $(dirname "$fleet_ca_cert")/$(basename "$fleet_ca_cert")"
  say "  Server certificate: $(dirname "$fleet_ca_cert")/fleet-server.crt"
  say "  Server private key: $(dirname "$fleet_ca_cert")/fleet-server.key"
  [ -n "$deploy_hosts" ] && say "  $APP_DIR/hosts"
}

main "$@"
