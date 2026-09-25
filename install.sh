#!/bin/sh
set -eu

REPO_URL="${REPO_URL:-https://github.com/impsik/linux-central-management.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/linux-central-management}"
INSTALL_REF_WAS_SET="${INSTALL_REF:+true}"
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
is_tty() { ( : < /dev/tty ) 2>/dev/null; }

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
    y|yes|true|1) return 0 ;;
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
    ip="$(hostname -I 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {print $i; exit}}')"
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

advanced_confirm() {
  [ "$advanced" = "true" ] && confirm "$@"
}

preflight_fail() {
  warn "$*"
  preflight_errors=$((preflight_errors + 1))
}

port_in_use() {
  ss -H -ltn | awk -v port=":$1" '$4 ~ (port "$") {found=1} END {exit !found}'
}

port_owned_by_nginx() {
  sudo_cmd ss -H -ltnp | awk -v port=":$1" '
    $4 ~ (port "$") {found=1; if ($0 !~ /"nginx"/) other=1}
    END {exit !(found && !other)}'
}

systemd_running() {
  case "$(systemctl show --property=SystemState --value 2>/dev/null)" in
    running|degraded|starting) return 0 ;;
    *) return 1 ;;
  esac
}

preflight() {
  info "Preflight: checking this admin node before making changes"
  preflight_errors=0
  [ "$(uname -s)" = "Linux" ] || preflight_fail "Linux is required. Run the installer on a Linux admin node."
  if [ -r /etc/os-release ]; then
    info "Operating system: $(. /etc/os-release; printf '%s' "${PRETTY_NAME:-Linux}")"
  fi
  if [ "$(id -u)" -ne 0 ]; then
    if ! have sudo; then
      preflight_fail "sudo is missing. Install sudo or run the installer as root."
    elif ! { sudo -n true 2>/dev/null || sudo -v; }; then
      preflight_fail "Cannot obtain sudo privileges. Ask your administrator for sudo access, then rerun."
    fi
  fi
  if ! have systemctl || ! systemd_running; then
    preflight_fail "A running systemd host is required. Use a Linux server or VM, not a container without systemd."
  fi
  for tool in curl timeout getent ss; do
    have "$tool" || preflight_fail "Missing $tool. Install curl, coreutils, libc utilities and iproute2 (iproute on RPM systems), then rerun."
  done
  if ! have apt-get; then
    for tool in git python3 openssl docker ansible go; do
      have "$tool" || preflight_fail "Missing $tool. Follow README > Red Hat / Rocky Linux / AlmaLinux preparation, then rerun."
    done
    if have docker; then
      if ! sudo_cmd docker compose version >/dev/null 2>&1 && ! have docker-compose; then
        preflight_fail "Docker Compose is missing. Install the Docker Compose plugin, then rerun."
      fi
      sudo_cmd docker info >/dev/null 2>&1 || preflight_fail "Docker is not available. Start it with sudo systemctl enable --now docker, then rerun."
    fi
    if [ "$install_nginx" = "true" ] && ! have nginx; then
      preflight_fail "nginx is missing. Install nginx first or choose the existing reverse proxy option (INSTALL_NGINX=no)."
    fi
    if [ "$install_nginx" = "true" ] && have nginx; then
      default_servers="$(sudo_cmd nginx -T 2>/dev/null | awk '/^# configuration file / {source=$0} /listen.*default_server/ {if (source !~ /\/fleet[.:]/) print source}')"
      if [ -n "$default_servers" ]; then
        preflight_fail "nginx already has a non-Fleet default server. Use INSTALL_NGINX=no and configure the existing proxy, or remove its conflicting default listener before rerunning."
      fi
    fi
    have update-ca-trust || preflight_fail "update-ca-trust is missing. Install ca-certificates before continuing."
  else
    info "APT prerequisites will be installed after preflight passes"
  fi
  case "$fleet_server_ip" in
    127.*|0.0.0.0) preflight_fail "No reachable admin-node IPv4 address detected. Rerun with FLEET_SERVER_IP set to the address agents will use." ;;
  esac
  case "$fleet_ca_cert" in
    /*.crt) ;;
    *) preflight_fail "FLEET_CA_CERT must be an absolute path ending in .crt." ;;
  esac
  if [ -f "$fleet_ca_cert" ] && ! sudo_cmd test -f "${fleet_ca_cert%.crt}.key"; then
    preflight_fail "The existing CA has no matching private key (${fleet_ca_cert%.crt}.key). Restore the key before rerunning."
  fi
  if [ -d "$APP_DIR/.git" ] && have git; then
    if ! git -C "$APP_DIR" diff --quiet || ! git -C "$APP_DIR" diff --cached --quiet; then
      preflight_fail "Tracked changes exist in $APP_DIR. Commit or stash them before installation; preflight has not changed them."
    fi
  fi
  if have ss; then
    if [ "$install_nginx" = "true" ]; then
      for port in 80 443; do
        if port_in_use "$port" && { ! systemctl is-active --quiet nginx || ! port_owned_by_nginx "$port"; }; then
          preflight_fail "Port $port is already occupied. Stop the conflicting service or use INSTALL_NGINX=no for your existing proxy."
        fi
      done
    fi
    # An existing installation owns its upstream port; fresh installs must not take it over.
    if [ "$docker_env_existing" != "true" ] && port_in_use 18000; then
      preflight_fail "Port 18000 is already occupied. Free the application upstream port before installing."
    fi
  fi
  if have getent && have timeout; then
    resolved_ips="$(timeout 10 getent ahostsv4 "$application_host" | awk '{print $1}' | sort -u)" || resolved_ips=""
    if [ -z "$resolved_ips" ]; then
      warn "DNS: $application_host does not resolve yet. Setup will add a local hosts-file fallback; configure DNS or a hosts entry on your browser machine too."
    elif ! printf '%s\n' "$resolved_ips" | grep -Fxq "$fleet_server_ip"; then
      preflight_fail "DNS: $application_host resolves to $resolved_ips, not $fleet_server_ip. Correct DNS or FLEET_SERVER_IP, then rerun."
    else
      info "DNS: $application_host resolves to $fleet_server_ip"
    fi
  fi
  if have timeout && have git; then
    if ! GIT_TERMINAL_PROMPT=0 timeout 20 git ls-remote --exit-code "$REPO_URL" "$INSTALL_REF" >/dev/null 2>&1; then
      preflight_fail "Cannot reach repository/ref $INSTALL_REF. Check REPO_URL, network access and Git credentials, then rerun."
    else
      info "Git repository and installation ref are reachable"
    fi
  elif have curl; then
    case "$REPO_URL" in
      https://*)
        curl -fsSL --connect-timeout 5 --max-time 20 "$REPO_URL/info/refs?service=git-upload-pack" >/dev/null 2>&1 \
          || preflight_fail "Cannot reach the Git repository. Check network access and REPO_URL, then rerun." ;;
      *) preflight_fail "Install git to verify this repository before continuing." ;;
    esac
  fi
  if have curl; then
    registry_status="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 https://registry-1.docker.io/v2/ 2>/dev/null)" || registry_status=""
    case "$registry_status" in
      200|401) info "Docker Hub registry is reachable" ;;
      *) preflight_fail "Cannot reach Docker Hub over HTTPS. Check DNS, proxy and firewall settings before rerunning." ;;
    esac
  fi
  [ "$preflight_errors" -eq 0 ] || err "Preflight found $preflight_errors problem(s). Resolve the messages above and rerun the same command. No installation changes were made."
  info "Preflight passed. Package-repository access will be checked when installing dependencies."
}

install_packages() {
  if ! have apt-get; then
    warn "apt-get not found. Please install: git curl ca-certificates docker docker-compose plugin python3 openssl ansible-core golang-go"
    return
  fi

  info "Installing OS packages"
  run_logged "Updating package indexes" sudo_cmd apt-get update

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
  run_logged "Installing required packages" sudo_cmd apt-get install -y git curl openssh-client ca-certificates openssl python3 docker.io "$ansible_pkg" golang-go $compose_pkg

  if have systemctl; then
    sudo_cmd systemctl enable --now docker >/dev/null 2>&1 || true
  fi
}

ensure_repo() {
  if [ -f "server/app/main.py" ] && [ -f "deploy/docker/docker-compose.yml" ]; then
    APP_DIR="$(pwd)"
    update_existing_checkout
    return
  fi

  if [ -d "$INSTALL_DIR/.git" ]; then
    APP_DIR="$INSTALL_DIR"
    update_existing_checkout
    return
  fi

  info "Cloning $REPO_URL to $INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  run_logged "Downloading application code" git clone --branch "$INSTALL_REF" "$REPO_URL" "$INSTALL_DIR"
  APP_DIR="$INSTALL_DIR"
}

update_existing_checkout() {
  info "Checking for updates in: $APP_DIR"
  if ! git -C "$APP_DIR" diff --quiet || ! git -C "$APP_DIR" diff --cached --quiet; then
    err "Tracked local changes found in $APP_DIR. Commit or stash them before updating."
  fi

  previous_head="$(git -C "$APP_DIR" rev-parse HEAD)"
  run_logged "Checking repository updates" git -C "$APP_DIR" fetch origin --prune
  run_logged "Selecting installation branch" git -C "$APP_DIR" checkout "$INSTALL_REF"
  run_logged "Updating application code" git -C "$APP_DIR" pull --ff-only origin "$INSTALL_REF"
  current_head="$(git -C "$APP_DIR" rev-parse HEAD)"

  if [ "$previous_head" = "$current_head" ]; then
    info "Application checkout is already up to date"
    return
  fi

  info "Updated application checkout: $previous_head -> $current_head"
  if [ "${FLEET_INSTALL_REEXEC:-0}" != "1" ]; then
    info "Restarting with the updated installer"
    FLEET_INSTALL_REEXEC=1 exec "$APP_DIR/install.sh" "$@"
  fi
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

write_inventory() {
  hosts_input="$1"
  inventory_user="$2"
  hosts_file="$APP_DIR/hosts"
  inventory_file="$APP_DIR/ansible/inventory.yml"
  mkdir -p "$APP_DIR/ansible"
  touch "$hosts_file"
  if [ ! -f "$inventory_file" ]; then
    printf 'all:\n  hosts:\n' > "$inventory_file"
  fi
  for inventory_host in $(printf '%s' "$hosts_input" | tr ',;' '  '); do
    case "$inventory_host" in [!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) err "Invalid managed host: $inventory_host" ;; esac
    case "$inventory_user" in -*|*[!A-Za-z0-9_.-]*) err "Invalid SSH username" ;; esac
    if ! awk -v host="$inventory_host" '$1 == host {found=1} END {exit !found}' "$hosts_file"; then
      if [ -n "$inventory_user" ]; then
        printf '%s ansible_user=%s\n' "$inventory_host" "$inventory_user" >> "$hosts_file"
      else
        printf '%s\n' "$inventory_host" >> "$hosts_file"
      fi
    fi
    if ! awk -v host="$inventory_host:" '$1 == host {found=1} END {exit !found}' "$inventory_file"; then
      if [ -n "$inventory_user" ]; then
        printf '    %s:\n      ansible_user: %s\n' "$inventory_host" "$inventory_user" >> "$inventory_file"
      else
        printf '    %s: {}\n' "$inventory_host" >> "$inventory_file"
      fi
    fi
  done
}

should_deploy_agents() {
  [ "$advanced" != "true" ] || confirm "Build and deploy fleet-agent to listed hosts now?" "y"
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
  attempts="${3:-60}"
  i=0
  while [ "$i" -lt "$attempts" ]; do
    if [ -n "$ca_cert" ]; then
      health_ok="$(curl --connect-timeout 5 --max-time 10 -fsS --cacert "$ca_cert" "$url/health" 2>/dev/null || true)"
    else
      health_ok="$(curl --connect-timeout 5 --max-time 10 -fsS "$url/health" 2>/dev/null || true)"
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

prepare_https() (
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
  trap 'rm -rf "$work_dir"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' HUP TERM

  sudo_cmd mkdir -p "$pki_dir"
  sudo_cmd chmod 755 "$pki_dir"
  if ! sudo_cmd test -f "$ca_cert"; then
    info "Creating the fleet internal CA"
    run_logged "Creating internal CA" sudo_cmd openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
      -keyout "$ca_key" -out "$ca_cert" -subj '/CN=Fleet Internal CA' \
      -addext 'basicConstraints=critical,CA:TRUE' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign'
    sudo_cmd chmod 600 "$ca_key"
    sudo_cmd chmod 644 "$ca_cert"
  fi
  sudo_cmd test -f "$ca_key" || err "CA private key is required to issue the server certificate: $ca_key"

  if have update-ca-certificates; then
    sudo_cmd install -m 0644 "$ca_cert" /usr/local/share/ca-certificates/fleet-internal-ca.crt
    sudo_cmd update-ca-certificates
  else
    sudo_cmd install -m 0644 "$ca_cert" /etc/pki/ca-trust/source/anchors/fleet-internal-ca.crt
    sudo_cmd update-ca-trust extract
  fi
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
  run_logged "Creating server certificate request" sudo_cmd openssl req -new -newkey rsa:3072 -nodes \
    -keyout "$pki_dir/fleet-server.key" -out "$work_dir/fleet-server.csr" \
    -subj "/CN=$server_host"
  run_logged "Signing server certificate" sudo_cmd openssl x509 -req -sha256 -days 397 \
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
    run_logged "Installing nginx" sudo_cmd apt-get install -y nginx
  elif ! have nginx; then
    err "nginx is not installed and apt-get is unavailable"
  fi
  if have apt-get; then
    sudo_cmd mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
  else
    sudo_cmd mkdir -p /etc/nginx/conf.d
  fi

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
  if have apt-get; then
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
  else
    sudo_cmd install -m 0644 "$work_dir/nginx-fleet" /etc/nginx/conf.d/fleet.conf
  fi
  sudo_cmd nginx -t
  sudo_cmd systemctl enable --now nginx
  sudo_cmd systemctl reload nginx
)

init_install_log() {
  if [ -z "${FLEET_INSTALL_LOG:-}" ]; then
    log_dir="$APP_DIR.install-logs"
    (umask 077; mkdir -p "$log_dir")
    FLEET_INSTALL_LOG="$(mktemp "$log_dir/install-XXXXXXXX.log")"
  fi
  chmod 600 "$FLEET_INSTALL_LOG"
  export FLEET_INSTALL_LOG
  info "Detailed installation log: $FLEET_INSTALL_LOG"
}

run_logged() (
  # A subshell keeps log bookkeeping out of callers' shell variables. Calling
  # commands directly preserves errexit, including inside shell functions.
  log_label="$1"
  shift
  if [ -z "${FLEET_INSTALL_LOG:-}" ]; then
    "$@"
    exit
  fi
  info "$log_label..."
  printf '\n--- %s ---\n' "$log_label" >> "$FLEET_INSTALL_LOG"
  log_first_line=$(( $(wc -l < "$FLEET_INSTALL_LOG") + 1 ))
  trap '
    log_status=$?
    if [ "$log_status" -eq 0 ]; then
      info "$log_label: done"
    else
      warn "$log_label: failed (exit $log_status)"
      sed -n "${log_first_line},\$p" "$FLEET_INSTALL_LOG" | tail -n 25 >&2
      warn "Full log: $FLEET_INSTALL_LOG"
    fi
    exit "$log_status"
  ' EXIT
  trap 'exit 130' INT
  trap 'exit 143' HUP TERM
  "$@" >> "$FLEET_INSTALL_LOG" 2>&1
)

record_install_stage() {
  set_env_value "$resume_file" "STAGE" "$1"
  info "Installation stage: $1"
}

installation_fingerprint() (
  # Include local changes and saved configuration, without saving their contents.
  cd "$APP_DIR"
  fingerprint_work="$(mktemp -d)"
  trap 'rm -rf "$fingerprint_work"' EXIT
  git ls-files --cached --others --exclude-standard -z -- .dockerignore install.sh agent server deploy scripts > "$fingerprint_work/files" || exit 1
  xargs -0 sha256sum < "$fingerprint_work/files" > "$fingerprint_work/hashes" || exit 1
  sha256sum "$root_env" "$docker_env" >> "$fingerprint_work/hashes" || exit 1
  sha256sum "$fingerprint_work/hashes" | awk '{print $1}'
)

start_server_stack() {
  stack_fingerprint="$(installation_fingerprint)"
  if [ "$resume" = "true" ] &&
     [ "$(get_env_value "$resume_file" STACK_FINGERPRINT)" = "$stack_fingerprint" ] &&
     wait_for_health "$server_url" "$fleet_ca_cert" 1; then
    info "Resuming: unchanged Master is healthy; skipping Docker rebuild"
    return
  fi
  record_install_stage "server-start"
  info "Starting server with Docker Compose"
  (
    cd "$APP_DIR/deploy/docker"
    run_logged "Starting database" docker_compose up -d db
    sync_postgres_password "$postgres_password"
    run_logged "Building and starting application" docker_compose up -d --build --remove-orphans
  )
  set_env_value "$resume_file" "STACK_FINGERPRINT" "$stack_fingerprint"
}

install_exit_hint() {
  install_exit_status=$?
  if [ "$install_exit_status" -ne 0 ] && [ -f "$resume_file" ]; then
    warn "Installation stopped during: $(get_env_value "$resume_file" STAGE)"
    warn "After correcting the problem, continue with: $APP_DIR/install.sh --resume"
  fi
}

attach_hosts_with_recovery() {
  node_attach_deferred="false"
  while :; do
    record_install_stage "node-attach"
    info "Deploying agents with add-host.sh"
    # Run a separate script: testing its exit status must not disable errexit
    # inside the deployment workflow.
    if (cd "$APP_DIR" && ATTACH_HOSTS="$deploy_hosts" ANSIBLE_USER="$ansible_user" FLEET_SERVER_IP="$fleet_server_ip" FLEET_CA_CERT="$fleet_ca_cert" ./add-host.sh); then
      info "Node attachment completed"
      return 0
    else
      attach_status=$?
    fi
    case "$attach_status" in 130|143) return "$attach_status" ;; esac
    warn "Node attachment failed (exit $attach_status). The Master remains installed."
    is_tty || return "$attach_status"
    while :; do
      say "  1) Retry after correcting the problem"
      say "  2) Change node address or SSH username"
      say "  3) Add nodes later"
      recovery_choice="$(prompt 'Next action' '3')"
      case "$recovery_choice" in
        1) break ;;
        2)
          deploy_hosts="$(prompt 'Managed host(s), space/comma separated' "$deploy_hosts")"
          ansible_user="$(prompt 'SSH username' "$ansible_user")"
          set_env_value "$resume_file" ATTACH_HOSTS "$deploy_hosts"
          set_env_value "$resume_file" ANSIBLE_USER "$ansible_user"
          break ;;
        3)
          node_attach_deferred="true"
          record_install_stage "node-attach-deferred"
          warn "Node attachment deferred. Continue later with: $APP_DIR/install.sh --resume"
          return 0 ;;
        *) warn "Choose 1, 2 or 3." ;;
      esac
    done
  done
}

update_existing_agents() (
  case "${UPDATE_AGENTS:-true}" in
    false|no|0) info "Existing agent updates skipped (UPDATE_AGENTS=false)"; return 0 ;;
    true|yes|1) ;;
    *) warn "UPDATE_AGENTS must be true or false"; return 1 ;;
  esac
  record_install_stage "agent-update"
  update_work="$(mktemp -d)" || return 1
  trap 'rm -rf "$update_work"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' HUP TERM
  cd "$APP_DIR/deploy/docker" || return 1
  # Read registered hosts, including offline nodes, so failures stay visible.
  # Inventory files alone do not include hosts joined through enrollment.
  docker_compose exec -T server python -c '
import json
from sqlalchemy import select
from app.db import SessionLocal
from app.models import Host
with SessionLocal() as db:
    print(json.dumps([dict(row._mapping) for row in db.execute(
        select(Host.agent_id, Host.hostname, Host.fqdn, Host.ip_address).order_by(Host.agent_id))]))
' > "$update_work/hosts.json" || return 1
  update_count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$update_work/hosts.json")" || return 1
  if [ "$update_count" = 0 ]; then
    info "No registered agents to update"
    return 0
  fi
  for update_arch in amd64 arm64; do
    docker_compose exec -T server cat "/app/enrollment-agents/fleet-agent-$update_arch" > "$update_work/fleet-agent-$update_arch" || return 1
  done
  # Reuse saved per-host SSH usernames, ports, keys and inventory aliases.
  set --
  [ ! -s "$APP_DIR/hosts" ] || set -- "$@" -i "$APP_DIR/hosts"
  [ ! -s "$APP_DIR/ansible/inventory.yml" ] || set -- "$@" -i "$APP_DIR/ansible/inventory.yml"
  if [ "$#" -gt 0 ]; then
    ansible-inventory "$@" --list > "$update_work/inventory.json" || return 1
    set -- --inventory "$update_work/inventory.json"
  fi
  update_identity="${FLEET_SSH_IDENTITY:-$(get_env_value "$root_env" FLEET_SSH_IDENTITY)}"
  if [ -n "$update_identity" ]; then set -- "$@" --identity "$update_identity"; fi
  update_user="${ANSIBLE_USER:-$(get_env_value "$root_env" ANSIBLE_USER)}"
  update_user="${update_user:-${SUDO_USER:-$(id -un)}}"
  update_report="$APP_DIR/agent-update-results.json"
  # The report contains host diagnostics, never credentials or configuration.
  umask 077
  python3 "$APP_DIR/scripts/update-agents.py" --hosts "$update_work/hosts.json" \
    --artifacts "$update_work" --ssh-user "$update_user" \
    --workers "${AGENT_UPDATE_WORKERS:-4}" --report "$update_report" "$@"
)

main() {
  say "Linux Central Management installer"
  say "----------------------------------"

  advanced="${INSTALL_ADVANCED:-false}"
  check_only="${INSTALL_CHECK_ONLY:-false}"
  resume="${INSTALL_RESUME:-false}"
  for option in "$@"; do
    case "$option" in
      --advanced) advanced="true" ;;
      --check) check_only="true" ;;
      --resume) resume="true" ;;
      --help|-h)
        say "Usage: sh install.sh [--check] [--advanced] [--resume]"
        say "  --check     Run preflight only; do not install or write configuration"
        say "  --advanced  Include CA/IP, token rotation and initial agent options"
        say "  --resume    Reuse saved answers/ref and skip rebuilding an unchanged healthy Master"
        say "  Existing agents are updated over SSH by default (UPDATE_AGENTS=false to skip)."
        return 0 ;;
      *) err "Unknown option: $option. Run sh install.sh --help." ;;
    esac
  done
  if [ "$resume" = "true" ]; then
    [ "$advanced" != "true" ] || err "Use --resume or --advanced separately; resume preserves existing credentials."
  fi
  export INSTALL_ADVANCED="$advanced" INSTALL_CHECK_ONLY="$check_only" INSTALL_RESUME="$resume"
  case "$INSTALL_DIR" in
    /*) ;;
    *) INSTALL_DIR="$(pwd)/$INSTALL_DIR" ;;
  esac
  APP_DIR="$INSTALL_DIR"
  if [ -f "server/app/main.py" ] && [ -f "deploy/docker/docker-compose.yml" ]; then
    APP_DIR="$(pwd)"
  fi
  docker_env="$APP_DIR/deploy/docker/.env"
  root_env="$APP_DIR/.env"
  resume_file="$APP_DIR.install-progress"
  if [ "$resume" = "true" ]; then
    [ -f "$resume_file" ] || err "No saved installation progress. Run ./install.sh normally first."
    info "Resuming installation from: $(get_env_value "$resume_file" STAGE)"
    if [ -z "$INSTALL_REF_WAS_SET" ]; then
      saved_ref="$(get_env_value "$resume_file" INSTALL_REF)"
      INSTALL_REF="${saved_ref:-$INSTALL_REF}"
    fi
    FLEET_HOSTNAME="${FLEET_HOSTNAME:-$(get_env_value "$resume_file" FLEET_HOSTNAME)}"
    FLEET_SERVER_IP="${FLEET_SERVER_IP:-$(get_env_value "$resume_file" FLEET_SERVER_IP)}"
    FLEET_CA_CERT="${FLEET_CA_CERT:-$(get_env_value "$resume_file" FLEET_CA_CERT)}"
    INSTALL_NGINX="${INSTALL_NGINX:-$(get_env_value "$resume_file" INSTALL_NGINX)}"
    ATTACH_HOSTS="${ATTACH_HOSTS-$(get_env_value "$resume_file" ATTACH_HOSTS)}"
    ANSIBLE_USER="${ANSIBLE_USER:-$(get_env_value "$resume_file" ANSIBLE_USER)}"
  fi
  docker_env_existing="false"
  [ -f "$docker_env" ] && docker_env_existing="true"

  existing_url="$(get_env_value "$root_env" "SERVER_URL")"
  default_host="$(url_host "$existing_url")"
  [ -n "$default_host" ] || default_host="fleet.local"
  application_host="${FLEET_HOSTNAME:-$(prompt "Application hostname (without https:// or a path)" "$default_host")}"
  validate_hostname "$application_host"
  server_url="https://$application_host"

  fleet_server_ip="$(get_env_value "$root_env" "FLEET_SERVER_IP")"
  [ -n "$fleet_server_ip" ] || fleet_server_ip="$(primary_ip)"
  if [ "$advanced" = "true" ]; then
    fleet_server_ip="${FLEET_SERVER_IP:-$(prompt "Fleet server IPv4 address" "$fleet_server_ip")}"
  else
    fleet_server_ip="${FLEET_SERVER_IP:-$fleet_server_ip}"
  fi
  validate_ipv4 "$fleet_server_ip"

  fleet_ca_cert="$(get_env_value "$root_env" "FLEET_CA_CERT")"
  [ -n "$fleet_ca_cert" ] || fleet_ca_cert="/etc/fleet-pki/fleet-ca.crt"
  if [ "$advanced" = "true" ]; then
    fleet_ca_cert="${FLEET_CA_CERT:-$(prompt "Internal CA certificate path" "$fleet_ca_cert")}"
  else
    fleet_ca_cert="${FLEET_CA_CERT:-$fleet_ca_cert}"
  fi

  terminal_ca_cert="$(get_env_value "$root_env" "FLEET_TERMINAL_CA_CERT")"
  if [ -z "$terminal_ca_cert" ] && test -f /etc/fleet-pki/terminal-ca.crt; then
    terminal_ca_cert="/etc/fleet-pki/terminal-ca.crt"
  fi
  [ -n "$terminal_ca_cert" ] || terminal_ca_cert="$fleet_ca_cert"

  proxy_default="yes"
  if [ "$docker_env_existing" = "true" ]; then
    proxy_default="$(get_env_value "$root_env" "INSTALL_NGINX")"
    if [ -z "$proxy_default" ]; then
      proxy_default="no"
      if have systemctl && systemctl is-active --quiet nginx; then proxy_default="yes"; fi
    fi
  fi
  install_nginx="false"
  if [ -n "${INSTALL_NGINX:-}" ]; then
    case "$(printf '%s' "$INSTALL_NGINX" | tr '[:upper:]' '[:lower:]')" in
      y|yes|true|1) install_nginx="true" ;;
      n|no|false|0) install_nginx="false" ;;
      *) err "INSTALL_NGINX must be yes/no, true/false, or 1/0" ;;
    esac
  elif confirm "Let the installer configure HTTPS with nginx? (no = existing reverse proxy)" "$proxy_default"; then
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

  preflight
  if [ "$check_only" = "true" ]; then
    info "Check complete. Rerun without --check to install."
    return 0
  fi

  mkdir -p "$(dirname "$resume_file")"
  (umask 077; touch "$resume_file")
  chmod 600 "$resume_file"
  set_env_value "$resume_file" INSTALL_REF "$INSTALL_REF"
  set_env_value "$resume_file" FLEET_HOSTNAME "$application_host"
  set_env_value "$resume_file" FLEET_SERVER_IP "$fleet_server_ip"
  set_env_value "$resume_file" FLEET_CA_CERT "$fleet_ca_cert"
  set_env_value "$resume_file" INSTALL_NGINX "$install_nginx"
  trap install_exit_hint EXIT
  trap 'exit 130' INT
  trap 'exit 143' HUP TERM
  init_install_log
  record_install_stage "OS-packages"
  install_packages
  # Preserve validated endpoint answers if ensure_repo restarts the updated
  # installer. Environment overrides skip only these already answered prompts.
  export FLEET_HOSTNAME="$application_host" FLEET_SERVER_IP="$fleet_server_ip"
  export FLEET_CA_CERT="$fleet_ca_cert" INSTALL_NGINX="$install_nginx"
  export INSTALL_REF
  record_install_stage "checkout-update"
  ensure_repo
  cd "$APP_DIR"
  record_install_stage "configuration"
  docker_env="$APP_DIR/deploy/docker/.env"
  root_env="$APP_DIR/.env"
  umask 077
  [ -f "$docker_env" ] || cp "$APP_DIR/deploy/docker/env.example" "$docker_env"
  [ -f "$root_env" ] || cp "$APP_DIR/env.example" "$root_env"

  current_bootstrap_user="$(get_env_value "$docker_env" "BOOTSTRAP_USERNAME")"
  [ -n "$current_bootstrap_user" ] || current_bootstrap_user="admin"
  bootstrap_user="$current_bootstrap_user"
  if [ "$docker_env_existing" != "true" ] || [ "$advanced" = "true" ]; then
    bootstrap_user="$(prompt "Admin username" "$current_bootstrap_user")"
  fi

  current_bootstrap_password="$(get_env_value "$docker_env" "BOOTSTRAP_PASSWORD")"
  bootstrap_password_display=""
  if is_placeholder_value "$current_bootstrap_password"; then
    bootstrap_password="$(prompt_secret_or_generate "Bootstrap admin password" "$(random_password)")"
    bootstrap_password_display="$bootstrap_password"
  elif advanced_confirm "Bootstrap admin password already exists. Rotate it now?" "n"; then
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
  elif advanced_confirm "Agent shared token already exists. Rotate it now? Existing agents must be redeployed if rotated." "n"; then
    agent_token="$(random_hex 32)"
  else
    agent_token="$current_agent_token"
    info "Preserved existing AGENT_SHARED_TOKEN"
  fi

  current_mfa_key="$(get_env_value "$docker_env" "MFA_ENCRYPTION_KEY")"
  if is_placeholder_value "$current_mfa_key"; then
    mfa_key="$(fernet_key)"
  elif advanced_confirm "MFA encryption key already exists. Rotate it now? Existing MFA enrollments may need to be reset." "n"; then
    mfa_key="$(fernet_key)"
  else
    mfa_key="$current_mfa_key"
    info "Preserved existing MFA_ENCRYPTION_KEY"
  fi

  current_terminal_token="$(get_env_value "$docker_env" "AGENT_TERMINAL_TOKEN")"
  terminal_token=""
  if is_placeholder_value "$current_terminal_token"; then
    if [ "$resume" != "true" ] && confirm "Enable browser Console now? (yes/no)" "no"; then
      terminal_token="$(random_hex 32)"
    fi
  elif advanced_confirm "Browser terminal proxy token already exists. Rotate it now? Existing agents must be redeployed if rotated." "n"; then
    terminal_token="$(random_hex 32)"
  else
    terminal_token="$current_terminal_token"
    info "Console is already enabled; preserved existing AGENT_TERMINAL_TOKEN"
  fi

  current_postgres_password="$(get_env_value "$docker_env" "POSTGRES_PASSWORD")"
  current_database_url="$(get_env_value "$docker_env" "DATABASE_URL")"
  if [ "$docker_env_existing" = "true" ] && [ -z "$current_postgres_password" ] && [ -z "$current_database_url" ]; then
    postgres_password="fleet"
    warn "Existing Docker env has no POSTGRES_PASSWORD; preserving legacy database password. Rotate it before production/non-local use."
  elif is_placeholder_value "$current_postgres_password"; then
    postgres_password="$(random_hex 24)"
  elif advanced_confirm "Postgres password already exists. Rotate it now? Existing database volume may need manual migration if rotated." "n"; then
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

  deploy_hosts="${ATTACH_HOSTS:-}"
  if [ -z "$deploy_hosts" ] && { [ "$advanced" = "true" ] || [ "$docker_env_existing" = "false" ]; }; then
    deploy_hosts="$(prompt "First managed host(s) (space/comma separated, blank to add later)" "")"
  fi
  ansible_user=""
  if [ -n "$deploy_hosts" ]; then
    ansible_user="${ANSIBLE_USER:-$(prompt "SSH username for managed hosts" "$(id -un 2>/dev/null || printf ubuntu)")}"
  fi

  set_env_value "$resume_file" ATTACH_HOSTS "$deploy_hosts"
  set_env_value "$resume_file" ANSIBLE_USER "$ansible_user"

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
  set_env_value "$root_env" "INSTALL_NGINX" "$install_nginx"
  set_env_value "$root_env" "SERVER_URL" "$server_url"
  set_env_value "$root_env" "FLEET_HOSTNAME" "$application_host"
  set_env_value "$root_env" "FLEET_SERVER_IP" "$fleet_server_ip"
  set_env_value "$root_env" "FLEET_CA_CERT" "$fleet_ca_cert"
  set_env_value "$root_env" "FLEET_TERMINAL_CA_CERT" "$terminal_ca_cert"
  set_env_value "$root_env" "AGENT_TOKEN" "$final_agent_token"
  set_env_value "$root_env" "TERM_TOKEN" "$final_terminal_token"
  saved_ssh_user="${ANSIBLE_USER:-$ansible_user}"
  [ -z "$saved_ssh_user" ] || set_env_value "$root_env" "ANSIBLE_USER" "$saved_ssh_user"
  [ -z "${FLEET_SSH_IDENTITY:-}" ] || set_env_value "$root_env" "FLEET_SSH_IDENTITY" "$FLEET_SSH_IDENTITY"

  prepare_https "$server_url" "$fleet_server_ip" "$fleet_ca_cert" "$install_nginx"
  enrollment_pki_dir="$(dirname "$fleet_ca_cert")/enrollment"
  sudo_cmd mkdir -p "$enrollment_pki_dir"
  sudo_cmd chmod 700 "$enrollment_pki_dir"
  sudo_cmd install -m 0644 "$fleet_ca_cert" "$enrollment_pki_dir/master-ca.crt"
  sudo_cmd install -m 0644 "$terminal_ca_cert" "$enrollment_pki_dir/terminal-ca.crt"
  sudo_cmd install -m 0600 "${terminal_ca_cert%.crt}.key" "$enrollment_pki_dir/terminal-ca.key"
  set_env_value "$docker_env" FLEET_ENROLLMENT_PKI_DIR "$enrollment_pki_dir"
  set_env_value "$docker_env" FLEET_ENROLLMENT_MASTER_IP "$fleet_server_ip"
  terminal_ca_b64="$(sudo_cmd base64 "$terminal_ca_cert" | tr -d '\r\n')"
  set_env_value "$docker_env" "AGENT_TERMINAL_TLS_CA_B64" "$terminal_ca_b64"

  chmod 600 "$docker_env" "$root_env"

  write_inventory "$deploy_hosts" "$ansible_user"

  start_server_stack
  server_ready="true"
  health_attempts=60
  # An external proxy may still need configuration; return the setup instructions promptly.
  [ "$install_nginx" = "true" ] || health_attempts=1
  if ! wait_for_health "$server_url" "$fleet_ca_cert" "$health_attempts"; then
    server_ready="false"
    warn "Agent deployment is deferred until $server_url is reachable with a trusted certificate."
  fi

  node_attach_deferred="false"
  if [ -n "$deploy_hosts" ]; then
    if [ "$server_ready" != "true" ]; then
      warn "Skipped agent deployment. Finish the reverse proxy setup, then run: cd $APP_DIR && ./add-host.sh"
    elif should_deploy_agents; then
      attach_hosts_with_recovery
    else
      node_attach_deferred="true"
      warn "Skipped agent deploy. You can run it later:"
      say "  cd $APP_DIR && ./add-host.sh"
    fi
  fi

  agent_update_failed="false"
  if [ "$server_ready" = "true" ]; then
    info "Checking existing agents for updates"
    if update_existing_agents; then
      info "Existing agent update stage completed"
    else
      agent_update_failed="true"
      warn "Some agents could not be updated. Master remains installed; rerun ./install.sh --resume after resolving the reported errors."
      warn "Agent update results (when available): $APP_DIR/agent-update-results.json"
    fi
  fi

  say ""
  if [ "$agent_update_failed" = "true" ]; then
    record_install_stage "agent-update-pending"
  elif [ "$server_ready" = "true" ] && [ "$node_attach_deferred" = "true" ]; then
    record_install_stage "node-attach-deferred"
  elif [ "$server_ready" = "true" ]; then
    record_install_stage "complete"
  else
    record_install_stage "waiting-for-proxy"
  fi
  say "Master installation complete."
  if [ "$server_ready" = "true" ]; then
    if [ "$agent_update_failed" = "true" ]; then
      say "Status: Master ready; agent updates pending"
    elif [ "$node_attach_deferred" = "true" ]; then
      say "Status: Master ready; node attachment pending"
    else
      say "Status: ready"
    fi
    say "Open: $server_url/"
  else
    say "Status: waiting for reverse proxy configuration"
    say "Expected URL: $server_url/"
    say "Proxy upstream: http://127.0.0.1:18000"
  fi
  say "Next: sign in, complete MFA setup, then follow Connect your first Linux host."
  if [ -n "$final_terminal_token" ]; then
    say "Console: enabled on Master; managed hosts also need Console configured."
  else
    say "Console: disabled. Rerun ./install.sh to enable it later."
  fi
  say "Trust this CA on your browser machine: $fleet_ca_cert"
  say "To add a host later: cd $APP_DIR && ./add-host.sh"
  say "Advanced setup remains available with: ./install.sh --advanced"
  say "Login: $bootstrap_user"
  say "Password: $bootstrap_password_display"
  say ""
  say "Installation log: ${FLEET_INSTALL_LOG:-not enabled}"
  say "Config files:"
  say "  $docker_env"
  say "  $root_env"
  say "  CA certificate: $(dirname "$fleet_ca_cert")/$(basename "$fleet_ca_cert")"
  say "  Server certificate: $(dirname "$fleet_ca_cert")/fleet-server.crt"
  say "  Server private key: $(dirname "$fleet_ca_cert")/fleet-server.key"
  [ -n "$deploy_hosts" ] && say "  $APP_DIR/hosts"
  [ "$agent_update_failed" != "true" ] || return 1
  return 0
}

main "$@"
