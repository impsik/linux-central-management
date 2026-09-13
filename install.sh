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
    elif ! sudo -v; then
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
  git clone --branch "$INSTALL_REF" "$REPO_URL" "$INSTALL_DIR"
  APP_DIR="$INSTALL_DIR"
}

update_existing_checkout() {
  info "Checking for updates in: $APP_DIR"
  if ! git -C "$APP_DIR" diff --quiet || ! git -C "$APP_DIR" diff --cached --quiet; then
    err "Tracked local changes found in $APP_DIR. Commit or stash them before updating."
  fi

  previous_head="$(git -C "$APP_DIR" rev-parse HEAD)"
  git -C "$APP_DIR" fetch origin --prune
  git -C "$APP_DIR" checkout "$INSTALL_REF"
  git -C "$APP_DIR" pull --ff-only origin "$INSTALL_REF"
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
}

main() {
  say "Linux Central Management installer"
  say "----------------------------------"

  advanced="${INSTALL_ADVANCED:-false}"
  check_only="${INSTALL_CHECK_ONLY:-false}"
  for option in "$@"; do
    case "$option" in
      --advanced) advanced="true" ;;
      --check) check_only="true" ;;
      --help|-h)
        say "Usage: sh install.sh [--check] [--advanced]"
        say "  --check     Run preflight only; do not install or write configuration"
        say "  --advanced  Include CA/IP, token rotation, terminal and initial agent options"
        return 0 ;;
      *) err "Unknown option: $option. Run sh install.sh --help." ;;
    esac
  done
  export INSTALL_ADVANCED="$advanced" INSTALL_CHECK_ONLY="$check_only"
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

  install_packages
  ensure_repo
  cd "$APP_DIR"
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
    if advanced_confirm "Enable browser terminal proxy token now? (higher risk)" "n"; then
      terminal_token="$(random_hex 32)"
    fi
  elif advanced_confirm "Browser terminal proxy token already exists. Rotate it now? Existing agents must be redeployed if rotated." "n"; then
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
  if [ "$advanced" = "true" ] && [ -z "$deploy_hosts" ]; then
    deploy_hosts="$(prompt "Managed hosts to deploy agent to now (space/comma separated, blank to skip)" "")"
  fi
  ansible_user=""
  if [ -n "$deploy_hosts" ]; then
    ansible_user="${ANSIBLE_USER:-$(prompt "SSH username for managed hosts" "$(id -un 2>/dev/null || printf ubuntu)")}"
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
  set_env_value "$root_env" "INSTALL_NGINX" "$install_nginx"
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
  health_attempts=60
  # An external proxy may still need configuration; return the setup instructions promptly.
  [ "$install_nginx" = "true" ] || health_attempts=1
  if ! wait_for_health "$server_url" "$fleet_ca_cert" "$health_attempts"; then
    server_ready="false"
    warn "Agent deployment is deferred until $server_url is reachable with a trusted certificate."
  fi

  if [ -n "$deploy_hosts" ]; then
    if [ "$server_ready" != "true" ]; then
      warn "Skipped agent deployment. Finish the reverse proxy setup, then run: cd $APP_DIR && ./add-host.sh"
    elif advanced_confirm "Build and deploy fleet-agent to listed hosts now?" "y"; then
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
  say "Next: sign in, complete MFA setup, then follow Connect your first Linux host."
  say "Trust this CA on your browser machine: $fleet_ca_cert"
  say "To add a host later: cd $APP_DIR && ./add-host.sh"
  say "Advanced setup remains available with: ./install.sh --advanced"
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
  return 0
}

main "$@"
