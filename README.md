# Linux Central Management — Self-Hosted Linux Server and Patch Management

Linux Central Management is self-hosted, web-based Linux server management
software for system administrators managing multiple machines. Manage host
inventory, Linux patching, package updates, CVE vulnerability reports, systemd
services, user accounts, SSH keys, and Ansible automation from one dashboard.

Run the Python/FastAPI web application and PostgreSQL database on your own
admin node with Docker Compose. A Go `fleet-agent` systemd service runs on each
managed Linux host. The project includes Debian/Ubuntu (APT/dpkg) and
Red Hat-family (DNF/RPM) package-management paths; individual operations depend
on the host distribution and installed tools.

![Linux Central Management web dashboard for managing Linux servers](docs/screenshots/2.png)

## Common Use Cases

- **Linux fleet inventory:** find hosts by owner, label, operating system, or
  health status and inspect their installed packages and available updates.
- **Centralized patch management:** plan security-update campaigns with
  maintenance windows, rollout controls, and approvals for high-risk actions.
- **CVE vulnerability reporting:** review package and host vulnerability
  information alongside update availability.
- **Day-to-day server administration:** manage services, users, SSH access,
  firewall rules, and remote terminal sessions through the web interface.
- **Linux automation:** run Ansible playbooks and scheduled jobs across selected
  hosts, then inspect execution logs and audit history.

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Linux distribution support](#linux-distribution-support)
- [Requirements](#requirements)
- [Install the admin node](#install-the-admin-node)
- [Add more hosts](#add-more-hosts-later)
- [Update an existing installation](#update-an-existing-installation)
- [Non-interactive defaults](#non-interactive-defaults)
- [Important files](#important-files)
- [Security notes](#security-notes)
- [Documentation and development](#documentation-and-development)

## Features

### Fleet visibility

- host inventory, ownership, labels, saved views, filtering, and global search;
- online/offline state, operating-system details, uptime, CPU, memory, disk, and
  other host-health information;
- dashboard attention views for operational problems;
- CVE and package-update reporting;
- generated operational reports and backup-verification results.

### Host administration

- package inventory, package updates, security campaigns, and controlled
  full package upgrades;
- service status and start, stop, restart, enable, and disable operations;
- user-account, SSH-key, and sudo-access management;
- firewall inspection and management;
- browser terminal access to managed hosts;
- Ansible-backed actions across one or more selected hosts.

### Automation and reliability

- one-time and recurring cron jobs with explicit timezone information;
- maintenance-window and high-risk-action controls;
- persistent job queue with queued/running/stale/failed visibility;
- cancellation and requeue controls, retry information, and per-agent queue
  pressure signals;
- job details, stdout/stderr tails, downloadable logs, and failed-run views;
- audit history for administrative and scheduled actions.

### Access and security

- local accounts, Active Directory/LDAP, and OIDC authentication;
- role-based access control and host visibility scopes;
- MFA for privileged users;
- two-person approval for configured high-risk actions;
- per-agent tokens and HMAC-signed agent requests;
- HTTPS for the web UI and native TLS/WSS for browser terminal traffic;
- an internal CA workflow for server and agent terminal certificates.

## Architecture

- **Admin node:** web UI, API, PostgreSQL, Docker Compose, and optionally nginx.
- **Managed host:** `fleet-agent` systemd service. Managed hosts do not require
  nginx; the agent serves its terminal WSS endpoint natively when enabled.
- **Browser:** connects only to the admin node over HTTPS/WSS.
- **Agent:** connects to the admin API over HTTPS. The admin node connects to
  the selected agent's terminal endpoint over verified WSS.

## Linux Distribution Support

Linux Central Management includes package-management support for Ubuntu/Debian
and Red Hat-family Linux hosts. Installation requirements and security-data
sources differ between these families.

The **admin node** runs the web application and database. **Managed hosts** run
the `fleet-agent` service. Choose the installation instructions for the admin
node's operating system; managed hosts use their own package manager.

| Capability | Ubuntu / Debian family | Red Hat family |
|---|---|---|
| Package inventory | dpkg | RPM |
| Package installation and updates | APT | DNF, with YUM fallback |
| Admin-node prerequisites | Installed automatically by `install.sh` on APT-based systems | Must be installed manually before running `install.sh` |
| CVE data | Central synchronization uses Ubuntu OVAL data for focal, jammy, and noble; this does not provide equivalent Debian coverage | Agent CVE checks include a DNF/YUM `updateinfo` fallback, dependent on repository advisory metadata |
| Full package upgrade | `apt-get dist-upgrade` | `dnf upgrade` or `yum upgrade` |

Full package upgrades use the host's configured repositories. They do not
perform an operating-system release migration, such as Ubuntu 22.04 to 24.04
or RHEL 8 to 9.

Available operations depend on the distribution, configured repositories, and
installed tools.

## Requirements

Admin node:

- an Ubuntu, Debian, or Red Hat-family Linux server with the prerequisites
  described below;
- root or `sudo` access;
- outbound access to the Git repository and operating-system package sources;
- Docker Engine with Compose support. The installer installs Docker and other
  required packages where supported;
- a hostname for the application, for example `fleet.example.internal` or
  `fleet.local`, which clients and managed hosts can resolve to the admin node.

Managed hosts:

- SSH access from the admin node;
- root or `sudo` access for the initial agent installation;
- network access to the admin node's HTTPS endpoint;
- network access from the admin node to TCP port `18080` on managed hosts when
  browser terminal access is enabled.

For a larger environment, use internal DNS for the application hostname.
`/etc/hosts` works for testing, but every browser and managed host must resolve
the name consistently. The `.local` suffix may conflict with mDNS on some
networks.

## Install the Admin Node

Complete the preparation for your admin node's operating system, then follow
[Common Setup: SSH, Installer and First Login](#common-setup-ssh-installer-and-first-login).

### Ubuntu / Debian

On APT-based admin nodes, `install.sh` installs the required packages, including
Docker, an available Docker Compose package, Python, OpenSSL, Ansible, and Go.
Package availability depends on the operating-system version and configured
repositories. The installer also installs nginx when that option is selected.

Continue to [common setup](#common-setup-ssh-installer-and-first-login).
The DNF preparation below is for Red Hat-family admin nodes.

### Red Hat / Rocky Linux / AlmaLinux

On Red Hat, Rocky Linux, AlmaLinux, and other `dnf`-based systems, install the
required packages manually before running `install.sh`. The installer installs
OS packages automatically only on `apt`-based systems.

Remove Docker packages that conflict with Docker CE:

```bash
sudo dnf remove -y \
  docker \
  docker-client \
  docker-client-latest \
  docker-common \
  docker-latest \
  docker-latest-logrotate \
  docker-logrotate \
  docker-engine \
  podman \
  runc
```

Install the repository helper and add Docker's official repository:

```bash
sudo dnf install -y dnf-plugins-core

sudo dnf config-manager --add-repo \
  https://download.docker.com/linux/rhel/docker-ce.repo
```

Install the application prerequisites:

```bash
sudo dnf install -y \
  git \
  curl \
  ca-certificates \
  python3 \
  openssl \
  ansible-core \
  golang \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin

sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in after adding the current user to the `docker` group, or
start a new group-aware shell with `newgrp docker`. Confirm that Docker works
before continuing:

```bash
docker version
docker compose version
```

If you want the installer to configure nginx, install nginx on the admin node
before running `install.sh`: the installer cannot install it automatically on
systems without APT. Alternatively, choose `no` when asked to install and
configure nginx, then configure your existing reverse proxy using the
[reverse proxy instructions](#reverse-proxy-choices).

Continue to the common setup below.

### Common Setup: SSH, Installer and First Login

These steps apply after preparing either an Ubuntu/Debian or a Red Hat-family
admin node.

#### Run the installer

Run the installer on the server that will host the web UI:

```bash
curl -fsSL https://raw.githubusercontent.com/impsik/linux-central-management/main/install.sh | sh
```

The installer first checks the admin node before installing packages, updating
the checkout, or writing configuration. It checks Linux/systemd, root or sudo
access, required tools, conflicting ports, hostname resolution, the Git
repository/ref, and Docker Hub connectivity. On APT-based systems, missing
application prerequisites are installed after these checks pass; other systems
must be prepared manually. Package-source access is checked during dependency
installation.

To run only the preflight checks from a checkout:

```bash
./install.sh --check
```

For a downloaded installer, pass the option to `sh`:

```bash
curl -fsSL https://raw.githubusercontent.com/impsik/linux-central-management/main/install.sh | sh -s -- --check
```

A failed preflight explains how to resolve each problem. Rerun the same command
after fixing it. Missing DNS produces a warning because the installer supports
a local hosts-file fallback; a hostname resolving to a different IP blocks
installation. Configure DNS or a hosts entry on the browser machine as well.

After preflight passes, the installer prepares TLS, applies database migrations
and starts the application with Docker Compose.

#### Installer questions

The standard installation asks for three groups of settings:

1. **Application hostname** — without `https://` or a path; default `fleet.local`.
2. **HTTPS setup** — let the installer configure nginx (the default for new
   installations), or choose `no` to use an existing reverse proxy.
3. **Admin account** — username and password. A blank password generates a
   secure password, displayed once in the installation summary.

The server IPv4 address is detected automatically and the internal CA defaults
to `/etc/fleet-pki/fleet-ca.crt`. Use `FLEET_SERVER_IP` or `FLEET_CA_CERT` to
override these values. Review the endpoint summary before proceeding.

On an existing installation, the standard flow preserves configured passwords,
tokens and the MFA key. It does not prompt to rotate them. Browser terminal
access stays disabled on new installations, and agents can be added after
signing in. MFA enrollment for privileged accounts remains required by default.

For additional options:

```bash
./install.sh --advanced
```

Advanced mode includes server IP and CA-path questions, explicit secret-rotation
choices, browser terminal enablement, and optional initial agent deployment.
`ATTACH_HOSTS` and `ANSIBLE_USER` remain available for scripted deployments in
either mode. Rotating agent or terminal tokens requires redeploying affected
agents; rotating the MFA key can invalidate enrollments.

#### Connect your first host

After signing in and completing MFA enrollment, an empty fleet opens
**Connect your first Linux host** instead of an empty operations dashboard.

1. Enter the managed host's IPv4 address or hostname and its SSH username.
2. Select **Prepare install command**.
3. On the admin node, change to the installation directory and run the generated
   command. The default directory is `~/linux-central-management`.
4. Supply the SSH password in that shell if needed, or use an existing SSH key.
   The account needs sudo access on the managed host.
5. Watch registration, connection, OS information and package inventory arrive,
   then select **View packages and updates**.

The command runs the existing `add-host.sh` helper; the browser does not collect
SSH passwords or execute the installation. The progress view offers service,
DNS and certificate troubleshooting. Use the host's reported hostname/FQDN or
IP address when tracking a particular host.

**Open dashboard** leaves setup, and **Add a host** reopens it from the dashboard.
Existing fleets open the normal dashboard. Setup is available to administrators;
other users keep their usual views. Terminal access, AD/OIDC and automation
remain optional later configuration.

#### Reverse proxy choices

If nginx installation is accepted, the installer configures HTTPS and proxies
the application to:

```text
http://127.0.0.1:18000
```

If nginx installation is declined, the installer still creates the internal
CA and application certificate and prints the paths required by your reverse
proxy. The default paths are:

```text
CA certificate:     /etc/fleet-pki/fleet-ca.crt
Server certificate: /etc/fleet-pki/fleet-server.crt
Server private key: /etc/fleet-pki/fleet-server.key
Upstream:           http://127.0.0.1:18000
```

Configure HTTPS in the chosen reverse proxy, then run `./add-host.sh` after the
health endpoint is reachable with a valid certificate.

#### Open the application

After installation, open the hostname selected during setup:

```text
https://fleet.example.internal/
```

The installer uses an internal CA by default. Import
`/etc/fleet-pki/fleet-ca.crt` into the browser or operating-system trust store
to remove certificate warnings. Trust the CA certificate, not an individual
server certificate, so server certificates can be renewed without updating
every client.

Log in with the bootstrap account. Active Directory/LDAP and OIDC can then be
configured under **Settings**.

![Active Directory settings](docs/screenshots/AD-settings.png)

## Add More Hosts Later

Run this on the admin node:

```bash
cd ~/linux-central-management
./add-host.sh
```

The helper asks for the new host addresses and SSH credentials, then:

- updates `hosts` and `ansible/inventory.yml`;
- builds and installs `fleet-agent`;
- installs the internal CA on the managed host;
- ensures the application hostname resolves to the admin node when an IP
  fallback is configured;
- verifies HTTPS trust before starting the agent;
- when terminal access is enabled, issues an IP-SAN terminal certificate and
  configures the agent's native WSS listener on TCP port `18080`.

`add-host.sh` does not install nginx on managed hosts.

## Update an Existing Installation

Run the installed copy of the installer on the admin node:

```bash
cd ~/linux-central-management
./install.sh
```

The update process is the same whether `install.sh` is started inside the
repository or downloaded again with `curl`. For an existing checkout it:

1. checks that tracked files have no local modifications;
2. runs `git fetch origin --prune`;
3. checks out the configured ref (`main` by default);
4. runs `git pull --ff-only origin main`;
5. when new commits were downloaded, restarts once using the updated
   `install.sh`;
6. preserves existing configuration and secrets; rotation is offered only in
   advanced mode;
7. rebuilds and restarts the Docker Compose services.

If tracked files contain local changes, the installer stops before updating.
Review and commit or stash those changes, then rerun it. It never performs a
hard reset or silently overwrites local work.

To update from another directory, the download command is also supported:

```bash
curl -fsSL https://raw.githubusercontent.com/impsik/linux-central-management/main/install.sh | sh
```

Existing secrets and the internal CA are preserved unless rotation is
explicitly selected. Keeping the same CA allows application and agent terminal
certificates to be renewed without changing trust stores.

## Non-interactive Defaults

The installer is interactive when a terminal is available. Common values can
also be supplied through environment variables.

### Supported setup variables

- `FLEET_HOSTNAME` — application hostname without a scheme or path;
- `FLEET_SERVER_IP` — admin node IPv4 address;
- `FLEET_CA_CERT` — internal CA certificate path;
- `INSTALL_NGINX` — `yes` or `no`;
- `INSTALL_CHECK_ONLY` — `true` for preflight only (equivalent to `--check`);
- `INSTALL_ADVANCED` — `true` to include advanced questions;
- `ATTACH_HOSTS` — one or more initial managed-host IP addresses or hostnames,
  separated by spaces or commas;
- `ANSIBLE_USER` — SSH user used to install the agent on initial hosts;
- `INSTALL_DIR` — repository/install directory, defaulting to
  `~/linux-central-management`;
- `INSTALL_REF` — Git branch or ref to install, defaulting to `main`;
- `REPO_URL` — alternate Git repository URL.

### Install the admin node without attaching an agent

```bash
curl -fsSL https://raw.githubusercontent.com/impsik/linux-central-management/main/install.sh | \
  FLEET_HOSTNAME=fleet.example.internal \
  FLEET_SERVER_IP=192.0.2.10 \
  INSTALL_NGINX=yes \
  sh
```

### Install the admin node and attach the first agent

Prepare SSH key access from the admin node to the managed host first. Then run:

```bash
curl -fsSL https://raw.githubusercontent.com/impsik/linux-central-management/main/install.sh | \
  FLEET_HOSTNAME=fleet.example.internal \
  FLEET_SERVER_IP=192.0.2.10 \
  INSTALL_NGINX=yes \
  ATTACH_HOSTS=192.0.2.21 \
  ANSIBLE_USER=fleet-admin \
  sh
```

This example installs the control plane on `192.0.2.10` and deploys
`fleet-agent` to `192.0.2.21` over SSH as `fleet-admin`. The SSH user must have
working `sudo` access. With key-based SSH and passwordless sudo, no host-login
password prompt is required.

Multiple initial agents can be supplied as one quoted value:

```bash
curl -fsSL https://raw.githubusercontent.com/impsik/linux-central-management/main/install.sh | \
  FLEET_HOSTNAME=fleet.example.internal \
  FLEET_SERVER_IP=192.0.2.10 \
  INSTALL_NGINX=yes \
  ATTACH_HOSTS='192.0.2.21 192.0.2.22 server23.example.internal' \
  ANSIBLE_USER=fleet-admin \
  sh
```

The bootstrap admin password is still generated securely when no existing
password is configured. The installer displays a newly generated password in
its final summary. Browser terminal access remains an explicit advanced-mode
opt-in and is not enabled merely by using non-interactive defaults.

Review `install.sh` before unattended production use. Secret rotation and host
attachment deliberately retain confirmation steps where appropriate.

Set `NO_COLOR=1` to disable colored installer log levels.

## Important Files

- `deploy/docker/.env` — server settings and secrets;
- `.env` — helper and agent-deployment values;
- `hosts` — Ansible host list used by deployment scripts;
- `ansible/inventory.yml` — inventory used by the application and helpers;
- `/etc/fleet-pki/` — internal CA and application TLS material;
- `/etc/nginx/sites-available/fleet` — installer-managed nginx site, when
  nginx setup is selected;
- `install.sh` — admin-node installer;
- `add-host.sh` — managed-host attachment helper.

Keep `.env` files and all private keys private. The CA private key should be
backed up securely and must not be copied to managed hosts.

## Security Notes

- Prefer a proper internal DNS name over an IP address for the application.
- Restrict the web UI and agent-management ports with firewall rules suitable
  for the management network.
- Keep `AGENT_SHARED_TOKEN`, `AGENT_TERMINAL_TOKEN`, `MFA_ENCRYPTION_KEY`, and
  `POSTGRES_PASSWORD` secret.
- Keep `AGENT_SHARED_TOKEN_ALLOW_RUNTIME=false` and
  `AGENT_SHARED_TOKEN_ALLOW_REBIND=false` after agents are enrolled.
- Keep `AGENT_HMAC_REQUIRED=true` except during a controlled legacy-agent
  migration.
- Keep `DB_AUTO_CREATE_TABLES=false` and apply schema changes through Alembic
  migrations in non-development deployments.
- MFA is required for privileged users by default.
- Two-person approval is enabled by default for configured high-risk actions,
  including full package upgrades and security campaigns.
- Browser terminal access is powerful and disabled by default. Enable it only
  when required and restrict TCP port `18080` on managed hosts to the admin
  node.
- Cron jobs are created manually. Review their timezone, next-run time, target
  hosts, and maintenance window before enabling disruptive actions.

Additional deployment guidance is available in
[`docs/security-baseline.md`](docs/security-baseline.md).

## Documentation and Development

- [Security baseline and deployment hardening](docs/security-baseline.md)
- [Load testing the agent API](docs/load-testing.md)
- [Frontend testing notes](docs/frontend-testing-notes.md)
- [Agent protocol](proto/README.md)
- [Changelog](CHANGELOG.md)
- [Release security checklist](RELEASE_SECURITY_CHECKLIST.md)

The backend lives in `server/`, the Go agent in `agent/`, deployment files in
`deploy/`, and Ansible playbooks in `ansible/`. The web UI uses HTML, CSS, and
JavaScript templates in `server/app/templates/`.

To run the tests from a development checkout, use Python 3.12 (the backend CI
version), Node.js 22, and a Go toolchain compatible with `agent/go.mod`:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r server/requirements.txt
python -m pytest server/tests -q

npm ci
npm run test:frontend

(cd agent && go test ./...)
```

Use a separate development checkout for testing. Deployment and host-attachment
scripts are intended for actual administration and require elevated privileges.
