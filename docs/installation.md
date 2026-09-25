# Linux Central Management installation and administration

[Back to the project overview](../README.md)

Use this guide to install the admin node, connect Linux hosts, update an existing
fleet and configure unattended deployments. Commands run on the admin node
unless a step explicitly says to run them on a managed host.

- [Requirements and sizing](#requirements)
- [Install the admin node](#install-the-admin-node)
- [Connect your first host](#connect-your-first-host)
- [Join without SSH access from the Master](#join-from-the-managed-host-without-ssh-access-from-the-master)
- [Add more hosts over SSH](#add-more-hosts-later)
- [Update an existing installation](#update-an-existing-installation)
- [Non-interactive defaults](#non-interactive-defaults)
- [Important files](#important-files)
- [Security notes](#security-notes)

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

- SSH access from the admin node when using SSH-based installation or agent updates;
  the one-time join-command workflow does not require this access;
- root or `sudo` access for the initial agent installation;
- network access to the admin node's HTTPS endpoint;
- network access from the admin node to TCP port `18080` on managed hosts when
  browser terminal access is enabled.

For a larger environment, use internal DNS for the application hostname.
`/etc/hosts` works for testing, but every browser and managed host must resolve
the name consistently. The `.local` suffix may conflict with mDNS on some
networks.

### Admin node sizing

For around 100 managed hosts, start with **4 vCPU, 16 GB RAM, and a 150 GB SSD**
for the application and PostgreSQL on the same machine. These are planning
recommendations, not certified capacity limits:

| Environment | CPU | RAM | SSD/NVMe storage |
|---|---:|---:|---:|
| 100-host pilot, few concurrent administrators | 4 vCPU | 8 GB | 100 GB |
| 100 hosts, recommended starting point | 4 vCPU | 16 GB | 150 GB |
| 250 hosts, validate with your workload | 8 vCPU | 16 GB | 200 GB |

Allow for the OS, Docker images, database growth, and logs; keep independent
backups elsewhere. Package count, inventory frequency, concurrent reports,
and history retention affect resource use. Configure log rotation as well as
database retention; unbounded container/proxy logs can dominate disk growth.
These estimates assume roughly
700–1000 installed packages per host and no local package mirror. Use the
[capacity test procedure](load-testing.md) before committing to a larger fleet.

The [September 2026 capacity measurements](performance-2026-09-14.md)
document the tested workload, response times, resource use, and limitations.
The short 100-host test met the 500 ms UI API p95 target (slowest route: 411 ms).
The 250-host test reached 1,251 ms, missed heartbeat intervals, and had one
disconnected poll during onboarding, so it did not pass all acceptance checks.
Both tests used a shared machine with limits of 2 CPUs / 2 GiB per application
and database container. The larger VM recommendation above has not been tested.
More CPU cores alone do not guarantee faster reports in the current single
application process; validate report latency on the intended hardware.

Background metrics default to 50 hosts per 60-second batch, selecting missing
or oldest data first. With all hosts online and responding, one pass takes
roughly two minutes for 100 hosts or five minutes for 250 hosts. Adjust
`METRICS_BACKGROUND_BATCH_LIMIT` (maximum 200) and
`METRICS_BACKGROUND_REFRESH_SECONDS` for the freshness you need, then retest.
Setting the refresh interval to `0` disables automatic collection.

Successful automatic `query-metrics` job results expire after seven days.
Manual jobs, failed or active runs, and jobs referenced by audit/workflow
records are preserved. This policy is separate from metric snapshot cleanup.
Configure these values in `deploy/docker/.env`:

```dotenv
METRICS_JOB_RETENTION_DAYS=7
METRICS_JOB_CLEANUP_INTERVAL_SECONDS=300
METRICS_JOB_CLEANUP_BATCH_SIZE=5000
```

Set retention days to `0` to disable this cleanup. Each pass removes at most
5000 eligible runs; PostgreSQL can reuse the freed space without reducing the
database file size immediately. Other job history and audit logs still need
an organization-specific retention policy. Keep one application process until
background schedulers have coordinated ownership; adding Uvicorn workers
currently starts additional scheduler instances.

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

The standard installation asks for these settings:

1. **Application hostname** — without `https://` or a path; default `fleet.local`.
2. **HTTPS setup** — let the installer configure nginx (the default for new
   installations), or choose `no` to use an existing reverse proxy.
3. **Admin account** — username and password. A blank password generates a
   secure password, displayed once in the installation summary.
4. **Console** — enable browser terminal access now? The default is `no`.
   Choosing `yes` generates the Master Console token. Hosts added afterwards
   receive Console configuration through the host attachment/enrollment flow.
5. **First managed hosts** — on a new installation, optionally enter host
   addresses for SSH-based deployment and an SSH username. Leave blank to add
   hosts from the web UI after signing in.

The server IPv4 address is detected automatically and the internal CA defaults
to `/etc/fleet-pki/fleet-ca.crt`. Use `FLEET_SERVER_IP` or `FLEET_CA_CERT` to
override these values. Review the endpoint summary before proceeding.

On an existing installation, the standard flow preserves configured passwords,
tokens and the MFA key. It does not prompt to rotate them. If Console is already
enabled, it remains enabled without another question. If disabled, the normal
installer offers to enable it; `--resume` preserves the saved choice. Enabling
Console on the Master does not reconfigure existing agents: binary-only agent
updates retain their Console settings. Agents can be added after signing in.
MFA enrollment for privileged accounts remains required by default.

For additional options:

```bash
./install.sh --advanced
```

Advanced mode includes server IP and CA-path questions, explicit secret-rotation
choices and initial agent deployment options (also offered on a fresh installation).
`ATTACH_HOSTS` and `ANSIBLE_USER` remain available for scripted deployments in
either mode. Rotating agent or terminal tokens requires redeploying affected
agents; rotating the MFA key can invalidate enrollments.

#### Connect your first host

After signing in and completing MFA enrollment, an empty fleet opens
**Connect your first Linux host** instead of an empty operations dashboard.

1. Select **Create join command**.
2. Run the generated command on the managed host with sudo access. The command
   expires after 15 minutes and can enroll one host.
3. Watch registration, connection, OS information and package inventory arrive,
   then select **View packages and updates**.

See [join-command requirements and recovery](#join-from-the-managed-host-without-ssh-access-from-the-master)
for supported architectures, TLS bootstrap and retries.

Alternatively, expand **Alternatively: install from the Master using SSH**,
enter the host address and SSH username, and select **Prepare install command**.
Run that command from the installation directory on the admin node (by default
`~/linux-central-management`). It uses `add-host.sh`; the browser does not collect
SSH passwords or execute installation. The SSH account needs sudo access.

The progress view offers service, DNS and certificate troubleshooting. Use the
host's reported hostname/FQDN or IP address when tracking a particular host.

**Open dashboard** leaves setup, and **Add a host** reopens it from the dashboard.
Existing fleets open the normal dashboard. Setup is available to administrators;
other users keep their usual views. Terminal access, AD/OIDC and automation
remain optional later configuration.

#### Final node readiness check

After starting agents and checking Console TLS, the attachment helper waits up to
180 seconds for each target to appear in the Master's database with a recent
heartbeat and fresh package and user inventories from this deployment attempt.
It reports which item is still missing. An ambiguous host identity is not treated
as success. Keep Master and node clocks synchronized for inventory timestamps.

This read-only check runs inside the local Docker Compose server container and
requires the updated server image. It uses the Master's existing database
connection; no browser login or new API credential is required. If readiness
times out, attachment fails and the installer's retry/change/defer menu applies.
A started systemd service alone is no longer reported as a completed attachment.

#### Recover from a node attachment error

During interactive installation, a failed node attachment offers three choices:
retry after correcting the problem, change the node address/SSH username, or add
nodes later. Retrying runs only the host attachment helper, not the Master build.
Changed targets are saved for `--resume`; connection and sudo checks run again.

Choosing to add nodes later leaves the Master available and reports node
attachment as pending. Unattended runs exit with the deployment error instead of
silently skipping a failed host. Interrupting deployment stops the installer.

#### Installation output and logs

The installer shows a short start/result line for package, repository, TLS
certificate and Docker commands. Detailed stdout and stderr go to a private log
under `~/linux-central-management.install-logs/` (next to the selected checkout).
The log path is printed when installation starts and in the final summary.

If a command fails, the installer displays its exit code and the last 25 lines
from that command, followed by the full log path. Installation stops on failure;
use the resume instructions after correcting the problem. The same log is kept
when the installer restarts itself after a code update. A later invocation
creates a new log. Interactive SSH and sudo steps remain visible.

#### Resume an interrupted installation

If installation fails, fix the reported problem and run:

```bash
./install.sh --resume
```

Resume restores the saved hostname, IP, CA path, proxy choice and any selected
node addresses/SSH username. Existing account credentials and tokens are kept;
SSH/sudo passwords must be provided again when needed. `--advanced` cannot be
combined with `--resume`, so resuming never prompts to rotate credentials.

Preflight, dependency installation and access checks run again. An unchanged
Master that passes the HTTPS health check skips the Docker rebuild. Changes to
application sources or saved configuration, or a failed health check, cause the
server stage to run again. Node deployment is retried through the same host
attachment helper; it is not skipped based solely on an old success marker.

The last stage and non-secret answers are stored in a private sidecar file next
to the checkout, for example `~/linux-central-management.install-progress`.
The file is read as data, never executed. `./install.sh --resume --check` checks
the saved endpoint without changing progress or installing anything. Run without
`--resume` for the normal installation/update workflow.

#### Join from the managed host without SSH access from the Master

In **Connect a Linux host**, select **Create join command**. Paste the command into
a shell on the new node. It requires `curl`, Python 3 and sudo, and supports
systemd hosts on amd64/x86_64 or arm64/aarch64. SSH password authentication and a
Master SSH key are not required. The previous SSH-based method remains available
under **Alternatively: install from the Master using SSH**.

The command expires after 15 minutes and can enroll exactly one host. Keep it
private; use **Revoke unused command** to cancel it. Creating another command in
the same view revokes the previous unused command. Tokens are stored as hashes,
consumed atomically and exchanged for a new per-agent credential. Enrollment
cannot replace an existing host identity or overwrite an installed agent.

The initial public bootstrap download permits an untrusted TLS certificate only
because the command checks its SHA-256 digest from the authenticated UI before
executing it with sudo. No enrollment token is sent during that download. The
verified bootstrap embeds the Master's CA and agent binary hashes; subsequent
health, binary and enrollment requests validate HTTPS certificates and do not
follow redirects. A checksum mismatch stops execution; generate a new command
if the Master was upgraded since the command was created.

The node installs a prebuilt agent, its systemd service and private credentials,
then sends inventories. If Console is enabled on the Master, enrollment also
issues a server certificate and an individual Console token. The node's firewall
permits Console from the resolved Master IPv4 address; routing/NAT must still
allow Master-to-node port 18080. Console continues to prompt for the local user's
credentials. It is not an outbound reverse tunnel.

Update the Master using `install.sh` before using enrollment. The Docker build
now uses the repository root and produces both agent architectures. The installer
mounts the required Master CA certificate and terminal signing CA into the server
container under `/run/fleet-enrollment`; it also supplies the Master IPv4 address.
Enrollment commands can use that address to bootstrap DNS and add a managed
`/etc/hosts` entry on the node when needed. The terminal signing key remains on
the Master. No shared agent or shared Console token is distributed to new nodes.

After a local installation error, retry the same command to finish a saved
incomplete enrollment. If the initial enrollment response was lost before local
credentials could be saved, generate a new command. Enrollment only installs new
agents; it does not update a completed installation. Preserve the node's generated
identity and credentials when updating its binary. `install.sh` now updates
registered agents through existing Master SSH access (see below). Certificate
renewal is not yet part of this workflow.

An existing reverse proxy must overwrite `X-Real-IP` with the connecting node's
address. The supplied nginx and Caddy configurations already do this; enrollment
does not use a client-supplied `X-Forwarded-For` prefix for certificate identities.

#### Guided SSH and sudo checks

A fresh installation offers to attach the first managed host; leave the answer
blank to add it later. The installer and `./add-host.sh` use the same checks:

- Check that the admin node can reach SSH on the host (port 22).
- Verify SSH access. OpenSSH asks you to verify a new host's fingerprint;
  changed host keys are never accepted automatically.
- If needed, offer to run `ssh-copy-id` and create a dedicated Ed25519 key.
  Encrypted keys should be loaded into an SSH agent with `ssh-add`.
- Test sudo before deploying the agent. Password-protected sudo is supported;
  the sudo password may differ from the SSH password. The selected hosts must
  accept the supplied sudo credential; add hosts separately if passwords differ.
- Configure the internal CA and Master name mapping, then verify the host can
  reach the Master's `/health` endpoint with certificate validation enabled.
  Ubuntu/Debian and Red Hat family CA trust stores are supported.
- Start the agent and, when Console is enabled, check its TLS endpoint from the
  admin node. OS login in Console still uses the managed user's own credentials.

For scripted runs, prepare trusted SSH host keys in advance. Optional
`FLEET_SSH_IDENTITY` selects a private key; `ANSIBLE_BECOME_PASS` supplies a sudo
password, and `ANSIBLE_PASS` remains available for SSH password authentication.
Passwords are passed to Ansible through a private temporary JSON file that is
removed on exit, rather than command-line arguments or saved configuration.
Missing access in an unattended run stops with an actionable error.

#### Console authentication

Console prompts for the managed machine's username and password using its local
`login`/PAM service on both Ubuntu/Debian and Red Hat family hosts. The account
must be permitted by that machine's PAM policy; signing into the management UI
does not sign you into the operating system.

This is independent of admin-node communication: deployment can continue to use
SSH keys, and agent communication continues to use its configured tokens and TLS.
SSH password authentication does not need to be enabled for Console.

New deployments set `FLEET_TERMINAL_BACKEND=login`. Existing `auto` settings also
use local login after updating the agent binary and restarting `fleet-agent`.
An explicit `FLEET_TERMINAL_BACKEND=ssh` remains an optional SSH backend and obeys
the target's SSH authentication policy; change it to `login` for local Console
authentication.

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

![Active Directory login configuration in Linux Central Management](screenshots/active-directory-settings.png)

*Active Directory settings example. Configure directory authentication after
local administrator sign-in.*

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
7. rebuilds and restarts the Docker Compose services;
8. after the Master health check passes, updates registered agents over SSH using
   the amd64/arm64 binaries built into that same server image.

For example, update both the Master and its registered agents from `cleanup`:

```bash
INSTALL_REF=cleanup ./install.sh
```

Agent discovery uses the Master's database, including hosts joined through
**Connect a Linux host**. SSH uses saved inventory usernames, ports and keys;
`ANSIBLE_USER` supplies the fallback username (otherwise the saved installation
user or current user). `FLEET_SSH_IDENTITY` can select a private key. The Master
must already have trusted SSH host keys, key-based access and passwordless sudo
(or root access). Enrollment alone does not establish this SSH access. Missing
access is reported per host; the installer does not weaken SSH host-key checks,
change sudo policy or ask for every node's password during an update.

Updates compare SHA-256 hashes, so a new build with the same displayed release
number is still installed. The updater verifies the running agent's identity
before writing, replaces only its binary, restarts it and checks that the new
process remains active. IDs, tokens, certificates, Console settings and service
configuration are retained. A failed restart triggers restoration of the previous
binary, retained as `/opt/fleet-agent/fleet-agent.previous`.

Four hosts are processed concurrently by default. Offline/unreachable hosts or
failed updates do not stop updates to other hosts; the installer exits nonzero
with **Master ready; agent updates pending**, plus diagnostics in
`agent-update-results.json`. Re-run `./install.sh --resume` after fixing access or
bringing hosts online: it remembers the installation ref, skips an unchanged
healthy Master rebuild and skips agents already running the matching binary.
An active process check does not prove application compatibility; failed agents
are never reported as updated. Custom binary paths and inactive agent services
are left unchanged and reported for review.

To update only the Master, use `UPDATE_AGENTS=false INSTALL_REF=cleanup ./install.sh`.
Set `AGENT_UPDATE_WORKERS=1` for sequential agent updates (maximum: 16).

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
- `ANSIBLE_USER` — SSH user for initial attachment and fallback user for agent updates;
- `FLEET_SSH_IDENTITY` — private key for SSH attachment and agent updates;
- `UPDATE_AGENTS` — update registered agents after Master installation, default `true`;
- `AGENT_UPDATE_WORKERS` — concurrent SSH updates, default `4` (range 1–16);
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
its final summary. Browser terminal access remains an explicit opt-in in the
standard installer and is not enabled by non-interactive defaults.

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
[`docs/security-baseline.md`](security-baseline.md).
