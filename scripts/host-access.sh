# Shared by add-host.sh. No actions run when this file is sourced.
confirm_access() {
  is_tty || return 1
  case "$(prompt "$1 (yes/no)" "yes")" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

validate_attach_target() {
  case "$1" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) err "Invalid host: $1. Use an IPv4 address or DNS hostname." ;; esac
  case "$ansible_user" in ''|-*|*[!A-Za-z0-9_.-]*) err "Invalid SSH username" ;; esac
}

ssh_probe() {
  if [ -n "${ssh_identity:-}" ]; then
    ssh -i "$ssh_identity" -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 \
      -o ConnectionAttempts=1 "$ansible_user@$access_host" "$@"
  else
    ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 \
      -o ConnectionAttempts=1 "$ansible_user@$access_host" "$@"
  fi
}

prepare_host_access() {
  access_host="$1"
  validate_attach_target "$access_host"
  info "Checking SSH access to $ansible_user@$access_host"
  # Distinguish name/network errors before offering to install an SSH key.
  python3 - "$access_host" <<'PY'
import socket, sys
try:
    with socket.create_connection((sys.argv[1], 22), timeout=10):
        pass
except OSError as exc:
    sys.exit(f"SSH connection to {sys.argv[1]}:22 failed: {exc}. Check the address, sshd and firewall.")
PY
  if ssh_probe true; then
    info "SSH key access works on $access_host"
    return
  fi
  # Let OpenSSH display and confirm a new host fingerprint. Never accept changed
  # host keys silently. This probe intentionally disables password authentication.
  if is_tty; then
    ssh -o StrictHostKeyChecking=ask -o ConnectTimeout=10 \
      -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
      "$ansible_user@$access_host" true && return
  fi
  if [ -n "${ansible_pass:-}" ]; then
    # Scripted password authentication is verified by Ansible with strict host
    # checking; this never permits an unknown or changed host key.
    return
  fi
  confirm_access "Set up SSH key access to $access_host using ssh-copy-id?" || \
    err "SSH access is not ready. Run ssh-copy-id $ansible_user@$access_host, then retry."
  have ssh-copy-id || err "ssh-copy-id is required (install openssh-client on Ubuntu/Debian or openssh-clients on Red Hat family systems)."
  if [ -z "${ssh_identity:-}" ]; then
    for candidate in "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa" "$HOME/.ssh/fleet_management"; do
      if [ -f "$candidate.pub" ]; then ssh_identity="$candidate"; break; fi
    done
  fi
  if [ -z "${ssh_identity:-}" ]; then
    confirm_access "Create a dedicated Ed25519 management key?" || err "No SSH key selected"
    ssh_identity="$HOME/.ssh/fleet_management"
    [ ! -e "$ssh_identity" ] && [ ! -e "$ssh_identity.pub" ] || err "Key path already exists: $ssh_identity"
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    ssh-keygen -t ed25519 -f "$ssh_identity" -C fleet-management
  fi
  [ -f "$ssh_identity.pub" ] || err "Public key missing: $ssh_identity.pub"
  ssh-copy-id -i "$ssh_identity.pub" -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "$ansible_user@$access_host"
  if ! ssh_probe true; then
    if [ -n "${SSH_AUTH_SOCK:-}" ]; then
      info "Loading the selected key into your SSH agent"
      ssh-add "$ssh_identity"
    fi
    ssh_probe true || err "Key access still fails. For an encrypted key, load it with ssh-add $ssh_identity and retry."
  fi
}

write_ansible_credentials() {
  # Values travel over stdin, never in process arguments or persistent config.
  printf '%s\n%s\n' "${ansible_pass:-}" "${become_pass:-}" | python3 -c '
import json, sys
ssh_password = sys.stdin.readline().rstrip("\n")
sudo_password = sys.stdin.readline().rstrip("\n")
values = {}
if ssh_password: values["ansible_password"] = ssh_password
if sudo_password: values["ansible_become_password"] = sudo_password
json.dump(values, sys.stdout)
' > "$credentials_file"
}

check_host_sudo() {
  info "Checking sudo/root access before installing anything on managed hosts"
  write_ansible_credentials
  if run_ansible -m command -a 'id -u'; then return; fi
  is_tty || err "Privilege check failed. Supply ANSIBLE_BECOME_PASS if sudo requires a password, or check SSH/sudo permissions."
  become_pass="$(prompt_secret 'Sudo password for managed hosts (SSH password may be different)')"
  [ -n "$become_pass" ] || err "A sudo password is required, or the account must have passwordless sudo rights."
  write_ansible_credentials
  run_ansible -m command -a 'id -u' || err "Privilege check failed. Verify this user can run sudo on every selected host. No agent has been installed."
}
