# Firewall management

Update both the Master and the managed node agents from the checkout containing
this feature. Older agents can report firewall status but do not support the
new activation action. Keep each node's existing identity and credentials when
updating its agent.

## Enable firewalls across hosts

1. Open **Firewall management** and click **Scan hosts**.
2. Select the hosts to manage, or use **Select all**.
3. Click **Enable selected** and confirm the host list.

Only selected hosts with a supported, inactive firewall are submitted. No port
or service input is needed for activation. The server checks service-management
permission, host visibility and online state again before creating a job.

The agent enables UFW, or starts firewalld and enables it at boot. Existing
firewall rules take effect; application ports need appropriate allow rules.
Results show success and failure counts, host-specific errors, and hosts skipped
because they became unavailable. The table refreshes after the job. If a job is
still running or its result could not be confirmed, scan again before retrying.

## Keep Master access available

Before activating an inactive firewall, the agent discovers the node's SSH
ports, including systemd SSH sockets, and the Console port when Console is
enabled. It prepares inbound TCP allows for those ports from the Master's IP
addresses. UFW rules are placed before ordinary user rules; firewalld rules are
prepared in permanent configuration before its service starts. Existing rules
and zone bindings are retained.

By default, Master addresses come from the node's `FLEET_SERVER_URL`. If that URL
resolves to a reverse proxy or load balancer, or NAT changes the source address,
set `FLEET_MANAGEMENT_IPS` in the node's agent environment to the addresses the
node actually sees for Master SSH and Console connections. It accepts explicit
IPv4/IPv6 addresses separated by commas or whitespace, not subnets. Restart the
agent after changing its environment. This override replaces the addresses
derived from the URL.

Activation stops with an explanation if management access cannot be determined,
both supported firewall managers are installed but inactive, or unsupported
custom rules could override the management exceptions. Resolve the reported
configuration on that node before retrying. Activation does not install a
missing firewall manager or replace a custom network policy.

These exceptions cover Master access. Administrators connecting from other
addresses and applications listening on other ports still need their own allow
rules. Prepared management rules may remain if a later activation step fails;
inspect the job output and firewall configuration before retrying.
