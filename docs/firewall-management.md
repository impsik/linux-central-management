# Firewall management

Update both the Master and the managed node agents from the checkout containing
these features. Older agents can report firewall status but may not support
enabling, disabling, or deleting selected rules. Updating the Master alone does not replace existing
node binaries. Keep each node's existing identity and credentials when updating
its agent; the displayed release number can be the same for different builds.

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

## Disable firewalls across hosts

Scan the hosts, select those with an active firewall, and click **Disable
selected**. The confirmation lists only the hosts whose firewalls will stop.
Inactive hosts are skipped by this action. No port or service input is needed.

The agent runs UFW's disable command, or stops and disables the firewalld service.
It verifies that the selected firewall is inactive before reporting success.
Saved rules remain available for **Enable selected**. Disabling stops host
firewall protection and turns off its configured automatic startup; it does not
mask firewalld or prevent an administrator or another service from starting it.
The same service-management permissions, host scope, job results and audit trail
apply as for enabling.

## Remove specific rules from one or several hosts

1. Scan hosts and select the host(s) to manage.
2. Click **Remove rules…** to open their rules, grouped by host.
3. Check only the rules to remove and click **Remove selected rules**.
   Unchecked rules and hosts without checked rules remain unchanged. Cancel or
   Escape closes the dialog without submitting a job.

The dialog shows the original rule, including source, direction and IPv6 details,
plus the firewalld zone. Both allow and deny rules can be selected. Port, Service
and Source inputs in the main toolbar are not used for this operation. Removing
SSH or Console allows may interrupt Master access; keep those rules unless that
is intentional. There is a limit of 100 rules per host and 500 per operation.

Agents re-read the rules before deleting and verify the result afterwards. UFW
rules are removed by exact numbered identity in descending order; a stale list
or unexpected post-deletion state fails with instructions to scan again. UFW
must be active to expose numbered rules. Firewalld removes the exact port,
service or rich rule in the displayed zone from runtime and permanent
configuration where present, without a reload affecting unrelated runtime rules.
For inactive firewalld, only permanent configuration is changed.

A failure can leave earlier removals applied. Inspect the per-host error and
rescan before retrying; a successful command that did not remove the selected
rule is not reported as success. Rules edited independently on the node during
an operation can cause it to stop with a verification error.

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
