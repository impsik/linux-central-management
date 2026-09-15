package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/fleet-agent/internal"
)

// All operating-system interaction is injected so tests never touch a firewall.
type firewallOps struct {
	run           func(context.Context, string, ...string) ([]byte, error)
	lookPath      func(string) (string, error)
	lookupIP      func(context.Context, string) ([]net.IPAddr, error)
	readFile      func(string) ([]byte, error)
	consolePort   func() (int, bool, error)
	managementIPs string
}

func systemFirewallOps() firewallOps {
	return firewallOps{
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			timeout := 5 * time.Second
			if name == "sudo" && len(args) > 2 && (args[1] == "systemctl" || (args[1] == "ufw" && args[2] == "--force")) {
				timeout = 30 * time.Second
			}
			commandCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			cmd := exec.CommandContext(commandCtx, name, args...)
			cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
			return cmd.CombinedOutput()
		},
		lookPath: exec.LookPath, lookupIP: net.DefaultResolver.LookupIPAddr,
		readFile: os.ReadFile, consolePort: internal.TerminalFirewallPort,
		managementIPs: os.Getenv("FLEET_MANAGEMENT_IPS"),
	}
}

func (o firewallOps) privileged(ctx context.Context, name string, args ...string) ([]byte, error) {
	return o.run(ctx, "sudo", append([]string{"-n", name}, args...)...)
}

type firewallState struct {
	backend string
	active  bool
}

func inspectFirewall(ctx context.Context, ops firewallOps) (firewallState, error) {
	var installed, active []string
	if _, err := ops.lookPath("firewall-cmd"); err == nil {
		installed = append(installed, "firewalld")
		out, err := ops.run(ctx, "firewall-cmd", "--state")
		state := strings.TrimSpace(strings.ToLower(string(out)))
		if err == nil && state == "running" {
			active = append(active, "firewalld")
		} else if !strings.Contains(state, "not running") && state != "not-running" {
			return firewallState{}, fmt.Errorf("cannot determine firewalld state: %s", strings.TrimSpace(string(out)))
		}
	}
	if _, err := ops.lookPath("ufw"); err == nil {
		installed = append(installed, "ufw")
		out, err := ops.privileged(ctx, "ufw", "status")
		state := strings.ToLower(string(out))
		if err != nil {
			return firewallState{}, fmt.Errorf("cannot determine UFW state: %s", strings.TrimSpace(string(out)))
		}
		if strings.Contains(state, "status: active") {
			active = append(active, "ufw")
		} else if !strings.Contains(state, "status: inactive") {
			return firewallState{}, fmt.Errorf("cannot determine UFW state")
		}
	}
	if len(active) > 1 {
		return firewallState{}, fmt.Errorf("both UFW and firewalld are active; resolve the conflicting managers before continuing")
	}
	if len(active) == 1 {
		return firewallState{backend: active[0], active: true}, nil
	}
	if len(installed) > 1 {
		return firewallState{}, fmt.Errorf("both UFW and firewalld are installed but inactive; choose one manager on the node first")
	}
	if len(installed) == 0 {
		return firewallState{}, fmt.Errorf("no supported firewall manager found (expected firewalld or ufw)")
	}
	return firewallState{backend: installed[0]}, nil
}

func queryInactiveFirewalld(ctx context.Context, ops firewallOps) (string, string, int, string) {
	payload := map[string]any{"backend": "firewalld", "status": "inactive", "rules": []FirewallRule{}}
	if _, err := ops.lookPath("firewall-offline-cmd"); err == nil {
		out, err := ops.privileged(ctx, "firewall-offline-cmd", "--get-default-zone")
		if err != nil {
			return "", string(out), 1, "cannot read inactive firewalld configuration"
		}
		zone := strings.TrimSpace(string(out))
		if !safeZone(zone) {
			return "", "", 1, "cannot determine inactive firewalld default zone"
		}
		payload["zone"] = zone
		rules := []FirewallRule{}
		for _, kind := range []string{"ports", "services", "rich-rules"} {
			out, err := ops.privileged(ctx, "firewall-offline-cmd", "--zone="+zone, "--list-"+kind)
			if err != nil {
				return "", string(out), 1, "cannot read inactive firewalld " + kind
			}
			if kind == "rich-rules" {
				for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
					if strings.TrimSpace(line) != "" {
						rules = append(rules, firewalldRichRule(line))
					}
				}
			} else {
				for _, value := range strings.Fields(string(out)) {
					rule := FirewallRule{Backend: "firewalld", Action: "allow", Raw: value}
					if kind == "services" {
						rule.Service = value
					} else if parts := strings.SplitN(value, "/", 2); len(parts) == 2 {
						rule.Port, rule.Protocol = parts[0], parts[1]
					}
					rules = append(rules, rule)
				}
			}
		}
		payload["rules"] = rules
	}
	b, _ := json.Marshal(payload)
	return string(b), "", 0, ""
}

// Preserve the raw rich rule; do not label source-scoped management accepts as
// denies in the host view. More complex actions remain visible as raw rules.
func firewalldRichRule(line string) FirewallRule {
	rule := FirewallRule{Backend: "firewalld", Raw: line}
	fields := strings.Fields(line)
	if len(fields) > 0 {
		switch fields[len(fields)-1] {
		case "accept":
			rule.Action = "allow"
		case "drop", "reject":
			rule.Action = "deny"
		}
	}
	return rule
}

type firewallManagement struct {
	Sources     []string `json:"management_sources"`
	SSHPorts    []int    `json:"ssh_ports"`
	ConsolePort int      `json:"console_port,omitempty"`
}

type firewallEnableResult struct {
	Backend            string `json:"backend"`
	Status             string `json:"status"`
	AlreadyActive      bool   `json:"already_active"`
	ManagementPrepared bool   `json:"management_prepared"`
	firewallManagement
	Zones []string `json:"zones,omitempty"`
}

func enableFirewall(ctx context.Context, serverURL string, ops firewallOps) (string, string, int, string) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	state, err := inspectFirewall(ctx, ops)
	if err != nil {
		return "", "", 1, err.Error()
	}
	result := firewallEnableResult{Backend: state.backend, Status: "active", AlreadyActive: state.active}
	if state.backend == "firewalld" {
		result.Status = "running"
	}
	if state.active {
		// Do not reload or alter an already working ruleset. Firewalld also needs
		// its service enabled to retain this state across a reboot.
		if state.backend == "firewalld" {
			if out, err := ops.privileged(ctx, "systemctl", "enable", "firewalld"); err != nil {
				return string(out), "", 1, "firewalld is active but enabling its boot service failed"
			}
		}
		body, _ := json.Marshal(result)
		return string(body), "", 0, ""
	}
	management, err := discoverFirewallManagement(ctx, serverURL, ops)
	if err != nil {
		return "", "", 1, "firewall remains inactive: " + err.Error()
	}
	result.firewallManagement = management
	if state.backend == "ufw" {
		err = prepareUfwManagement(ctx, management, ops)
	} else {
		result.Zones, err = prepareFirewalldManagement(ctx, management, ops)
	}
	if err != nil {
		return "", "", 1, "firewall remains inactive: " + err.Error()
	}
	result.ManagementPrepared = true
	if state.backend == "ufw" {
		if out, err := ops.privileged(ctx, "ufw", "--force", "enable"); err != nil {
			return string(out), "", 1, "UFW activation failed after preparing management access"
		}
	} else {
		if out, err := ops.privileged(ctx, "systemctl", "enable", "--now", "firewalld"); err != nil {
			return string(out), "", 1, "firewalld activation failed after preparing management access"
		}
	}
	verified, err := inspectFirewall(ctx, ops)
	if err != nil || !verified.active || verified.backend != state.backend {
		return "", "", 1, "firewall activation command completed but active state could not be verified"
	}
	body, _ := json.Marshal(result)
	return string(body), "", 0, ""
}

func discoverFirewallManagement(ctx context.Context, serverURL string, ops firewallOps) (firewallManagement, error) {
	var result firewallManagement
	endpoint, err := url.Parse(serverURL)
	if err != nil || endpoint.Hostname() == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return result, fmt.Errorf("cannot determine Master address from FLEET_SERVER_URL")
	}
	sources := map[string]bool{}
	addSource := func(value string) error {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("management source %q must be a routable IP address", value)
		}
		sources[ip.String()] = true
		return nil
	}
	if strings.TrimSpace(ops.managementIPs) != "" {
		for _, value := range strings.Fields(strings.ReplaceAll(ops.managementIPs, ",", " ")) {
			if err := addSource(value); err != nil {
				return result, err
			}
		}
	} else if ip := net.ParseIP(endpoint.Hostname()); ip != nil {
		if err := addSource(ip.String()); err != nil {
			return result, err
		}
	} else {
		resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		addresses, err := ops.lookupIP(resolveCtx, endpoint.Hostname())
		if err != nil {
			return result, fmt.Errorf("cannot resolve Master address: %w", err)
		}
		for _, address := range addresses {
			if err := addSource(address.IP.String()); err != nil {
				return result, err
			}
		}
	}
	if len(sources) == 0 || len(sources) > 32 {
		return result, fmt.Errorf("could not establish a bounded set of Master source IPs; configure FLEET_MANAGEMENT_IPS on the node")
	}
	for source := range sources {
		result.Sources = append(result.Sources, source)
	}
	sort.Strings(result.Sources)
	result.SSHPorts, err = discoverSSHPorts(ctx, ops)
	if err != nil {
		return result, err
	}
	port, enabled, err := ops.consolePort()
	if err != nil {
		return result, err
	}
	if enabled {
		result.ConsolePort = port
	}
	return result, nil
}

func addressPort(value string) (string, int, error) {
	pos := strings.LastIndex(value, ":")
	if pos < 0 {
		return "", 0, fmt.Errorf("invalid listen address %q", value)
	}
	port, err := strconv.Atoi(value[pos+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid listen port in %q", value)
	}
	return strings.Trim(value[:pos], "[]"), port, nil
}

func discoverSSHPorts(ctx context.Context, ops firewallOps) ([]int, error) {
	ports := map[int]bool{}
	sshd, err := ops.lookPath("sshd")
	if err != nil {
		sshd, err = ops.lookPath("/usr/sbin/sshd")
	}
	if err != nil {
		return nil, fmt.Errorf("OpenSSH server was not found; cannot protect management SSH")
	}
	configuration, err := ops.privileged(ctx, sshd, "-T")
	if err != nil {
		return nil, fmt.Errorf("cannot read effective SSH server configuration: %s", strings.TrimSpace(string(configuration)))
	}
	for _, line := range strings.Split(string(configuration), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == "port" {
			port, err := strconv.Atoi(parts[1])
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port in effective SSH server configuration")
			}
			ports[port] = true
		}
	}
	listeners, err := ops.privileged(ctx, "ss", "-H", "-ltnp")
	if err != nil {
		return nil, fmt.Errorf("cannot inspect SSH listening sockets: %s", strings.TrimSpace(string(listeners)))
	}
	externalListener := false
	addListener := func(value string) {
		host, port, err := addressPort(value)
		if err == nil {
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				externalListener = true
				ports[port] = true
			}
		}
	}
	for _, line := range strings.Split(string(listeners), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && strings.Contains(line, `"sshd"`) {
			addListener(fields[3])
		}
	}
	// Ubuntu may let systemd own a different port from sshd_config.
	for _, unit := range []string{"ssh.socket", "sshd.socket"} {
		out, err := ops.run(ctx, "systemctl", "show", unit, "--property=LoadState,ActiveState,Listen")
		if strings.Contains(string(out), "ActiveState=active") {
			if err != nil {
				return nil, fmt.Errorf("cannot inspect active SSH socket unit %s", unit)
			}
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "Listen=") {
					fields := strings.Fields(strings.TrimPrefix(line, "Listen="))
					for index, field := range fields {
						if index+1 < len(fields) && fields[index+1] == "(Stream)" {
							addListener(field)
						}
					}
				}
			}
		}
	}
	if !externalListener || len(ports) == 0 || len(ports) > 32 {
		return nil, fmt.Errorf("cannot establish listening management SSH ports; firewall was not enabled")
	}
	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)
	return result, nil
}

func managementPorts(management firewallManagement) []int {
	ports := append([]int(nil), management.SSHPorts...)
	if management.ConsolePort != 0 {
		for _, port := range ports {
			if port == management.ConsolePort {
				return ports
			}
		}
		ports = append(ports, management.ConsolePort)
	}
	return ports
}

func prepareUfwManagement(ctx context.Context, management firewallManagement, ops firewallOps) error {
	defaults, err := ops.readFile("/etc/default/ufw")
	if err != nil {
		return fmt.Errorf("cannot inspect UFW defaults before activation: %w", err)
	}
	outputAllowed := false
	for _, line := range strings.Split(string(defaults), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) == 2 && parts[0] == "DEFAULT_OUTPUT_POLICY" {
			outputAllowed = strings.Trim(strings.TrimSpace(parts[1]), `"'`) == "ACCEPT"
		}
	}
	if !outputAllowed {
		return fmt.Errorf("custom UFW outgoing policy requires manual review to preserve agent and DNS connectivity")
	}
	// Custom before-rules/hooks run ahead of UFW's user rules. Refuse these
	// rather than pretending a prepended allow can override an earlier drop.
	verify, args := "dpkg", []string{"--verify", "ufw"}
	if _, err := ops.lookPath(verify); err != nil {
		verify, args = "rpm", []string{"-V", "ufw"}
		if _, err := ops.lookPath(verify); err != nil {
			return fmt.Errorf("cannot verify packaged UFW before-rules; enable manually after reviewing management access")
		}
	}
	verification, verifyErr := ops.run(ctx, verify, args...)
	if verifyErr != nil && len(strings.TrimSpace(string(verification))) == 0 {
		return fmt.Errorf("could not verify UFW configuration before activation")
	}
	for _, line := range strings.Split(string(verification), "\n") {
		if line != "" && !strings.HasPrefix(line, "missing") && (len(line) < 10 || line[9] != ' ') {
			return fmt.Errorf("could not verify UFW configuration before activation: %s", line)
		}
		for _, name := range []string{"/etc/ufw/before.rules", "/etc/ufw/before6.rules", "/etc/ufw/after.rules", "/etc/ufw/after6.rules", "/etc/ufw/before.init", "/etc/ufw/after.init"} {
			if strings.Contains(line, name) {
				return fmt.Errorf("custom or missing %s requires manual review before enabling UFW", name)
			}
		}
	}
	// Stock hooks contain shell scaffolding. Package verification above checks
	// their integrity without rejecting the unchanged distribution templates.
	added, err := ops.privileged(ctx, "ufw", "show", "added")
	if err != nil {
		return fmt.Errorf("cannot inspect saved UFW rules before activation")
	}
	for _, line := range strings.Split(string(added), "\n") {
		words := " " + strings.ToLower(line) + " "
		if strings.Contains(words, " out ") && (strings.Contains(words, " deny ") || strings.Contains(words, " reject ")) {
			return fmt.Errorf("custom UFW outgoing deny rules require review to preserve agent and DNS connectivity")
		}
	}
	for _, source := range management.Sources {
		for _, port := range managementPorts(management) {
			rule := []string{"allow", "from", source, "to", "any", "port", strconv.Itoa(port), "proto", "tcp"}
			// Delete only this exact management allow, if present, to ensure UFW
			// does not leave a duplicate behind a preceding deny. Other rules stay.
			out, err := ops.privileged(ctx, "ufw", append([]string{"--force", "delete"}, rule...)...)
			if err != nil && !strings.Contains(strings.ToLower(string(out)), "non-existent rule") {
				return fmt.Errorf("cannot prepare management allow for %s:%d: %s", source, port, strings.TrimSpace(string(out)))
			}
			// prepend is the family-aware equivalent of insert 1 for IPv4/IPv6.
			out, err = ops.privileged(ctx, "ufw", append([]string{"prepend"}, rule...)...)
			if err != nil {
				return fmt.Errorf("cannot prioritize management allow for %s:%d: %s", source, port, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

func safeZone(zone string) bool {
	if zone == "" || len(zone) > 64 {
		return false
	}
	for _, ch := range zone {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

func managementRichRule(source string, port int) string {
	family := "ipv4"
	if strings.Contains(source, ":") {
		family = "ipv6"
	}
	return fmt.Sprintf(`rule family="%s" priority="-32768" source address="%s" port port="%d" protocol="tcp" accept`, family, source, port)
}

func prepareFirewalldManagement(ctx context.Context, management firewallManagement, ops firewallOps) ([]string, error) {
	if _, err := ops.lookPath("firewall-offline-cmd"); err != nil {
		return nil, fmt.Errorf("firewall-offline-cmd is required to protect management access before starting firewalld")
	}
	read := func(args ...string) (string, error) {
		out, err := ops.privileged(ctx, "firewall-offline-cmd", args...)
		if err != nil {
			return "", fmt.Errorf("cannot inspect firewalld %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
		}
		return strings.TrimSpace(string(out)), nil
	}
	defaultZone, err := read("--get-default-zone")
	if err != nil || !safeZone(defaultZone) {
		return nil, fmt.Errorf("cannot determine firewalld default zone")
	}
	zoneList, err := read("--get-zones")
	if err != nil {
		return nil, err
	}
	zones := map[string]bool{defaultZone: true}
	knownZones := map[string]bool{}
	for _, zone := range strings.Fields(zoneList) {
		if !safeZone(zone) {
			return nil, fmt.Errorf("unsupported firewalld zone name")
		}
		knownZones[zone] = true
		interfaces, err := read("--zone="+zone, "--list-interfaces")
		if err != nil {
			return nil, err
		}
		sources, err := read("--zone="+zone, "--list-sources")
		if err != nil {
			return nil, err
		}
		if interfaces != "" || sources != "" {
			zones[zone] = true
		}
	}
	// NetworkManager can assign a zone only when firewalld starts, independently
	// of the bindings currently present in permanent zone configuration.
	if _, err := ops.lookPath("nmcli"); err == nil {
		connections, err := ops.run(ctx, "nmcli", "-t", "-f", "UUID", "connection", "show", "--active")
		if err != nil && !strings.Contains(strings.ToLower(string(connections)), "not running") {
			return nil, fmt.Errorf("cannot determine NetworkManager firewall zones")
		}
		if err == nil {
			for _, connection := range strings.Fields(string(connections)) {
				out, err := ops.run(ctx, "nmcli", "-g", "connection.zone", "connection", "show", connection)
				zone := strings.TrimSpace(string(out))
				if err != nil || (zone != "" && !knownZones[zone]) {
					return nil, fmt.Errorf("cannot determine an active NetworkManager connection's firewall zone")
				}
				if zone != "" {
					zones[zone] = true
				}
			}
		}
	}
	direct, err := read("--direct", "--get-all-rules")
	if err != nil {
		return nil, err
	}
	if direct != "" {
		return nil, fmt.Errorf("custom firewalld direct rules require manual management-access review before activation")
	}
	passthroughs, err := read("--direct", "--get-all-passthroughs")
	if err != nil {
		return nil, err
	}
	if passthroughs != "" {
		return nil, fmt.Errorf("custom firewalld passthrough rules require manual management-access review before activation")
	}
	policies, err := read("--get-policies")
	if err != nil {
		return nil, err
	}
	for _, policy := range strings.Fields(policies) {
		info, err := read("--info-policy=" + policy)
		if err != nil {
			return nil, err
		}
		// Policies can precede zone rules. Fail closed for deny policies/rules
		// rather than changing someone else's policy to force management access.
		lower := strings.ToLower(info)
		if strings.Contains(lower, "target: drop") || strings.Contains(lower, "target: reject") ||
			strings.Contains(lower, " drop") || strings.Contains(lower, " reject") {
			return nil, fmt.Errorf("firewalld policy %s may block management traffic; review it before activation", policy)
		}
	}
	result := make([]string, 0, len(zones))
	for zone := range zones {
		rules, err := read("--zone="+zone, "--list-rich-rules")
		if err != nil {
			return nil, err
		}
		for _, rule := range strings.Split(rules, "\n") {
			if strings.Contains(rule, `priority="-`) && (strings.Contains(rule, " drop") || strings.Contains(rule, " reject")) {
				return nil, fmt.Errorf("zone %s has an early deny rule; review management access before activation", zone)
			}
		}
		result = append(result, zone)
	}
	sort.Strings(result)
	for _, zone := range result {
		for _, source := range management.Sources {
			for _, port := range managementPorts(management) {
				rule := managementRichRule(source, port)
				out, err := ops.privileged(ctx, "firewall-offline-cmd", "--zone="+zone, "--add-rich-rule="+rule)
				if err != nil {
					return nil, fmt.Errorf("cannot prepare management rule in zone %s: %s", zone, strings.TrimSpace(string(out)))
				}
				if _, err := ops.privileged(ctx, "firewall-offline-cmd", "--zone="+zone, "--query-rich-rule="+rule); err != nil {
					return nil, fmt.Errorf("management rule could not be verified in zone %s", zone)
				}
			}
		}
	}
	return result, nil
}
