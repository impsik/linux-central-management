package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
)

type firewallReply struct {
	text string
	err  error
}

// Every OS interaction is fake, including discovery; unknown commands fail.
type fakeFirewall struct {
	calls     []string
	installed map[string]bool
	active    map[string]bool
	replies   map[string]firewallReply
	files     map[string]string
	ops       firewallOps
}

func newFakeFirewall(backend string) *fakeFirewall {
	f := &fakeFirewall{
		installed: map[string]bool{"sshd": true, "dpkg": true},
		active:    map[string]bool{}, replies: map[string]firewallReply{},
		files: map[string]string{"/etc/default/ufw": "DEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n",
			// Representative unchanged packaged hooks contain real shell syntax.
			"/etc/ufw/before.init": "#!/bin/sh\nset -e\ncase \"$1\" in\nstart) ;;\nstop) ;;\nstatus) ;;\nflush-all) ;;\nesac\nexit 0\n",
		},
	}
	if backend == "ufw" {
		f.installed["ufw"] = true
	} else {
		f.installed["firewall-cmd"], f.installed["firewall-offline-cmd"] = true, true
	}
	f.ops = firewallOps{
		run: f.run,
		lookPath: func(name string) (string, error) {
			if f.installed[name] {
				return name, nil
			}
			return "", os.ErrNotExist
		},
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if contents, ok := f.files[name]; ok {
				return []byte(contents), nil
			}
			return nil, os.ErrNotExist
		},
		consolePort: func() (int, bool, error) { return 18443, true, nil },
	}
	return f
}

func (f *fakeFirewall) run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "sudo" && len(args) > 1 && args[0] == "-n" {
		name, args = args[1], args[2:]
	}
	key := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if reply, ok := f.replies[key]; ok {
		return []byte(reply.text), reply.err
	}
	switch key {
	case "systemctl show firewalld --property=LoadState,ActiveState":
		if f.active["firewalld"] {
			return []byte("LoadState=loaded\nActiveState=active\n"), nil
		}
		return []byte("LoadState=loaded\nActiveState=inactive\n"), nil
	case "firewall-cmd --state":
		if f.active["firewalld"] {
			return []byte("running\n"), nil
		}
		return []byte("not running\n"), fmt.Errorf("exit 252")
	case "ufw status":
		if f.active["ufw"] {
			return []byte("Status: active\n"), nil
		}
		return []byte("Status: inactive\n"), nil
	case "dpkg --verify ufw", "ufw show added":
		return nil, nil
	case "sshd -T":
		return []byte("port 2222\n"), nil
	case "ss -H -ltnp":
		return []byte(`LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=2,fd=3))`), nil
	case "systemctl show ssh.socket --property=LoadState,ActiveState,Listen", "systemctl show sshd.socket --property=LoadState,ActiveState,Listen":
		return []byte("LoadState=not-found\nActiveState=inactive\n"), nil
	case "ufw --force enable":
		f.active["ufw"] = true
		return nil, nil
	case "ufw --force disable":
		f.active["ufw"] = false
		return nil, nil
	case "systemctl enable --now firewalld":
		f.active["firewalld"] = true
		return nil, nil
	case "systemctl disable --now firewalld":
		f.active["firewalld"] = false
		return nil, nil
	case "systemctl enable firewalld":
		return nil, nil
	case "firewall-offline-cmd --get-default-zone":
		return []byte("public"), nil
	case "firewall-offline-cmd --get-zones":
		return []byte("public work private trusted"), nil
	case "firewall-offline-cmd --zone=work --list-interfaces":
		return []byte("eth0"), nil
	case "firewall-offline-cmd --zone=private --list-sources":
		return []byte("192.0.2.0/24"), nil
	case "firewall-offline-cmd --direct --get-all-rules", "firewall-offline-cmd --direct --get-all-passthroughs", "firewall-offline-cmd --get-policies":
		return nil, nil
	}
	if name == "ufw" && (strings.HasPrefix(strings.Join(args, " "), "--force delete allow ") || strings.HasPrefix(strings.Join(args, " "), "prepend allow ")) {
		return nil, nil
	}
	if name == "firewall-offline-cmd" && len(args) == 2 && strings.HasPrefix(args[0], "--zone=") {
		for _, prefix := range []string{"--list-", "--add-rich-rule=", "--query-rich-rule="} {
			if strings.HasPrefix(args[1], prefix) {
				return nil, nil
			}
		}
	}
	return nil, fmt.Errorf("unexpected fake command: %s", key)
}

func (f *fakeFirewall) activated() bool {
	for _, call := range f.calls {
		if call == "ufw --force enable" || call == "systemctl enable --now firewalld" {
			return true
		}
	}
	return false
}

func TestEnableUfwProtectsNondefaultSSHAndConsoleBeforeActivation(t *testing.T) {
	f := newFakeFirewall("ufw")
	stdout, _, code, message := enableFirewall(context.Background(), "https://fleet.example", f.ops)
	if code != 0 {
		t.Fatalf("enable failed: %s; commands: %v", message, f.calls)
	}
	var result firewallEnableResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if !result.ManagementPrepared || result.AlreadyActive || result.ConsolePort != 18443 || !reflect.DeepEqual(result.SSHPorts, []int{2222}) || !reflect.DeepEqual(result.Sources, []string{"192.0.2.10"}) {
		t.Fatalf("unexpected result: %+v", result)
	}
	lastRule, activation, prepends := -1, -1, 0
	for index, call := range f.calls {
		if strings.HasPrefix(call, "ufw prepend allow from 192.0.2.10 ") {
			lastRule = index
			prepends++
		}
		if call == "ufw --force enable" {
			activation = index
		}
		for _, forbidden := range []string{"ufw reset", "ufw default", "ufw reload"} {
			if strings.Contains(call, forbidden) {
				t.Fatalf("changed unrelated rules: %s", call)
			}
		}
	}
	if prepends != 2 || activation <= lastRule {
		t.Fatalf("management must be prepared first: %v", f.calls)
	}
}

func TestEnableInactiveFirewalldProtectsAllBoundZonesBeforeStart(t *testing.T) {
	f := newFakeFirewall("firewalld")
	f.installed["nmcli"] = true
	f.replies["nmcli -t -f UUID connection show --active"] = firewallReply{text: "connection-id"}
	f.replies["nmcli -g connection.zone connection show connection-id"] = firewallReply{text: "trusted"}
	stdout, _, code, message := enableFirewall(context.Background(), "https://192.0.2.10", f.ops)
	if code != 0 {
		t.Fatalf("enable failed: %s; commands: %v", message, f.calls)
	}
	var result firewallEnableResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "running" || !reflect.DeepEqual(result.Zones, []string{"private", "public", "trusted", "work"}) {
		t.Fatalf("unexpected result: %+v", result)
	}
	adds, verifies, activation := 0, 0, -1
	for index, call := range f.calls {
		if strings.Contains(call, "--add-rich-rule=") {
			adds++
			if activation >= 0 || !strings.Contains(call, `priority="-32768" source address="192.0.2.10"`) {
				t.Fatalf("unsafe rule/order: %s", call)
			}
		}
		if strings.Contains(call, "--query-rich-rule=") {
			verifies++
			if activation >= 0 {
				t.Fatal("late rule verification")
			}
		}
		if call == "systemctl enable --now firewalld" {
			activation = index
		}
	}
	if adds != 8 || verifies != 8 || activation < 0 {
		t.Fatalf("missing preparation: %v", f.calls)
	}
}

func TestQueryInstalledInactiveFirewalld(t *testing.T) {
	f := newFakeFirewall("firewalld")
	state, err := inspectFirewall(context.Background(), f.ops)
	if err != nil || state.active || state.backend != "firewalld" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	f.replies["firewall-offline-cmd --zone=public --list-ports"] = firewallReply{text: "2222/tcp"}
	stdout, _, code, message := queryInactiveFirewalld(context.Background(), f.ops)
	if code != 0 || !strings.Contains(stdout, `"status":"inactive"`) || !strings.Contains(stdout, `"port":"2222"`) {
		t.Fatalf("query=%s code=%d error=%s", stdout, code, message)
	}
	if f.activated() {
		t.Fatal("query activated firewall")
	}
}

func TestEnableKeepsActiveManagerWithoutChangingRules(t *testing.T) {
	for _, backend := range []string{"ufw", "firewalld"} {
		t.Run(backend, func(t *testing.T) {
			f := newFakeFirewall(backend)
			f.installed["ufw"], f.installed["firewall-cmd"] = true, true
			f.active[backend] = true
			stdout, _, code, message := enableFirewall(context.Background(), "invalid-unused-url", f.ops)
			if code != 0 || !strings.Contains(stdout, `"already_active":true`) {
				t.Fatalf("%s: %s", stdout, message)
			}
			for _, call := range f.calls {
				if call != "ufw status" && call != "firewall-cmd --state" && call != "systemctl show firewalld --property=LoadState,ActiveState" && !(backend == "firewalld" && call == "systemctl enable firewalld") {
					t.Fatalf("active ruleset was changed: %v", f.calls)
				}
			}
		})
	}
}

func TestFirewallEnableFailsBeforeActivationWhenManagementIsUncertain(t *testing.T) {
	commandErr := fmt.Errorf("command failed")
	cases := []struct {
		name, backend string
		configure     func(*fakeFirewall)
		want          string
	}{
		{"ambiguous managers", "ufw", func(f *fakeFirewall) { f.installed["firewall-cmd"] = true }, "choose one"},
		{"both active", "ufw", func(f *fakeFirewall) {
			f.installed["firewall-cmd"] = true
			f.active["ufw"], f.active["firewalld"] = true, true
		}, "both UFW"},
		{"unresolved master", "ufw", func(f *fakeFirewall) {
			f.ops.lookupIP = func(context.Context, string) ([]net.IPAddr, error) { return nil, nil }
		}, "Master"},
		{"no SSH listener", "ufw", func(f *fakeFirewall) { f.replies["ss -H -ltnp"] = firewallReply{text: ""} }, "listening management SSH"},
		{"SSH config failure", "ufw", func(f *fakeFirewall) { f.replies["sshd -T"] = firewallReply{err: commandErr} }, "SSH server configuration"},
		{"console config failure", "ufw", func(f *fakeFirewall) {
			f.ops.consolePort = func() (int, bool, error) { return 0, false, fmt.Errorf("invalid console address") }
		}, "console address"},
		{"modified before rules", "ufw", func(f *fakeFirewall) {
			f.replies["dpkg --verify ufw"] = firewallReply{text: "??5?????? c /etc/ufw/before.rules"}
		}, "before.rules"},
		{"modified stock hook", "ufw", func(f *fakeFirewall) {
			f.replies["dpkg --verify ufw"] = firewallReply{text: "??5?????? c /etc/ufw/before.init"}
		}, "before.init"},
		{"package verification failure", "ufw", func(f *fakeFirewall) {
			f.replies["dpkg --verify ufw"] = firewallReply{text: "dpkg: error: unable to read database", err: commandErr}
		}, "verify UFW"},
		{"outgoing default deny", "ufw", func(f *fakeFirewall) { f.files["/etc/default/ufw"] = "DEFAULT_OUTPUT_POLICY=DROP" }, "outgoing policy"},
		{"saved outgoing deny", "ufw", func(f *fakeFirewall) {
			f.replies["ufw show added"] = firewallReply{text: "ufw deny out to any port 443 proto tcp"}
		}, "outgoing deny"},
		{"UFW preparation failure", "ufw", func(f *fakeFirewall) {
			f.replies["ufw prepend allow from 192.0.2.10 to any port 2222 proto tcp"] = firewallReply{err: commandErr}
		}, "prioritize management"},
		{"missing offline tool", "firewalld", func(f *fakeFirewall) { delete(f.installed, "firewall-offline-cmd") }, "firewall-offline-cmd is required"},
		{"direct rule", "firewalld", func(f *fakeFirewall) {
			f.replies["firewall-offline-cmd --direct --get-all-rules"] = firewallReply{text: "ipv4 filter INPUT 0 -j DROP"}
		}, "direct rules"},
		{"passthrough rule", "firewalld", func(f *fakeFirewall) {
			f.replies["firewall-offline-cmd --direct --get-all-passthroughs"] = firewallReply{text: "ipv4 -A INPUT -j DROP"}
		}, "passthrough rules"},
		{"deny policy", "firewalld", func(f *fakeFirewall) {
			f.replies["firewall-offline-cmd --get-policies"] = firewallReply{text: "custom"}
			f.replies["firewall-offline-cmd --info-policy=custom"] = firewallReply{text: "target: DROP"}
		}, "policy custom"},
		{"early rich deny", "firewalld", func(f *fakeFirewall) {
			f.replies["firewall-offline-cmd --zone=public --list-rich-rules"] = firewallReply{text: `rule priority="-32768" source address="192.0.2.10" drop`}
		}, "early deny"},
		{"rich rule verification failure", "firewalld", func(f *fakeFirewall) {
			f.replies["firewall-offline-cmd --zone=private --query-rich-rule="+managementRichRule("192.0.2.10", 2222)] = firewallReply{err: commandErr}
		}, "could not be verified"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFakeFirewall(test.backend)
			test.configure(f)
			_, _, code, message := enableFirewall(context.Background(), "https://fleet.example", f.ops)
			if code == 0 || !strings.Contains(message, test.want) {
				t.Fatalf("code=%d error=%q, want %q", code, message, test.want)
			}
			if f.activated() {
				t.Fatalf("unsafe activation: %v", f.calls)
			}
		})
	}
}

func TestSSHSocketActivationAndMasterSourceOverride(t *testing.T) {
	f := newFakeFirewall("ufw")
	f.ops.managementIPs = "2001:db8::10,192.0.2.20"
	f.ops.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		t.Fatal("override must replace DNS")
		return nil, nil
	}
	f.replies["sshd -T"] = firewallReply{text: "port 22"}
	f.replies["ss -H -ltnp"] = firewallReply{}
	f.replies["systemctl show ssh.socket --property=LoadState,ActiveState,Listen"] = firewallReply{text: "LoadState=loaded\nActiveState=active\nListen=[::]:2222 (Stream)"}
	management, err := discoverFirewallManagement(context.Background(), "https://proxy.example", f.ops)
	if err != nil || !reflect.DeepEqual(management.SSHPorts, []int{22, 2222}) || !reflect.DeepEqual(management.Sources, []string{"192.0.2.20", "2001:db8::10"}) {
		t.Fatalf("management=%+v err=%v", management, err)
	}
	if !strings.Contains(managementRichRule("2001:db8::10", 2222), `family="ipv6"`) {
		t.Fatal("wrong address family")
	}
	for _, bad := range []string{"0.0.0.0/0", "127.0.0.1", "::", "example.com"} {
		f.ops.managementIPs = bad
		if _, err := discoverFirewallManagement(context.Background(), "https://proxy.example", f.ops); err == nil {
			t.Fatalf("accepted unsafe source %q", bad)
		}
	}
}

func TestEnableVerifiesActiveStateAfterCommand(t *testing.T) {
	f := newFakeFirewall("ufw")
	f.replies["ufw --force enable"] = firewallReply{}
	_, _, code, message := enableFirewall(context.Background(), "https://fleet.example", f.ops)
	if code == 0 || !strings.Contains(message, "active state could not be verified") {
		t.Fatalf("code=%d message=%q", code, message)
	}
}

func TestEnablePreservesOrdinaryUfwRulesAndDisabledConsole(t *testing.T) {
	f := newFakeFirewall("ufw")
	delete(f.installed, "dpkg")
	f.installed["rpm"] = true
	// RPM reports changed files with exit 1, including legitimate user rules.
	f.replies["rpm -V ufw"] = firewallReply{text: "S.5....T.  c /etc/ufw/user.rules\n", err: fmt.Errorf("exit 1")}
	f.replies["ufw show added"] = firewallReply{text: "ufw deny from 198.51.100.9\nufw allow 443/tcp"}
	f.ops.consolePort = func() (int, bool, error) { return 0, false, nil }
	_, _, code, message := enableFirewall(context.Background(), "https://fleet.example", f.ops)
	if code != 0 {
		t.Fatal(message)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "ufw prepend ") || strings.Contains(call, "ufw --force delete ") {
			if !strings.Contains(call, "from 192.0.2.10 to any port 2222 proto tcp") {
				t.Fatalf("unrelated rule changed: %s", call)
			}
		}
	}
}

func TestEnableFirewalldAcceptsStockIPv6Policy(t *testing.T) {
	f := newFakeFirewall("firewalld")
	f.replies["firewall-offline-cmd --get-policies"] = firewallReply{text: "allow-host-ipv6"}
	f.replies["firewall-offline-cmd --info-policy=allow-host-ipv6"] = firewallReply{text: "allow-host-ipv6\n  priority: -15000\n  target: CONTINUE\n  ingress-zones: ANY\n  egress-zones: HOST\n  rich rules:\n    rule family=\"ipv6\" icmp-type name=\"neighbour-advertisement\" accept\n"}
	_, _, code, message := enableFirewall(context.Background(), "https://fleet.example", f.ops)
	if code != 0 {
		t.Fatal(message)
	}
}

func TestFirewalldManagementRulesAreReportedAsAllows(t *testing.T) {
	management := managementRichRule("192.0.2.10", 2222)
	if rule := firewalldRichRule(management); rule.Action != "allow" || rule.Raw != management {
		t.Fatalf("incorrect management rule: %+v", rule)
	}
	if rule := firewalldRichRule(`rule source address="198.51.100.9" drop`); rule.Action != "deny" {
		t.Fatalf("incorrect deny rule: %+v", rule)
	}
}

func TestFirewalldInspectionDoesNotActivateStoppedDaemon(t *testing.T) {
	for _, serviceState := range []string{"inactive", "failed"} {
		f := newFakeFirewall("firewalld")
		f.replies["systemctl show firewalld --property=LoadState,ActiveState"] = firewallReply{text: "LoadState=loaded\nActiveState=" + serviceState}
		state, err := inspectFirewall(context.Background(), f.ops)
		if err != nil || state.active || state.backend != "firewalld" {
			t.Fatalf("service=%s state=%+v err=%v", serviceState, state, err)
		}
		for _, call := range f.calls {
			if call == "firewall-cmd --state" {
				t.Fatalf("%s service inspected through potentially activating D-Bus call", serviceState)
			}
		}
	}
}

func TestFirewalldInspectionFailsSafelyOnUnstableOrUnreadableService(t *testing.T) {
	for _, reply := range []firewallReply{
		{text: "LoadState=loaded\nActiveState=activating"},
		{text: "LoadState=loaded\nActiveState=deactivating"},
		{text: "LoadState=loaded\nActiveState=unknown"},
		{text: "LoadState=not-found\nActiveState=inactive"},
		{text: "LoadState=loaded"},
		{text: "LoadState=loaded\nActiveState=inactive", err: fmt.Errorf("systemd unavailable")},
	} {
		f := newFakeFirewall("firewalld")
		f.replies["systemctl show firewalld --property=LoadState,ActiveState"] = reply
		if _, err := inspectFirewall(context.Background(), f.ops); err == nil {
			t.Fatalf("accepted uncertain systemd state: %q", reply.text)
		}
		for _, call := range f.calls {
			if call == "firewall-cmd --state" {
				t.Fatal("uncertain state must not fall back to D-Bus activation")
			}
		}
	}
}

func TestFirewalldInspectionVerifiesActiveDaemon(t *testing.T) {
	f := newFakeFirewall("firewalld")
	f.active["firewalld"] = true
	f.replies["firewall-cmd --state"] = firewallReply{text: "not running", err: fmt.Errorf("exit 252")}
	if _, err := inspectFirewall(context.Background(), f.ops); err == nil {
		t.Fatal("systemd active alone must not prove a functioning firewalld daemon")
	}
}
