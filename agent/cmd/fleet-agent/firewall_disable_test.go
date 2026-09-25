package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
)

func disableCommand(backend string) string {
	if backend == "ufw" {
		return "ufw --force disable"
	}
	return "systemctl disable --now firewalld"
}

func TestDisableFirewallPreservesSavedRulesWithoutManagementDiscovery(t *testing.T) {
	for _, backend := range []string{"ufw", "firewalld"} {
		for _, active := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/active=%v", backend, active), func(t *testing.T) {
				f := newFakeFirewall(backend)
				f.active[backend] = active
				f.ops.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
					t.Fatal("disable must not discover Master addresses")
					return nil, nil
				}
				f.ops.consolePort = func() (int, bool, error) {
					t.Fatal("disable must not inspect Console configuration")
					return 0, false, nil
				}
				f.ops.readFile = func(string) ([]byte, error) {
					t.Fatal("disable must not read/change saved configuration")
					return nil, nil
				}
				stdout, _, code, message := disableFirewall(context.Background(), f.ops)
				if code != 0 {
					t.Fatalf("disable failed: %s; commands: %v", message, f.calls)
				}
				var result firewallDisableResult
				if err := json.Unmarshal([]byte(stdout), &result); err != nil {
					t.Fatal(err)
				}
				if result.Backend != backend || result.Status != "inactive" || result.AlreadyInactive == active {
					t.Fatalf("unexpected result: %+v", result)
				}
				disables, stateReads, dbusReads := 0, 0, 0
				for _, call := range f.calls {
					switch call {
					case disableCommand(backend):
						disables++
					case "ufw status", "systemctl show firewalld --property=LoadState,ActiveState":
						stateReads++
					case "firewall-cmd --state":
						dbusReads++
						if !active || disables != 0 {
							t.Fatal("inactive status/disable verification must not activate firewalld through D-Bus")
						}
					default:
						t.Fatalf("unexpected command could change saved rules/discover management: %s", call)
					}
				}
				if disables != 1 || stateReads != 2 || f.active[backend] {
					t.Fatalf("must disable boot activation and verify state even when already inactive: %v", f.calls)
				}
				if backend == "firewalld" && active && dbusReads != 1 {
					t.Fatal("active firewalld must still be verified")
				}
			})
		}
	}
}

func TestDisableFirewallRejectsCommandErrorsAndFalseSuccess(t *testing.T) {
	for _, backend := range []string{"ufw", "firewalld"} {
		for _, failure := range []string{"command error", "still active", "state read error"} {
			t.Run(backend+"/"+failure, func(t *testing.T) {
				f := newFakeFirewall(backend)
				f.active[backend] = true
				want := "inactive state could not be verified"
				switch failure {
				case "command error":
					f.replies[disableCommand(backend)] = firewallReply{text: "permission denied", err: fmt.Errorf("exit 1")}
					want = "deactivation failed"
				case "still active":
					f.replies[disableCommand(backend)] = firewallReply{}
				case "state read error":
					f.ops.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
						if !f.active[backend] {
							return []byte("state unavailable"), fmt.Errorf("state read failed")
						}
						return f.run(ctx, name, args...)
					}
				}
				_, _, code, message := disableFirewall(context.Background(), f.ops)
				if code == 0 || !strings.Contains(message, want) {
					t.Fatalf("code=%d message=%q, want %q", code, message, want)
				}
				if f.activated() {
					t.Fatal("disable must never enable a firewall")
				}
			})
		}
	}
}

func TestDisableFirewallRejectsAmbiguousManagersBeforeChanges(t *testing.T) {
	for _, active := range []bool{true, false} {
		f := newFakeFirewall("ufw")
		f.installed["firewall-cmd"] = true
		f.active["ufw"], f.active["firewalld"] = active, active
		_, _, code, message := disableFirewall(context.Background(), f.ops)
		if code == 0 || !strings.Contains(message, "both UFW and firewalld") {
			t.Fatalf("ambiguous state accepted: active=%v code=%d error=%q", active, code, message)
		}
		for _, call := range f.calls {
			if call != "ufw status" && call != "firewall-cmd --state" && call != "systemctl show firewalld --property=LoadState,ActiveState" {
				t.Fatalf("ambiguous managers were changed: %v", f.calls)
			}
		}
	}
}

func TestDisableSelectsOnlyActiveManagerWhenBothInstalled(t *testing.T) {
	for _, backend := range []string{"ufw", "firewalld"} {
		f := newFakeFirewall(backend)
		f.installed["ufw"], f.installed["firewall-cmd"] = true, true
		f.active[backend] = true
		_, _, code, message := disableFirewall(context.Background(), f.ops)
		if code != 0 {
			t.Fatalf("%s: %s; expected both managers inactive after disabling initially active one", backend, message)
		}
		for _, call := range f.calls {
			if call != "ufw status" && call != "firewall-cmd --state" && call != "systemctl show firewalld --property=LoadState,ActiveState" && call != disableCommand(backend) {
				t.Fatalf("changed the other manager: %v", f.calls)
			}
		}
	}
}
