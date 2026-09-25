package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type firewallNoRule struct{}

func (firewallNoRule) Error() string { return "exit 1" }
func (firewallNoRule) ExitCode() int { return 1 }

func TestUfwSavedRulesLifecycle(t *testing.T) {
	f := newFakeFirewall("ufw")
	saved := []string{}
	ctx := context.Background()
	f.ops.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		key := name + " " + strings.Join(args, " ")
		if key == "sudo -n ufw show added" {
			return []byte("Added user rules (see 'ufw status' for running firewall):\n" + strings.Join(saved, "\n")), nil
		}
		if key == "sudo -n ufw allow 1122/tcp" {
			if len(saved) > 0 {
				return []byte("Skipping adding existing rule"), nil
			}
			saved = append(saved, "ufw allow 1122/tcp")
			return []byte("Rule added"), nil
		}
		if key == "sudo -n ufw --force delete allow 1122/tcp" || key == "sudo -n ufw --force delete 1" {
			saved = []string{}
			return []byte("Rule deleted"), nil
		}
		if key == "sudo -n ufw status numbered" {
			out := "Status: active\n"
			if len(saved) > 0 {
				out += "[ 1] 1122/tcp ALLOW IN Anywhere\n"
			}
			return []byte(out), nil
		}
		return f.run(ctx, name, args...)
	}
	out, _, code, msg := controlUfwWithOps(ctx, "allow", 1122, "tcp", "", "", f.ops)
	if code != 0 || !strings.Contains(out, "Firewall is OFF") {
		t.Fatalf("%s %s", out, msg)
	}
	_, _, code, msg = controlUfwWithOps(ctx, "allow", 1122, "tcp", "", "", f.ops)
	if code != 0 || len(saved) != 1 {
		t.Fatalf("duplicate changed rules: %s", msg)
	}
	out, _, code, msg = queryInactiveUfw(ctx, f.ops)
	if code != 0 || !strings.Contains(out, "1122/tcp") {
		t.Fatal(out, msg)
	}
	var report struct{ Rules []FirewallRule }
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	_, _, code, msg = deleteSelectedFirewallRules(ctx, report.Rules, f.ops)
	if code != 0 || len(saved) != 0 || f.active["ufw"] {
		t.Fatal("inactive removal", msg)
	}
	_, _, code, msg = controlUfwWithOps(ctx, "allow", 1122, "tcp", "", "", f.ops)
	if code != 0 {
		t.Fatal(msg)
	}
	_, _, code, msg = enableFirewall(ctx, "https://fleet.example.test", f.ops)
	if code != 0 || !f.active["ufw"] || len(saved) != 1 {
		t.Fatal("enable lost saved rules", msg)
	}
	out, _, code, msg = queryUfwWithOps(ctx, f.ops)
	if code != 0 {
		t.Fatal(msg)
	}
	json.Unmarshal([]byte(out), &report)
	_, _, code, msg = deleteSelectedFirewallRules(ctx, report.Rules, f.ops)
	if code != 0 || len(saved) != 0 {
		t.Fatal("active removal", msg)
	}
	_, _, code, msg = disableFirewall(ctx, f.ops)
	if code != 0 || f.active["ufw"] {
		t.Fatal("disable", msg)
	}
}

func TestSavedUfwParserKeepsQuotedProfileSourceAndComments(t *testing.T) {
	args, err := splitUfwCommand(`ufw allow from 192.0.2.10 to any app 'OpenSSH' comment 'Master access'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ufw", "allow", "from", "192.0.2.10", "to", "any", "app", "OpenSSH", "comment", "Master access"}
	if !reflect.DeepEqual(args, want) {
		t.Fatal(args)
	}
	for _, bad := range []string{"ufw reset", "ufw enable", "ufw allow 'unclosed"} {
		if _, err := splitUfwCommand(bad); err == nil {
			t.Fatal(bad)
		}
	}
}

func TestFirewalldChangesBothStoresWithoutReloadAndSupportsInactive(t *testing.T) {
	for _, active := range []bool{true, false} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			f := newFakeFirewall("firewalld")
			f.active["firewalld"] = active
			entries := map[string]bool{}
			mutations := 0
			f.ops.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				key := strings.Join(args, " ")
				if strings.Contains(key, "--reload") {
					t.Fatal("unexpected reload")
				}
				if strings.HasSuffix(key, "--get-default-zone") {
					return []byte("public"), nil
				}
				last := args[len(args)-1]
				store := "runtime"
				if strings.Contains(key, "--permanent") || strings.Contains(key, "offline") {
					store = "saved"
				}
				for _, verb := range []string{"query", "add", "remove"} {
					prefix := "--" + verb + "-rich-rule="
					if strings.HasPrefix(last, prefix) {
						ruleKey := store + strings.TrimPrefix(last, prefix)
						if verb == "query" {
							if entries[ruleKey] {
								return []byte("yes"), nil
							}
							return []byte("no"), firewallNoRule{}
						}
						mutations++
						entries[ruleKey] = verb == "add"
						return []byte("success"), nil
					}
				}
				return f.run(ctx, name, args...)
			}
			ctx := context.Background()
			out, _, code, msg := controlFirewalldWithOps(ctx, "allow", 443, "tcp", "192.0.2.10", "", active, f.ops)
			if code != 0 {
				t.Fatal(out, msg)
			}
			want := 1
			if active {
				want = 2
			}
			if mutations != want {
				t.Fatal(mutations)
			}
			_, _, code, msg = controlFirewalldWithOps(ctx, "allow", 443, "tcp", "192.0.2.10", "", active, f.ops)
			if code != 0 || mutations != want {
				t.Fatal("duplicate", msg)
			}
		})
	}
	kind, rule := firewalldRuleSpec("deny", 443, "tcp", "", "")
	if kind != "rich-rule" || strings.Contains(rule, "family=") {
		t.Fatal("unscoped deny must cover both families", rule)
	}
}

func TestFirewalldScanNeverHidesCommandFailure(t *testing.T) {
	f := newFakeFirewall("firewalld")
	f.replies["firewall-offline-cmd --zone=public --list-services"] = firewallReply{err: fmt.Errorf("read failed")}
	_, _, code, msg := queryFirewalldWithOps(context.Background(), false, f.ops)
	if code == 0 || !strings.Contains(msg, "incomplete") {
		t.Fatal(msg)
	}
}

func TestRemoveSavedUfwRouteRulePreservesOtherRules(t *testing.T) {
	f := newFakeFirewall("ufw")
	route := "ufw route allow in on eth0 out on eth1 to 192.0.2.8 port 443 proto tcp"
	keep := "ufw allow 22/tcp"
	saved := []string{route, keep}
	f.ops.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		key := name + " " + strings.Join(args, " ")
		if key == "sudo -n ufw show added" {
			return []byte(strings.Join(saved, "\n")), nil
		}
		if key == "sudo -n ufw --force route delete allow in on eth0 out on eth1 to 192.0.2.8 port 443 proto tcp" {
			saved = []string{keep}
			return []byte("Rule deleted"), nil
		}
		return f.run(ctx, name, args...)
	}
	_, _, code, msg := deleteSelectedFirewallRules(context.Background(), []FirewallRule{{Backend: "ufw", ID: savedUfwID(route), Raw: route}}, f.ops)
	if code != 0 || !reflect.DeepEqual(saved, []string{keep}) || f.active["ufw"] {
		t.Fatal(saved, msg)
	}
}
