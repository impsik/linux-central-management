package main

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestDeleteSelectedUfwRules(t *testing.T) {
	for _, scenario := range []string{"success", "stale", "noop", "duplicate", "concurrent"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFakeFirewall("ufw")
			f.active["ufw"] = true
			lines := []string{"18080/tcp ALLOW IN 192.0.2.10", "22/tcp ALLOW IN 192.0.2.10", "22/tcp DENY IN Anywhere", "22/tcp (v6) DENY IN Anywhere (v6)"}
			selected := []FirewallRule{{Backend: "ufw", ID: "2", Raw: "[ 2] " + lines[1]}, {Backend: "ufw", ID: "4", Raw: "[ 4] " + lines[3]}}
			if scenario == "stale" {
				selected[0].Raw = "[ 2] 22/tcp ALLOW IN Anywhere"
			}
			if scenario == "duplicate" {
				selected = append(selected, selected[0])
			}
			deleted := []string{}
			snapshots := 0
			f.ops.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				key := name + " " + strings.Join(args, " ")
				if key == "sudo -n ufw status numbered" {
					snapshots++
					if scenario == "concurrent" && snapshots == 2 {
						lines[0] = "443/tcp ALLOW IN Anywhere"
					}
					text := "Status: active\n"
					for i, line := range lines {
						text += fmt.Sprintf("[ %d] %s\n", i+1, line)
					}
					return []byte(text), nil
				}
				if strings.HasPrefix(key, "sudo -n ufw --force delete ") {
					id, _ := strconv.Atoi(args[len(args)-1])
					deleted = append(deleted, strconv.Itoa(id))
					if scenario != "noop" {
						lines = append(lines[:id-1], lines[id:]...)
					}
					return []byte("Could not delete non-existent rule"), nil
				}
				return f.run(ctx, name, args...)
			}
			_, _, code, msg := deleteSelectedFirewallRules(context.Background(), selected, f.ops)
			if scenario == "success" {
				if code != 0 {
					t.Fatal(msg)
				}
				if !reflect.DeepEqual(deleted, []string{"4", "2"}) {
					t.Fatal(deleted)
				}
				if !reflect.DeepEqual(lines, []string{"18080/tcp ALLOW IN 192.0.2.10", "22/tcp DENY IN Anywhere"}) {
					t.Fatal(lines)
				}
			} else {
				if code == 0 {
					t.Fatal("false success")
				}
				if scenario != "noop" && len(deleted) != 0 {
					t.Fatalf("mutated stale selection: %v", deleted)
				}
			}
		})
	}
}

func TestDeleteSelectedFirewalldRule(t *testing.T) {
	for _, scenario := range []string{"active", "inactive", "noop", "missing", "read-error"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFakeFirewall("firewalld")
			f.active["firewalld"] = scenario != "inactive"
			raw := `rule source address="192.0.2.10" port port="8080" protocol="tcp" accept`
			present := map[bool]bool{false: scenario != "missing", true: scenario != "missing"}
			removals := 0
			f.ops.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				key := name + " " + strings.Join(args, " ")
				if strings.Contains(key, "--reload") {
					t.Fatal("must not reload unrelated runtime rules")
				}
				if strings.Contains(key, "--zone=public") {
					permanent := strings.Contains(key, "--permanent") || strings.Contains(key, "offline")
					last := args[len(args)-1]
					if strings.HasPrefix(last, "--list-") {
						if scenario == "read-error" {
							return nil, fmt.Errorf("read failed")
						}
						if last == "--list-rich-rules" && present[permanent] {
							return []byte(raw), nil
						}
						return nil, nil
					}
					if last == "--remove-rich-rule="+raw {
						removals++
						if scenario != "noop" {
							present[permanent] = false
						}
						return []byte("success"), nil
					}
				}
				return f.run(ctx, name, args...)
			}
			_, _, code, msg := deleteSelectedFirewallRules(context.Background(), []FirewallRule{{Backend: "firewalld", Zone: "public", Raw: raw}}, f.ops)
			if scenario == "active" || scenario == "inactive" {
				if code != 0 {
					t.Fatal(msg)
				}
				want := 2
				if scenario == "inactive" {
					want = 1
				}
				if removals != want {
					t.Fatal(removals)
				}
			} else if code == 0 {
				t.Fatal("false success")
			}
		})
	}
}

func TestDeleteUfwAllowPreservesSource(t *testing.T) {
	got := buildUfwArgs("delete", 22, "tcp", "192.0.2.10", "")
	want := []string{"-n", "ufw", "--force", "delete", "allow", "from", "192.0.2.10", "to", "any", "port", "22", "proto", "tcp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}
