package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

func ruleChangeResult(changed bool, active bool) (string, string, int, string) {
	message := "Rule saved and verified."
	if !changed {
		message = "Rule already in the requested state; no changes made."
	}
	if !active {
		message += " Firewall is OFF; saved rules are not enforced."
	} else {
		message += " Firewall is ON. Existing rule order and policy still apply."
	}
	body, _ := json.Marshal(map[string]any{"changed": changed, "message": message})
	return string(body), "", 0, ""
}

func controlUfwWithOps(ctx context.Context, action string, port int, protocol, source, service string, ops firewallOps) (string, string, int, string) {
	before, err := savedUfwRules(ctx, ops)
	if err != nil {
		return "", "", 1, err.Error()
	}
	args := buildUfwArgs(action, port, protocol, source, service)
	out, err := ops.privileged(ctx, "ufw", args[2:]...)
	if err != nil {
		return string(out), "", 1, fmt.Sprintf("UFW rule change failed: %v", err)
	}
	after, err := savedUfwRules(ctx, ops)
	if err != nil {
		return string(out), "", 1, "Cannot verify saved rules after the command; scan again"
	}
	changed := !reflect.DeepEqual(before, after)
	if !changed && !strings.Contains(strings.ToLower(string(out)), "skipping adding existing rule") {
		return string(out), "", 1, "No matching rule changed; scan hosts and select the exact rule"
	}
	status, err := ops.privileged(ctx, "ufw", "status")
	if err != nil {
		return string(out), "", 1, "Rule saved but firewall status could not be verified"
	}
	return ruleChangeResult(changed, strings.Contains(string(status), "Status: active"))
}

func firewalldRuleSpec(action string, port int, protocol, source, service string) (string, string) {
	if action == "deny" || source != "" {
		parts := []string{"rule"}
		if source != "" {
			family := "ipv4"
			if strings.Contains(source, ":") {
				family = "ipv6"
			}
			parts = append(parts, fmt.Sprintf(`family="%s"`, family), fmt.Sprintf(`source address="%s"`, source))
		}
		if service != "" {
			parts = append(parts, fmt.Sprintf(`service name="%s"`, service))
		} else {
			parts = append(parts, fmt.Sprintf(`port port="%d" protocol="%s"`, port, protocol))
		}
		verdict := "accept"
		if action == "deny" {
			verdict = "reject"
		}
		return "rich-rule", strings.Join(append(parts, verdict), " ")
	}
	if service != "" {
		return "service", service
	}
	return "port", fmt.Sprintf("%d/%s", port, protocol)
}

func firewalldQueryRule(ctx context.Context, ops firewallOps, command string, store []string, kind, spec string) (bool, error) {
	out, err := ops.privileged(ctx, command, append(append([]string{}, store...), "--query-"+kind+"="+spec)...)
	answer := strings.TrimSpace(string(out))
	if err == nil && answer == "yes" {
		return true, nil
	}
	if exit, ok := err.(interface{ ExitCode() int }); ok && exit.ExitCode() == 1 && answer == "no" {
		return false, nil
	}
	return false, fmt.Errorf("cannot verify firewalld rule: %s (%v)", answer, err)
}

func controlFirewalldWithOps(ctx context.Context, action string, port int, protocol, source, service string, active bool, ops firewallOps) (string, string, int, string) {
	command := "firewall-cmd"
	if !active {
		command = "firewall-offline-cmd"
	}
	out, err := ops.privileged(ctx, command, "--get-default-zone")
	zone := strings.TrimSpace(string(out))
	if err != nil || !safeZone(zone) {
		return "", "", 1, "Cannot determine firewall default zone"
	}
	kind, spec := firewalldRuleSpec(action, port, protocol, source, service)
	stores := [][]string{{"--zone=" + zone}}
	if active {
		stores = [][]string{{"--permanent", "--zone=" + zone}, {"--zone=" + zone}}
	}
	present := []bool{}
	for _, store := range stores {
		exists, err := firewalldQueryRule(ctx, ops, command, store, kind, spec)
		if err != nil {
			return "", "", 1, err.Error()
		}
		present = append(present, exists)
	}
	desired := action != "delete"
	changed := false
	for i, store := range stores {
		if present[i] == desired {
			continue
		}
		verb := "--add-"
		if !desired {
			verb = "--remove-"
		}
		out, err = ops.privileged(ctx, command, append(append([]string{}, store...), verb+kind+"="+spec)...)
		if err != nil {
			return string(out), "", 1, "Firewalld rule change failed; some configuration may have changed. Scan again."
		}
		exists, err := firewalldQueryRule(ctx, ops, command, store, kind, spec)
		if err != nil || exists != desired {
			return string(out), "", 1, "Could not verify firewalld rule change; scan again"
		}
		changed = true
	}
	return ruleChangeResult(changed, active)
}

// Keep saved rules visible as well as runtime-only rules, without a reload.
func queryFirewalldWithOps(ctx context.Context, active bool, ops firewallOps) (string, string, int, string) {
	command := "firewall-cmd"
	status := "running"
	if !active {
		command = "firewall-offline-cmd"
		status = "inactive"
	}
	out, err := ops.privileged(ctx, command, "--get-default-zone")
	zone := strings.TrimSpace(string(out))
	if err != nil || !safeZone(zone) {
		return "", "", 1, "Cannot read firewalld default zone"
	}
	type ruleStore struct {
		args  []string
		scope string
	}
	stores := []ruleStore{{[]string{"--zone=" + zone}, "saved"}}
	if active {
		stores = []ruleStore{{[]string{"--zone=" + zone}, "runtime"}, {[]string{"--permanent", "--zone=" + zone}, "saved"}}
	}
	rules := []FirewallRule{}
	indexes := map[string]int{}
	for _, store := range stores {
		for _, kind := range []string{"ports", "services", "rich-rules"} {
			out, err := ops.privileged(ctx, command, append(append([]string{}, store.args...), "--list-"+kind)...)
			if err != nil {
				return "", string(out), 1, "Cannot read firewalld " + store.scope + " " + kind + "; rule list is incomplete"
			}
			entries := strings.Fields(string(out))
			if kind == "rich-rules" {
				entries = strings.Split(strings.TrimSpace(string(out)), "\n")
			}
			for _, entry := range entries {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				key := kind + ":" + entry
				if index, ok := indexes[key]; ok {
					rules[index].Scope = "runtime + saved"
					continue
				}
				rule := FirewallRule{Backend: "firewalld", Raw: entry, Action: "allow", Zone: zone, Scope: store.scope}
				if kind == "rich-rules" {
					rule = firewalldRichRule(entry)
					rule.Zone = zone
					rule.Scope = store.scope
				} else if kind == "services" {
					rule.Service = entry
				} else {
					parts := strings.SplitN(entry, "/", 2)
					rule.Port = parts[0]
					if len(parts) == 2 {
						rule.Protocol = parts[1]
					}
				}
				indexes[key] = len(rules)
				rules = append(rules, rule)
			}
		}
	}
	notice := "Default zone only. Other zones and custom firewall rules are not shown."
	if !active {
		notice = "Firewall is OFF; saved rules are not enforced. " + notice
	}
	body, _ := json.Marshal(map[string]any{"backend": "firewalld", "status": status, "zone": zone, "rules": rules, "notice": notice})
	return string(body), "", 0, ""
}
