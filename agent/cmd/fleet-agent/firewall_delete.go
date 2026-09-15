package main

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Deletion uses fresh, exact rule identities, never reconstructs a rule from
// the port/source form. UFW numbering is checked again before each deletion.
func deleteSelectedFirewallRules(ctx context.Context, rules []FirewallRule, ops firewallOps) (string, string, int, string) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	removed := 0
	fail := func(err error) (string, string, int, string) {
		return fmt.Sprintf("%d rule(s) removed and verified. Failed operations may have partially changed rules; scan again before retrying.", removed), "", 1, err.Error()
	}
	if len(rules) == 0 || len(rules) > 100 {
		return fail(fmt.Errorf("select between 1 and 100 rules"))
	}
	state, err := inspectFirewall(ctx, ops)
	if err != nil {
		return fail(err)
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		key := rule.Backend + "\x00" + rule.Zone + "\x00" + rule.Raw
		if rule.Backend == "ufw" {
			key = "ufw:" + rule.ID
		}
		if rule.Backend != state.backend || rule.Raw == "" || len(rule.Raw) > 4096 || seen[key] {
			return fail(fmt.Errorf("invalid or duplicate rule selection; scan hosts again"))
		}
		seen[key] = true
	}
	if state.backend == "ufw" {
		snapshot, err := ufwRuleSnapshot(ctx, ops)
		if err != nil {
			return fail(err)
		}
		ids := make([]int, 0, len(rules))
		for _, rule := range rules {
			id, err := strconv.Atoi(rule.ID)
			if err != nil || id < 1 || id > len(snapshot) || ufwRuleText(rule.Raw) != snapshot[id-1] || parseUfwStatusLine(rule.Raw).ID != rule.ID {
				return fail(fmt.Errorf("firewall rules changed; scan hosts again before removing rules"))
			}
			ids = append(ids, id)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(ids)))
		for _, id := range ids {
			current, err := ufwRuleSnapshot(ctx, ops)
			if err != nil {
				return fail(err)
			}
			if !reflect.DeepEqual(current, snapshot) {
				return fail(fmt.Errorf("firewall rules changed; scan hosts again"))
			}
			out, err := ops.privileged(ctx, "ufw", "--force", "delete", strconv.Itoa(id))
			if err != nil {
				return fail(fmt.Errorf("ufw delete failed: %s: %w", strings.TrimSpace(string(out)), err))
			}
			expected := append([]string{}, snapshot[:id-1]...)
			expected = append(expected, snapshot[id:]...)
			current, err = ufwRuleSnapshot(ctx, ops)
			if err != nil {
				return fail(err)
			}
			if !reflect.DeepEqual(current, expected) {
				return fail(fmt.Errorf("could not verify rule removal; scan hosts again"))
			}
			removed++
			snapshot = current
		}
	} else if state.backend == "firewalld" {
		// Query both stores before changing anything. Avoid reload, which would
		// replace unrelated runtime-only rules with permanent configuration.
		type removal struct {
			rule   FirewallRule
			flag   string
			stores [][]string
		}
		plans := []removal{}
		command := "firewall-cmd"
		if !state.active {
			command = "firewall-offline-cmd"
		}
		for _, rule := range rules {
			if !safeZone(rule.Zone) {
				return fail(fmt.Errorf("invalid firewall zone; scan hosts again"))
			}
			stores := [][]string{{"--zone=" + rule.Zone}}
			if state.active {
				stores = append(stores, []string{"--permanent", "--zone=" + rule.Zone})
			}
			plan := removal{rule: rule}
			for _, store := range stores {
				flag, err := findFirewalldRule(ctx, ops, command, store, rule.Raw)
				if err != nil {
					return fail(err)
				}
				if flag != "" {
					plan.flag = flag
					plan.stores = append(plan.stores, store)
				}
			}
			if len(plan.stores) == 0 {
				return fail(fmt.Errorf("firewall rule no longer exists; scan hosts again"))
			}
			plans = append(plans, plan)
		}
		for _, plan := range plans {
			for _, store := range plan.stores {
				flag, err := findFirewalldRule(ctx, ops, command, store, plan.rule.Raw)
				if err != nil {
					return fail(err)
				}
				if flag != plan.flag {
					return fail(fmt.Errorf("firewall rules changed; scan hosts again"))
				}
				args := append(append([]string{}, store...), "--remove-"+flag+"="+plan.rule.Raw)
				out, err := ops.privileged(ctx, command, args...)
				if err != nil {
					return fail(fmt.Errorf("firewalld removal failed (configuration may be partially changed): %s: %w", strings.TrimSpace(string(out)), err))
				}
				flag, err = findFirewalldRule(ctx, ops, command, store, plan.rule.Raw)
				if err != nil {
					return fail(err)
				}
				if flag != "" {
					return fail(fmt.Errorf("could not verify firewall rule removal"))
				}
			}
			removed++
		}
	} else {
		return fail(fmt.Errorf("unsupported firewall backend"))
	}
	return fmt.Sprintf("%d rule(s) removed and verified", removed), "", 0, ""
}

func ufwRuleText(raw string) string {
	if i := strings.Index(raw, "]"); i >= 0 {
		raw = raw[i+1:]
	}
	return strings.Join(strings.Fields(raw), " ")
}

func ufwRuleSnapshot(ctx context.Context, ops firewallOps) ([]string, error) {
	out, err := ops.privileged(ctx, "ufw", "status", "numbered")
	if err != nil {
		return nil, fmt.Errorf("cannot read UFW rules: %w", err)
	}
	if !strings.Contains(string(out), "Status: active") {
		return nil, fmt.Errorf("UFW must be active to inspect numbered rules")
	}
	rules := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		rule := parseUfwStatusLine(line)
		if rule.ID != strconv.Itoa(len(rules)+1) || rule.Action == "" {
			return nil, fmt.Errorf("cannot identify UFW rule; scan hosts again")
		}
		rules = append(rules, ufwRuleText(line))
	}
	return rules, nil
}

func findFirewalldRule(ctx context.Context, ops firewallOps, command string, store []string, raw string) (string, error) {
	for _, kind := range []string{"port", "service", "rich-rule"} {
		args := append(append([]string{}, store...), "--list-"+kind+"s")
		out, err := ops.privileged(ctx, command, args...)
		if err != nil {
			return "", fmt.Errorf("cannot read firewalld rules: %s: %w", strings.TrimSpace(string(out)), err)
		}
		entries := strings.Fields(string(out))
		if kind == "rich-rule" {
			entries = strings.Split(strings.TrimSpace(string(out)), "\n")
		}
		for _, entry := range entries {
			if strings.TrimSpace(entry) == raw {
				return kind, nil
			}
		}
	}
	return "", nil
}
