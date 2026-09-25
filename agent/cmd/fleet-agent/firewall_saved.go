package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// ufw show added exposes saved user rules even when the firewall is disabled.
// Its output is parsed as data and passed as argv, never evaluated by a shell.
func splitUfwCommand(line string) ([]string, error) {
	args := []string{}
	var word strings.Builder
	quote := rune(0)
	escaped := false
	started := false
	for _, ch := range line {
		if escaped {
			word.WriteRune(ch)
			escaped = false
			started = true
			continue
		}
		if ch == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			} else {
				word.WriteRune(ch)
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			started = true
			continue
		}
		if ch == ' ' || ch == '\t' {
			if started {
				args = append(args, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		word.WriteRune(ch)
		started = true
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("cannot parse saved UFW rule")
	}
	if started {
		args = append(args, word.String())
	}
	if len(args) < 3 || args[0] != "ufw" {
		return nil, fmt.Errorf("invalid saved UFW rule")
	}
	action := args[1]
	if action == "route" && len(args) > 3 {
		action = args[2]
	}
	if action != "allow" && action != "deny" && action != "reject" && action != "limit" {
		return nil, fmt.Errorf("unsupported saved UFW rule")
	}
	return args, nil
}

func savedUfwID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "saved:" + hex.EncodeToString(sum[:])
}

func savedUfwRules(ctx context.Context, ops firewallOps) ([]FirewallRule, error) {
	out, err := ops.privileged(ctx, "ufw", "show", "added")
	if err != nil {
		return nil, fmt.Errorf("cannot read saved UFW rules: %s: %w", strings.TrimSpace(string(out)), err)
	}
	rules := []FirewallRule{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "Added user rules (see 'ufw status' for running firewall):" || strings.HasPrefix(line, "(None)") {
			continue
		}
		args, err := splitUfwCommand(line)
		if err != nil {
			return nil, err
		}
		action := args[1]
		if action == "route" {
			action = args[2]
		}
		rules = append(rules, FirewallRule{Backend: "ufw", ID: savedUfwID(line), Raw: line, Action: action})
	}
	return rules, nil
}

func queryInactiveUfw(ctx context.Context, ops firewallOps) (string, string, int, string) {
	rules, err := savedUfwRules(ctx, ops)
	if err != nil {
		return "", "", 1, err.Error()
	}
	body, _ := json.Marshal(map[string]any{"backend": "ufw", "status": "inactive", "rules": rules, "rules_scope": "saved", "notice": "Firewall is OFF. Saved rules are not enforced. An unspecific saved UFW rule may cover both IPv4 and IPv6."})
	return string(body), "", 0, ""
}

func deleteSavedUfwRules(ctx context.Context, rules []FirewallRule, ops firewallOps) (string, string, int, string) {
	current, err := savedUfwRules(ctx, ops)
	fail := func(err error) (string, string, int, string) {
		return "Some earlier removals may have completed; scan again.", "", 1, err.Error()
	}
	if err != nil {
		return fail(err)
	}
	for _, selected := range rules {
		found := false
		for _, rule := range current {
			if selected.ID == rule.ID && selected.Raw == rule.Raw {
				found = true
			}
		}
		if !found {
			return fail(fmt.Errorf("saved rules changed; scan hosts again"))
		}
	}
	for _, selected := range rules {
		fresh, err := savedUfwRules(ctx, ops)
		if err != nil {
			return fail(err)
		}
		if !reflect.DeepEqual(fresh, current) {
			return fail(fmt.Errorf("saved rules changed; scan hosts again"))
		}
		args, err := splitUfwCommand(selected.Raw)
		if err != nil {
			return fail(err)
		}
		deleteArgs := append([]string{"--force", "delete"}, args[1:]...)
		if args[1] == "route" {
			deleteArgs = append([]string{"--force", "route", "delete"}, args[2:]...)
		}
		out, err := ops.privileged(ctx, "ufw", deleteArgs...)
		if err != nil {
			return fail(fmt.Errorf("saved rule deletion failed: %s: %w", strings.TrimSpace(string(out)), err))
		}
		expected := []FirewallRule{}
		for _, rule := range current {
			if rule.ID != selected.ID {
				expected = append(expected, rule)
			}
		}
		fresh, err = savedUfwRules(ctx, ops)
		if err != nil {
			return fail(err)
		}
		if !reflect.DeepEqual(fresh, expected) {
			return fail(fmt.Errorf("could not verify saved rule removal; scan again"))
		}
		current = fresh
	}
	return fmt.Sprintf("%d saved rule(s) removed and verified. Firewall remains OFF.", len(rules)), "", 0, ""
}
