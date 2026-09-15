package main

import (
	"context"
	"encoding/json"
	"time"
)

type firewallDisableResult struct {
	Backend         string `json:"backend"`
	Status          string `json:"status"`
	AlreadyInactive bool   `json:"already_inactive"`
}

func disableFirewall(ctx context.Context, ops firewallOps) (string, string, int, string) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	state, err := inspectFirewall(ctx, ops)
	if err != nil {
		return "", "", 1, err.Error()
	}
	// Disable boot activation even when the current runtime state is inactive.
	// These commands retain saved rules and require no management-port changes.
	if state.backend == "ufw" {
		if out, err := ops.privileged(ctx, "ufw", "--force", "disable"); err != nil {
			return string(out), "", 1, "UFW deactivation failed"
		}
	} else {
		if out, err := ops.privileged(ctx, "systemctl", "disable", "--now", "firewalld"); err != nil {
			return string(out), "", 1, "firewalld deactivation failed"
		}
	}
	// If both managers are installed, the initially active one was unambiguous.
	// Both being inactive afterward is the expected result, not a selection error.
	installed, active, err := inspectFirewallManagers(ctx, ops)
	verified := false
	for _, backend := range installed {
		if backend == state.backend {
			verified = true
		}
	}
	if err != nil || !verified || len(active) != 0 {
		return "", "", 1, "firewall deactivation command completed but inactive state could not be verified"
	}
	body, _ := json.Marshal(firewallDisableResult{
		Backend: state.backend, Status: "inactive", AlreadyInactive: !state.active,
	})
	return string(body), "", 0, ""
}
