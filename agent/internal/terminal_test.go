package internal

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestTerminalSSHTargetUsesOverride(t *testing.T) {
	t.Setenv("FLEET_TERMINAL_SSH_HOST", "192.0.2.10")

	if got := terminalSSHTarget(); got != "192.0.2.10" {
		t.Fatalf("terminalSSHTarget() = %q, want override", got)
	}
}

func TestTerminalSSHCommandUsesResolvedTarget(t *testing.T) {
	t.Setenv("FLEET_TERMINAL_SSH_HOST", "192.0.2.10")

	cmd := terminalSSHCommand("imre")
	got := strings.Join(cmd.Args, " ")
	if !strings.Contains(got, "imre@192.0.2.10") {
		t.Fatalf("terminalSSHCommand args = %q, want target user@host", got)
	}
	if strings.Contains(got, "imre@localhost") {
		t.Fatalf("terminalSSHCommand args = %q, should not force localhost", got)
	}
	if !strings.Contains(got, "NumberOfPasswordPrompts=3") {
		t.Fatalf("terminalSSHCommand args = %q, want explicit password prompt count", got)
	}
}

func TestPrefersSSHConsoleBackendHonorsExplicitBackend(t *testing.T) {
	t.Setenv("FLEET_TERMINAL_BACKEND", "ssh")
	if !prefersSSHConsoleBackend() {
		t.Fatal("prefersSSHConsoleBackend() = false, want true for explicit ssh backend")
	}

	t.Setenv("FLEET_TERMINAL_BACKEND", "login")
	if prefersSSHConsoleBackend() {
		t.Fatal("prefersSSHConsoleBackend() = true, want false for explicit login backend")
	}
}

func TestConsoleDefaultsToLocalLogin(t *testing.T) {
	for _, backend := range []string{"", "auto", "login"} {
		t.Run("backend="+backend, func(t *testing.T) {
			t.Setenv("FLEET_TERMINAL_BACKEND", backend)
			if prefersSSHConsoleBackend() {
				t.Fatal("console must use local login independently of SSH availability")
			}
			cmd := loginCommand()
			args := strings.Join(cmd.Args, " ")
			if strings.Contains(args, "terminal-ssh-login") || strings.Contains(args, " -f ") {
				t.Fatalf("console must authenticate through local login: %s", args)
			}
		})
	}
}

func TestRunTerminalSSHLoginFromArgsIgnoresNormalAgentStart(t *testing.T) {
	if RunTerminalSSHLoginFromArgs([]string{os.Args[0]}) {
		t.Fatal("RunTerminalSSHLoginFromArgs() = true for normal agent args")
	}
}

func TestSameHostOrigin(t *testing.T) {
	if !sameHostOrigin(&http.Request{Host: "agent.local:18080", Header: http.Header{}}) {
		t.Fatal("sameHostOrigin without Origin = false, want true")
	}
	if !sameHostOrigin(&http.Request{Host: "agent.local:18080", Header: http.Header{"Origin": []string{"http://agent.local:18080"}}}) {
		t.Fatal("sameHostOrigin matching Origin = false, want true")
	}
	if sameHostOrigin(&http.Request{Host: "agent.local:18080", Header: http.Header{"Origin": []string{"http://evil.local"}}}) {
		t.Fatal("sameHostOrigin cross-site Origin = true, want false")
	}
}

func TestTerminalListenDefaultsToManagementTarget(t *testing.T) {
	t.Setenv("FLEET_TERMINAL_LISTEN", "")
	t.Setenv("FLEET_TERMINAL_SSH_HOST", "192.0.2.10")

	if got := terminalListenAddr(); got != "192.0.2.10:18080" {
		t.Fatalf("terminalListenAddr() = %q, want management target default", got)
	}
}

func TestTerminalListenAllowsExplicitLoopback(t *testing.T) {
	t.Setenv("FLEET_TERMINAL_LISTEN", "127.0.0.1:18080")

	if got := terminalListenAddr(); got != "127.0.0.1:18080" {
		t.Fatalf("terminalListenAddr() = %q, want explicit loopback", got)
	}
}

func TestTerminalTokenFromRequestRequiresHeader(t *testing.T) {
	req, err := http.NewRequest("GET", "/terminal/ws?token=query-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := terminalTokenFromRequest(req); got != "" {
		t.Fatalf("terminalTokenFromRequest() = %q, want empty without header", got)
	}

	req.Header.Set("X-Fleet-Terminal-Token", "header-secret")
	if got := terminalTokenFromRequest(req); got != "header-secret" {
		t.Fatalf("terminalTokenFromRequest() = %q, want header token", got)
	}
}

func TestPlaceholderTerminalTokensAreRejected(t *testing.T) {
	placeholders := []string{
		"change-me-terminal-token",
		"change-me-anything",
		"changeme",
	}
	for _, token := range placeholders {
		if !isPlaceholderTerminalToken(token) {
			t.Fatalf("isPlaceholderTerminalToken(%q) = false, want true", token)
		}
	}

	if isPlaceholderTerminalToken("actual-random-token") {
		t.Fatal("isPlaceholderTerminalToken(actual-random-token) = true, want false")
	}
}

func TestTerminalFirewallPortMatchesTerminalConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, tokenKey, token, listen string
		port                          int
		enabled, invalid              bool
	}{
		{"custom port", "FLEET_TERMINAL_TOKEN", "real-secret", "0.0.0.0:18443", 18443, true, false},
		{"token alias", "AGENT_TERMINAL_TOKEN", "real-secret", "[::]:18080", 18080, true, false},
		{"legacy token alias", "TERM_TOKEN", "real-secret", "192.0.2.20:18080", 18080, true, false},
		{"disabled", "FLEET_TERMINAL_TOKEN", "", "0.0.0.0:18080", 0, false, false},
		{"placeholder", "FLEET_TERMINAL_TOKEN", "change-me-token", "0.0.0.0:18080", 0, false, false},
		{"loopback", "FLEET_TERMINAL_TOKEN", "real-secret", "127.0.0.1:18080", 0, false, false},
		{"invalid port", "FLEET_TERMINAL_TOKEN", "real-secret", "0.0.0.0:nope", 0, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, key := range []string{"FLEET_TERMINAL_TOKEN", "AGENT_TERMINAL_TOKEN", "TERM_TOKEN"} {
				t.Setenv(key, "")
			}
			t.Setenv(test.tokenKey, test.token)
			t.Setenv("FLEET_TERMINAL_LISTEN", test.listen)
			port, enabled, err := TerminalFirewallPort()
			if port != test.port || enabled != test.enabled || (err != nil) != test.invalid {
				t.Fatalf("got (%d, %v, %v)", port, enabled, err)
			}
		})
	}
}
