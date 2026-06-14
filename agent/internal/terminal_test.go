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
