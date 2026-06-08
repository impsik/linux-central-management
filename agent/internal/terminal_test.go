package internal

import (
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

func TestRunTerminalSSHLoginFromArgsIgnoresNormalAgentStart(t *testing.T) {
	if RunTerminalSSHLoginFromArgs([]string{os.Args[0]}) {
		t.Fatal("RunTerminalSSHLoginFromArgs() = true for normal agent args")
	}
}
