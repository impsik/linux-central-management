package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIsEnabledState(t *testing.T) {
	cases := map[string]bool{
		"enabled":         true,
		"enabled-runtime": true,
		"alias":           false,
		"static":          false,
		"indirect":        false,
		"disabled":        false,
		"masked":          false,
		"not-found":       false,
		"linked":          false,
		"linked-runtime":  false,
		"generated":       false,
		"transient":       false,
		"masked-runtime":  false,
	}

	for in, want := range cases {
		got := isEnabledState(in)
		if got != want {
			t.Fatalf("isEnabledState(%q)=%v, want %v", in, got, want)
		}
	}
}

func TestAgentTokenFileReadWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-agent", "agent-token")

	if err := writeAgentTokenFile(path, " per-agent-token "); err != nil {
		t.Fatalf("writeAgentTokenFile returned error: %v", err)
	}

	got, err := readAgentTokenFile(path)
	if err != nil {
		t.Fatalf("readAgentTokenFile returned error: %v", err)
	}
	if got != "per-agent-token" {
		t.Fatalf("read token = %q, want per-agent-token", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestSignAgentRequestAddsHeaders(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.test/agent/heartbeat?agent_id=srv-1", strings.NewReader(""))
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}

	signAgentRequest(req, "agent-token", nil)

	if req.Header.Get("X-Fleet-Agent-Timestamp") == "" {
		t.Fatal("missing X-Fleet-Agent-Timestamp")
	}
	if req.Header.Get("X-Fleet-Agent-Signature") == "" {
		t.Fatal("missing X-Fleet-Agent-Signature")
	}
}

func TestParsePasswdStatusAll(t *testing.T) {
	out := "" +
		"root P 2026-02-01 0 99999 7 -1\n" +
		"newuser NP 2026-02-01 0 99999 7 -1\n" +
		"lockeduser L 2026-02-01 0 99999 7 -1\n"

	m := parsePasswdStatusAll(out)
	if m["root"] != "P" {
		t.Fatalf("root status = %q, want P", m["root"])
	}
	if m["newuser"] != "NP" {
		t.Fatalf("newuser status = %q, want NP", m["newuser"])
	}
	if m["lockeduser"] != "L" {
		t.Fatalf("lockeduser status = %q, want L", m["lockeduser"])
	}
}

func TestSudoListingAllowsCommands(t *testing.T) {
	for _, tc := range []struct {
		name, listing string
		want          bool
	}{
		{"denied", "User nobody is not allowed to run sudo on slave1.\n", false},
		{"defaults only", "Matching Defaults entries for user on host:\n    env_reset, authenticate\n", false},
		{"root commands", "Sudoers entry: /etc/sudoers\n    RunAsUsers: ALL\n    Commands:\n\tALL\n", true},
		{"limited commands", "Sudoers entry: /etc/sudoers.d/custom\n    Commands:\n\t/usr/bin/systemctl restart nginx\n", true},
		{"deny only", "Sudoers entry: /etc/sudoers\n    Commands:\n\t!ALL\n", false},
		{"deny overrides all", "Sudoers entry: /etc/sudoers\n    Commands:\n\tALL\n\t!ALL\n", false},
		{"deny overrides command", "    Commands:\n\t/usr/bin/id\n\t!/usr/bin/id\n", false},
		{"deny specific preserves other rights", "    Commands:\n\tALL\n\t!/usr/bin/id\n", true},
		{"later allow", "    Commands:\n\t!ALL\n\nSudoers entry: custom\n    Commands:\n\t/usr/bin/id\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sudoListingAllowsCommands(tc.listing); got != tc.want {
				t.Fatalf("sudoListingAllowsCommands = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUserHasSudoAccessQueriesPolicyAndRequiresGrantedCommands(t *testing.T) {
	bin := t.TempDir()
	script := `#!/bin/sh
[ "$LC_ALL" = C ] || exit 8
[ "$1 $2 $3" = "-n -ll -U" ] || exit 9
case "$4" in
  nobody) printf 'User nobody is not allowed to run sudo on host.\n'; exit 0 ;;
  sudo-group-denied) printf 'User sudo-group-denied is not allowed to run sudo on host.\n'; exit 0 ;;
  custom-grant) printf 'Sudoers entry: custom\n    Commands:\n\t/usr/bin/id\n'; exit 0 ;;
  listing-failed) printf 'Sudoers entry: custom\n    Commands:\n\tALL\n'; exit 1 ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("LC_ALL", "et_EE.UTF-8")
	for _, tc := range []struct {
		user string
		want bool
	}{
		{"root", true}, {"nobody", false}, {"sudo-group-denied", false}, {"custom-grant", true}, {"listing-failed", false},
	} {
		if got := userHasSudoAccess(context.Background(), tc.user); got != tc.want {
			t.Errorf("userHasSudoAccess(%q) = %v, want %v", tc.user, got, tc.want)
		}
	}
}

func TestNormalizeSudoProfile(t *testing.T) {
	cases := map[string]string{
		"":         "B",
		"  ":       "B",
		"A":        "A",
		"a":        "A",
		"B":        "B",
		"b":        "B",
		"N":        "N",
		"n":        "N",
		"none":     "N",
		" NONE  ":  "N",
		"unknown":  "B",
		"reduced?": "B",
	}

	for in, want := range cases {
		got := normalizeSudoProfile(in)
		if got != want {
			t.Fatalf("normalizeSudoProfile(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestServiceControlCommandsStopsSocketBeforeService(t *testing.T) {
	got, err := serviceControlCommands("ssh.service", "stop", true)
	if err != nil {
		t.Fatalf("serviceControlCommands returned error: %v", err)
	}
	want := [][]string{
		{"stop", "ssh.socket"},
		{"stop", "ssh.service"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stop commands = %#v, want %#v", got, want)
	}
}

func TestServiceControlCommandsDisablesSocketNow(t *testing.T) {
	got, err := serviceAutostartCommands("ssh.service", "disable", "disabled", "enabled")
	if err != nil {
		t.Fatalf("serviceControlCommands returned error: %v", err)
	}
	want := [][]string{
		{"disable", "--now", "ssh.socket"},
		{"disable", "ssh.service"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("disable commands = %#v, want %#v", got, want)
	}
}

func TestServiceControlCommandsWithoutSocketKeepsOrdinaryServiceBehavior(t *testing.T) {
	got, err := serviceControlCommands("nginx.service", "stop", false)
	if err != nil {
		t.Fatalf("serviceControlCommands returned error: %v", err)
	}
	want := [][]string{{"stop", "nginx.service"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stop commands = %#v, want %#v", got, want)
	}
}

func TestServiceControlCommandsStartWaitsForSystemdResult(t *testing.T) {
	got, err := serviceControlCommands("unattended-upgrades.service", "start", false)
	if err != nil {
		t.Fatalf("serviceControlCommands returned error: %v", err)
	}
	want := [][]string{{"start", "unattended-upgrades.service"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("start commands = %#v, want %#v", got, want)
	}
}

func TestServiceControlCommandsRestartWaitsForSystemdResult(t *testing.T) {
	got, err := serviceControlCommands("nginx.service", "restart", false)
	if err != nil {
		t.Fatalf("serviceControlCommands returned error: %v", err)
	}
	want := [][]string{{"restart", "nginx.service"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restart commands = %#v, want %#v", got, want)
	}
}

func TestServiceActivationPreservesUnitAndSocketStates(t *testing.T) {
	for _, tc := range []struct {
		service, socket                string
		enabled, canEnable, canDisable bool
	}{
		{"disabled", "enabled", true, true, true},
		{"static", "enabled", true, true, true},
		{"static", "disabled", false, true, true},
		{"static", "static", false, false, false},
		{"disabled", "unknown", false, true, true},
		{"enabled-runtime", "unknown", true, true, true},
		{"indirect", "unknown", false, false, false},
		{"generated", "unknown", false, false, false},
		{"transient", "unknown", false, false, false},
		{"masked", "enabled", true, false, true},
		{"unknown", "unknown", false, false, false},
	} {
		got := serviceActivation(tc.service, tc.socket)
		if got.UnitFileState != tc.service || got.SocketUnitFileState != tc.socket ||
			got.Enabled != tc.enabled || got.CanEnable != tc.canEnable || got.CanDisable != tc.canDisable {
			t.Errorf("serviceActivation(%q, %q) = %+v", tc.service, tc.socket, got)
		}
	}
}

func TestServiceAutostartCommandsDoNotToggleStaticUnits(t *testing.T) {
	for _, tc := range []struct {
		action, service, socket string
		want                    [][]string
	}{
		{"enable", "disabled", "unknown", [][]string{{"enable", "example.service"}}},
		{"enable", "static", "disabled", [][]string{{"enable", "example.socket"}}},
		{"disable", "static", "enabled", [][]string{{"disable", "--now", "example.socket"}}},
		{"disable", "enabled", "static", [][]string{{"disable", "example.service"}}},
		{"disable", "static", "static", nil},
		{"enable", "static", "static", nil},
		{"enable", "indirect", "unknown", nil},
		{"disable", "generated", "unknown", nil},
		{"enable", "masked", "disabled", nil},
	} {
		got, err := serviceAutostartCommands("example.service", tc.action, tc.service, tc.socket)
		if !reflect.DeepEqual(got, tc.want) || (err != nil) != (tc.want == nil) {
			t.Errorf("%s %s/%s: commands=%v, error=%v; want %v", tc.action, tc.service, tc.socket, got, err, tc.want)
		}
	}
}

func TestControlServiceChecksActualStateBeforeAutostartMutation(t *testing.T) {
	bin := t.TempDir()
	logPath := filepath.Join(bin, "mutations")
	t.Setenv("MUTATION_LOG", logPath)
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(`#!/bin/sh
[ "$1 $2 $3" = "show --property=UnitFileState --value" ] || exit 8
printf 'static\n'
`), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(`#!/bin/sh
printf '%s\n' "$*" >> "$MUTATION_LOG"
`), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	for _, action := range []string{"enable", "disable"} {
		_, _, code, errText := controlService(context.Background(), "example", action)
		if code == 0 || !strings.Contains(errText, "static") {
			t.Errorf("controlService(%s): code=%d, error=%q", action, code, errText)
		}
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("sudo called for static units: stat error = %v", err)
	}
}

func TestSplitRpmNameArch(t *testing.T) {
	name, arch := splitRpmNameArch("openssl-libs.x86_64")
	if name != "openssl-libs" || arch != "x86_64" {
		t.Fatalf("splitRpmNameArch returned %q/%q", name, arch)
	}
	name, arch = splitRpmNameArch("python3.11.noarch")
	if name != "python3.11" || arch != "noarch" {
		t.Fatalf("splitRpmNameArch with dotted name returned %q/%q", name, arch)
	}
}

func TestParseRpmCheckUpdateLine(t *testing.T) {
	got, ok := parseRpmCheckUpdateLine("openssl-libs.x86_64 1:3.2.2-6.el9_5 baseos")
	if !ok {
		t.Fatal("parseRpmCheckUpdateLine returned ok=false")
	}
	if got.Name != "openssl-libs" || got.Arch != "x86_64" || got.CandidateVersion != "1:3.2.2-6.el9_5" {
		t.Fatalf("parsed RPM update = %#v", got)
	}
	if _, ok := parseRpmCheckUpdateLine("Last metadata expiration check: 0:03:12 ago"); ok {
		t.Fatal("metadata line should be ignored")
	}
}

func TestParseOSReleaseValue(t *testing.T) {
	content := "NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nVERSION_ID=\"9.8\"\n"
	if got := parseOSReleaseValue(content, "ID"); got != "rhel" {
		t.Fatalf("ID = %q, want rhel", got)
	}
	if got := parseOSReleaseValue(content, "VERSION_ID"); got != "9.8" {
		t.Fatalf("VERSION_ID = %q, want 9.8", got)
	}
}

func TestParseRpmInfoFieldsCapturesMultilineDescription(t *testing.T) {
	out := "" +
		"Name        : abattis-cantarell-fonts\n" +
		"Version     : 0.301\n" +
		"Release     : 4.el9\n" +
		"Architecture: noarch\n" +
		"Summary     : Humanist sans serif font\n" +
		"Description :\n" +
		"Cantarell is a humanist sans serif font family.\n" +
		"It is used by GNOME and related desktop components.\n"

	fields := parseRpmInfoFields(out)
	if fields["summary"] != "Humanist sans serif font" {
		t.Fatalf("summary = %q", fields["summary"])
	}
	wantDesc := "Cantarell is a humanist sans serif font family.\nIt is used by GNOME and related desktop components."
	if fields["description"] != wantDesc {
		t.Fatalf("description = %q, want %q", fields["description"], wantDesc)
	}
}

func TestParseUfwStatusLine(t *testing.T) {
	rule := parseUfwStatusLine("[ 1] 443/tcp                    ALLOW IN    10.0.0.0/8")
	if rule.ID != "1" || rule.Port != "443" || rule.Protocol != "tcp" || rule.Action != "allow" || rule.Source != "10.0.0.0/8" {
		t.Fatalf("parsed UFW rule = %#v", rule)
	}
}

func TestParseUfwStatusLineService(t *testing.T) {
	rule := parseUfwStatusLine("[ 2] OpenSSH                    ALLOW IN    Anywhere")
	if rule.ID != "2" || rule.Service != "OpenSSH" || rule.Port != "" || rule.Action != "allow" || rule.Source != "Anywhere" {
		t.Fatalf("parsed UFW service rule = %#v", rule)
	}
}

func TestParseUfwStatusLineServiceWithSpaces(t *testing.T) {
	rule := parseUfwStatusLine("[ 3] Apache Full                ALLOW IN    192.168.1.0/24")
	if rule.ID != "3" || rule.Service != "Apache Full" || rule.Port != "" || rule.Action != "allow" || rule.Source != "192.168.1.0/24" {
		t.Fatalf("parsed UFW spaced service rule = %#v", rule)
	}
}

func TestBuildUfwArgsServiceDelete(t *testing.T) {
	got := buildUfwArgs("delete", 0, "tcp", "", "OpenSSH")
	want := []string{"-n", "ufw", "--force", "delete", "allow", "OpenSSH"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ufw args = %#v, want %#v", got, want)
	}
}

func TestBuildUfwArgsServiceAllowFromSource(t *testing.T) {
	got := buildUfwArgs("allow", 0, "tcp", "192.168.1.0/24", "OpenSSH")
	want := []string{"-n", "ufw", "allow", "from", "192.168.1.0/24", "to", "any", "app", "OpenSSH"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ufw args = %#v, want %#v", got, want)
	}
}

func TestBuildFirewalldRejectRule(t *testing.T) {
	_, got := firewalldRuleSpec("deny", 443, "tcp", "10.0.0.0/8", "")
	want := `rule family="ipv4" source address="10.0.0.0/8" port port="443" protocol="tcp" reject`
	if got != want {
		t.Fatalf("rich rule = %q, want %q", got, want)
	}
}

func TestRunDiskCleanupRejectsUnsupportedAction(t *testing.T) {
	_, _, code, errMsg := runDiskCleanup(context.Background(), true, []string{"wipe-everything"})
	if code == 0 {
		t.Fatal("runDiskCleanup returned success for unsupported action")
	}
	if !strings.Contains(errMsg, "unsupported cleanup action") {
		t.Fatalf("error = %q, want unsupported cleanup action", errMsg)
	}
}

func TestFirewallRejectsAmbiguousPortAndProfileBeforeOSAccess(t *testing.T) {
	_, _, code, message := controlFirewall(context.Background(), "allow", 1122, "tcp", "", "cockpit", "https://fleet.example")
	if code == 0 || !strings.Contains(message, "either a port") {
		t.Fatalf("code=%d message=%s", code, message)
	}
}
