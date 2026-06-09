package main

import (
	"reflect"
	"testing"
)

func TestIsEnabledState(t *testing.T) {
	cases := map[string]bool{
		"enabled":         true,
		"enabled-runtime": true,
		"alias":           true,
		"static":          true,
		"indirect":        true,
		"disabled":        false,
		"masked":          false,
		"not-found":       false,
	}

	for in, want := range cases {
		got := isEnabledState(in)
		if got != want {
			t.Fatalf("isEnabledState(%q)=%v, want %v", in, got, want)
		}
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

func TestParseGroupMembers(t *testing.T) {
	members := parseGroupMembers("wheel:x:10:imre,deploy\n")
	if !members["imre"] || !members["deploy"] {
		t.Fatalf("group members = %#v, want imre and deploy", members)
	}
	if members[""] {
		t.Fatalf("empty member should not be recorded: %#v", members)
	}
}

func TestParseUserGroupsAndNamedGroupMatch(t *testing.T) {
	groups := parseUserGroups("imre wheel docker")
	if !hasAnyNamedGroup(groups, "sudo", "wheel", "admin") {
		t.Fatalf("groups = %#v, want wheel sudo match", groups)
	}
	if hasAnyNamedGroup(groups, "sudo", "admin") {
		t.Fatalf("groups = %#v, should not match sudo/admin", groups)
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
	got, err := serviceControlCommands("ssh.service", "disable", true)
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

func TestServiceInventoryEnabledTreatsSocketEnabledAsEnabled(t *testing.T) {
	enabledUnits := map[string]bool{
		"ssh.service": false,
		"ssh.socket":  true,
	}

	if !serviceInventoryEnabled("ssh", func(unitName string) bool {
		return enabledUnits[unitName]
	}) {
		t.Fatal("ssh inventory enabled = false, want true when ssh.socket is enabled")
	}
}

func TestServiceInventoryEnabledFalseWhenServiceAndSocketDisabled(t *testing.T) {
	if serviceInventoryEnabled("ssh", func(unitName string) bool {
		return false
	}) {
		t.Fatal("ssh inventory enabled = true, want false when service and socket are disabled")
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
	got := buildFirewalldRejectRule(443, "tcp", "10.0.0.0/8")
	want := `rule family="ipv4" source address="10.0.0.0/8" port port="443" protocol="tcp" reject`
	if got != want {
		t.Fatalf("rich rule = %q, want %q", got, want)
	}
}
