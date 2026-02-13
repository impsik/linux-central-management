package main

import "testing"

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
