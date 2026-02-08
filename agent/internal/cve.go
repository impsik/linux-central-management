package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

// CheckCVE runs an Ubuntu-native CVE inspection using `pro fix <CVE> --dry-run`.
// It does NOT apply fixes.
//
// Output is JSON for stable server-side parsing:
//
//	{
//	  "cve": "CVE-2021-45105",
//	  "affected": false,
//	  "summary": "...",
//	  "raw": "<trimmed command output>"
//	}
func CheckCVE(ctx context.Context, cve string) (string, string, int, string) {
	cve = strings.TrimSpace(cve)
	if cve == "" {
		return "", "", 1, "cve is required"
	}

	checkCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, "pro", "fix", cve, "--dry-run")
	b, err := cmd.CombinedOutput()
	out := string(b)
	code := 0
	if err != nil {
		code = 1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		// keep out; it often contains the real reason (e.g. pro not installed)
	}

	affected := true
	summary := ""

	low := strings.ToLower(out)
	if strings.Contains(low, "does not affect your system") || strings.Contains(low, "no affected source packages are installed") {
		affected = false
		summary = "not affected"
	} else if strings.Contains(low, "affects your system") || strings.Contains(low, "affected") {
		affected = true
		summary = "affected"
	}

	// Trim raw output a bit to avoid bloating DB/logs.
	trimmed := strings.TrimSpace(out)
	if len(trimmed) > 12000 {
		trimmed = trimmed[:12000] + "\n…(truncated)"
	}

	payload := map[string]any{
		"cve":       cve,
		"affected":  affected,
		"summary":   summary,
		"raw":       trimmed,
		"exit_code": code,
	}
	j, jerr := json.Marshal(payload)
	if jerr != nil {
		// fallback: never fail the agent just because JSON marshal failed
		return "", out, code, "json marshal failed"
	}

	// When pro is missing, surface a clearer error.
	if strings.Contains(low, "command not found") || strings.Contains(low, "no such file") {
		return string(j), out, 1, "ubuntu pro client not available (install ubuntu-advantage-tools)"
	}

	if err != nil {
		// keep JSON stdout plus a short error string
		return string(j), out, code, "pro fix failed"
	}

	return string(j), "", 0, ""
}

// helper for tests/other packages
func _bytesTrim(b []byte) []byte {
	return bytes.TrimSpace(b)
}
