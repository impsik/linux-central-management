package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// CheckCVE inspects whether this host is affected by a CVE.
//
// Preferred path (Ubuntu-native): `pro fix <CVE> --dry-run`.
// Fallback path (no pro client installed): fetch and parse https://ubuntu.com/security/<CVE>.
//
// Output is JSON for stable server-side parsing.
func CheckCVE(ctx context.Context, cve string) (string, string, int, string) {
	cve = strings.TrimSpace(strings.ToUpper(cve))
	if cve == "" {
		return "", "", 1, "cve is required"
	}

	// Try ubuntu-pro client first (even if not attached, it can still answer).
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
	}

	low := strings.ToLower(out)
	proMissing := strings.Contains(low, "command not found") || strings.Contains(low, "no such file")

	if !proMissing {
		affected := false
		summary := "unknown"

		if strings.Contains(low, "does not affect your system") || strings.Contains(low, "no affected source packages are installed") {
			affected = false
			summary = "not affected"
		} else if strings.Contains(low, "affects your system") {
			affected = true
			summary = "affected"
		}

		trimmed := strings.TrimSpace(out)
		if len(trimmed) > 12000 {
			trimmed = trimmed[:12000] + "\n…(truncated)"
		}

		pkgs := extractAptPackagesFromProDryRun(out)
		payload := map[string]any{
			"cve":       cve,
			"affected":  affected,
			"summary":   summary,
			"source":    "pro",
			"raw":       trimmed,
			"exit_code": code,
			"packages":  pkgs,
		}
		j, jerr := json.Marshal(payload)
		if jerr != nil {
			return "", out, code, "json marshal failed"
		}

		if err != nil {
			return string(j), out, code, "pro fix failed"
		}
		return string(j), "", 0, ""
	}

	// Fallback: ubuntu.com CVE page parse.
	return checkCVEViaUbuntuCom(ctx, cve)
}

type ubuntuComRow struct {
	Package  string `json:"package"`
	Release  string `json:"release"`  // e.g. 22.04
	Codename string `json:"codename"` // e.g. jammy
	Status   string `json:"status"`   // e.g. Vulnerable|Fixed|Not affected
}

func checkCVEViaUbuntuCom(ctx context.Context, cve string) (string, string, int, string) {
	ctx2, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://ubuntu.com/security/%s", cve)
	req, _ := http.NewRequestWithContext(ctx2, "GET", url, nil)
	req.Header.Set("User-Agent", "fleet-agent/0.1")

	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 1, fmt.Sprintf("ubuntu.com fetch failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2_500_000))
	html := string(bodyBytes)
	if resp.StatusCode >= 300 {
		trim := strings.TrimSpace(html)
		if len(trim) > 4000 {
			trim = trim[:4000] + "\n…(truncated)"
		}
		return "", trim, 1, fmt.Sprintf("ubuntu.com returned %s", resp.Status)
	}

	versionID := strings.TrimSpace(readOSRelease("VERSION_ID"))
	codename := readOSRelease("VERSION_CODENAME")
	if codename == "" {
		codename = readOSRelease("UBUNTU_CODENAME")
	}
	codename = strings.TrimSpace(strings.ToLower(codename))

	rows := parseUbuntuComCVETable(html)

	matched := make([]ubuntuComRow, 0, 4)
	for _, r := range rows {
		if codename != "" && strings.EqualFold(r.Codename, codename) {
			matched = append(matched, r)
			continue
		}
		if versionID != "" && strings.TrimSpace(r.Release) == versionID {
			matched = append(matched, r)
			continue
		}
	}

	affected := false
	unknown := false
	affectedPkgs := []string{}
	for _, r := range matched {
		s := strings.ToLower(strings.TrimSpace(r.Status))
		if strings.Contains(s, "vulnerable") || strings.Contains(s, "needed") {
			affected = true
			affectedPkgs = append(affectedPkgs, r.Package)
		} else if strings.Contains(s, "unknown") || strings.Contains(s, "pending") {
			unknown = true
		}
	}

	summary := "not affected"
	if affected {
		summary = "affected"
	} else if unknown || len(matched) == 0 {
		summary = "unknown"
	}

	payload := map[string]any{
		"cve":      cve,
		"affected": affected,
		"summary":  summary,
		"source":   "ubuntu.com",
		"packages": affectedPkgs,
		"details": map[string]any{
			"version_id":      versionID,
			"codename":        codename,
			"matched_rows":    matched,
			"affected_pkgs":   affectedPkgs,
			"matched_row_cnt": len(matched),
		},
	}
	j, jerr := json.Marshal(payload)
	if jerr != nil {
		return "", "", 1, "json marshal failed"
	}
	return string(j), "", 0, ""
}

func readOSRelease(key string) string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) != key {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, "\"")
		return v
	}
	return ""
}

func parseUbuntuComCVETable(html string) []ubuntuComRow {
	rows := []ubuntuComRow{}

	// Split by <tr to keep it manageable.
	parts := strings.Split(html, "<tr")
	currentPkg := ""

	rePkg := regexp.MustCompile(`(?is)<th[^>]*rowspan="\d+"[^>]*>\s*([^<\s]+)\s*</th>`)
	reRelease := regexp.MustCompile(`(?is)<td[^>]*>\s*([0-9]{2}\.[0-9]{2})\s*.*?<span[^>]*u-text--muted[^>]*>\s*([^<\s]+)\s*</span>`)
	reStatus := regexp.MustCompile(`(?is)<div[^>]*>\s*(Not affected|Vulnerable|Fixed|Pending|Unknown|Ignored|Deferred|Needs triage|Needed)\s*</div>`)

	for _, p := range parts {
		if m := rePkg.FindStringSubmatch(p); len(m) == 2 {
			currentPkg = strings.TrimSpace(m[1])
		}
		m2 := reRelease.FindStringSubmatch(p)
		if len(m2) != 3 {
			continue
		}
		rel := strings.TrimSpace(m2[1])
		code := strings.TrimSpace(m2[2])

		st := ""
		if m3 := reStatus.FindStringSubmatch(p); len(m3) == 2 {
			st = strings.TrimSpace(m3[1])
		}
		if currentPkg == "" || rel == "" || st == "" {
			continue
		}

		rows = append(rows, ubuntuComRow{Package: currentPkg, Release: rel, Codename: code, Status: st})
	}

	return rows
}

func extractAptPackagesFromProDryRun(out string) []string {
	out = strings.ReplaceAll(out, "\r\n", "\n")
	// Heuristic parsing: pro fix --dry-run typically embeds an apt simulation/plan.
	// Common patterns:
	//  - "Inst <pkg> (.."
	//  - "Upgrade <pkg> (.."
	re := regexp.MustCompile(`(?m)^\s*(?:Inst|Upgrade)\s+([a-z0-9][a-z0-9+\-\.]+)\b`)
	m := re.FindAllStringSubmatch(out, -1)
	seen := map[string]bool{}
	pkgs := make([]string, 0, 8)
	for _, mm := range m {
		if len(mm) < 2 {
			continue
		}
		p := strings.TrimSpace(mm[1])
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// helper for tests/other packages
func _bytesTrim(b []byte) []byte { return bytes.TrimSpace(b) }
