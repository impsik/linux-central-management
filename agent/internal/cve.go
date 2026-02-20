package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var reANSI = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSICodes(s string) string {
	return reANSI.ReplaceAllString(s, "")
}

// CheckCVE inspects whether this host is affected by a CVE.
//
// Preferred path: Ask Fleet Server (local DB).
// Fallback path (if server is down/unknown): `pro fix <CVE> --dry-run` (Ubuntu-native).
//
// Output is JSON for stable server-side parsing.
func CheckCVE(ctx context.Context, cve string) (string, string, int, string) {
	cve = strings.TrimSpace(strings.ToUpper(cve))
	if cve == "" {
		return "", "", 1, "cve is required"
	}

	// 1. Try Fleet Server first (Fast, Offline)
	jsonResp, rawResp, code, errStr := checkCVEViaFleetServer(ctx, cve)
	if code == 0 && jsonResp != "" {
		// Server knew about it (either found or definitively not found)
		// We trust the server's DB.
		return jsonResp, rawResp, code, errStr
	}

	// 2. Fallback: Try ubuntu-pro client (Slow, External)
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

	// pro output contains ANSI color codes; strip them before parsing.
	noAnsi := stripANSICodes(out)
	low := strings.ToLower(noAnsi)
	proMissing := strings.Contains(low, "command not found") || strings.Contains(low, "no such file")

	if !proMissing {
		affected := false
		summary := "unknown"

		resolvedLine := strings.Contains(low, " is resolved")
		alreadyInstalled := strings.Contains(low, "the update is already installed")

		pkgs := extractAptPackagesFromProDryRun(noAnsi)

		if strings.Contains(low, "does not affect your system") || strings.Contains(low, "no affected source packages are installed") {
			affected = false
			summary = "not affected"
			pkgs = []string{}
		} else if alreadyInstalled {
			affected = false
			summary = "resolved"
			pkgs = []string{}
		} else if len(pkgs) > 0 {
			affected = true
			summary = "fix available"
		} else if strings.Contains(low, "affects your system") {
			affected = true
			summary = "affected"
		} else if strings.Contains(low, "affected source package") && strings.Contains(low, "installed") {
			affected = true
			summary = "affected"
		} else if resolvedLine {
			affected = false
			summary = "resolved"
		}

		trimmed := strings.TrimSpace(noAnsi)
		if len(trimmed) > 12000 {
			trimmed = trimmed[:12000] + "\n…(truncated)"
		}

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

	// Fallback: Check via Fleet Server (Offline/Local DB)
	return checkCVEViaFleetServer(ctx, cve)
}

func checkCVEViaFleetServer(ctx context.Context, cve string) (string, string, int, string) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	serverURL := os.Getenv("FLEET_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8000"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	// Determine codename
	codename := readOSRelease("VERSION_CODENAME")
	if codename == "" {
		codename = readOSRelease("UBUNTU_CODENAME")
	}
	codename = strings.TrimSpace(strings.ToLower(codename))

	url := fmt.Sprintf("%s/patching/cve/%s?distro_codename=%s", serverURL, cve, codename)
	
	req, _ := http.NewRequestWithContext(ctx2, "GET", url, nil)
	// Add token if available
	token := os.Getenv("FLEET_AGENT_TOKEN")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 1, fmt.Sprintf("fleet server fetch failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", "", 1, "cve not found in local db"
	}
	if resp.StatusCode != 200 {
		return "", "", 1, fmt.Sprintf("fleet server returned %s", resp.Status)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 1, "failed to decode server response"
	}

	// result: { "cve": "...", "found": true, "distro_found": true, "data": { "packages": {...} } }
	
	affected := false
	summary := "unknown"
	pkgs := []string{}
	
	if found, _ := result["found"].(bool); !found {
		summary = "unknown (not in db)"
	} else if distroFound, _ := result["distro_found"].(bool); !distroFound {
		summary = "not affected (distro mismatch)"
	} else {
		data, _ := result["data"].(map[string]any)
		if data != nil {
			// simplified check: if packages list is non-empty and any status is 'released'/'needed'
			packages, _ := data["packages"].(map[string]any)
			if len(packages) > 0 {
				affected = true
				summary = "affected"
				for p := range packages {
					pkgs = append(pkgs, p)
				}
			} else {
				summary = "not affected"
			}
		}
	}

	payload := map[string]any{
		"cve":      cve,
		"affected": affected,
		"summary":  summary,
		"source":   "fleet-server-db",
		"packages": pkgs,
		"details":  result,
	}
	j, _ := json.Marshal(payload)
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

func extractAptPackagesFromProDryRun(out string) []string {
	out = strings.ReplaceAll(out, "\r\n", "\n")
	out = strings.ReplaceAll(out, "\\\n", " ") 

	seen := map[string]bool{}
	pkgs := make([]string, 0, 8)

	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		pkgs = append(pkgs, p)
	}

	rePlan := regexp.MustCompile(`(?m)^\s*(?:Inst|Upgrade)\s+([a-z0-9][a-z0-9+\-\.]+)\b`)
	for _, mm := range rePlan.FindAllStringSubmatch(out, -1) {
		if len(mm) >= 2 {
			add(mm[1])
		}
	}

	reCmd := regexp.MustCompile(`(?is)\bapt\s+install\b[^\n\}]*\s--only-upgrade\b([^\n\}]+)`)
	if m := reCmd.FindStringSubmatch(out); len(m) == 2 {
		rest := strings.TrimSpace(m[1])
		toks := strings.Fields(rest)
		for _, t := range toks {
			if t == "&&" || t == "{" || t == "}" || strings.HasPrefix(t, "-") || t == "apt" || t == "update" || t == "install" {
				continue
			}
			add(t)
		}
	}

	return pkgs
}

func _bytesTrim(b []byte) []byte { return bytes.TrimSpace(b) }
