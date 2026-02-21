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
// ONLY path: Ask Fleet Server (local DB).
// The `pro fix` fallback has been completely disabled for privacy/speed.
//
// Output is JSON for stable server-side parsing.
func CheckCVE(ctx context.Context, cve string) (string, string, int, string) {
	cve = strings.TrimSpace(strings.ToUpper(cve))
	if cve == "" {
		return "", "", 1, "cve is required"
	}

	// Always ask Fleet Server (Fast, Offline)
	jsonResp, rawResp, code, errStr := checkCVEViaFleetServer(ctx, cve)
	
	// If server is down or returns error, we simply fail/report error.
	// We do NOT fallback to external 'pro fix'.
	
	return jsonResp, rawResp, code, errStr
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
			packages, _ := data["packages"].(map[string]any)
			
			// Filter: Only report packages that are actually installed AND older than fixed version
			installedPkgs := getInstalledPackages()
			
			for p, statusRaw := range packages {
				// Status in DB might be a version string OR a status code (e.g. 'needed', 'DNE')
				
				neededVer := ""
				switch v := statusRaw.(type) {
				case string:
					neededVer = v
				case map[string]any:
					// Depending on how DB schema returns it
					if s, ok := v["version"].(string); ok {
						neededVer = s
					} else if _, ok := v["status"].(string); ok {
						// e.g. status='released'
					}
				}

				if currentVer, installed := installedPkgs[p]; installed {
					// It is installed. Is it vulnerable?
					if isVersionAffected(currentVer, neededVer) {
						pkgs = append(pkgs, fmt.Sprintf("%s (installed:%s < fixed:%s)", p, currentVer, neededVer))
					}
				}
			}

			if len(pkgs) > 0 {
				affected = true
				summary = "affected"
			} else {
				summary = "not affected (all installed packages are patched)"
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
    // Unused if pro fix is disabled, but kept for compilation safety or future use
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

func getInstalledPackages() map[string]string {
	// dpkg-query -W -f='${Package} ${Version}\n'
	// Returns map of pkg_name -> installed_version
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// dpkg-query -W -f='${Package} ${Version}\n'
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package} ${Version}\n")
	out, err := cmd.Output()
	
	res := make(map[string]string)
	if err != nil {
		return res
	}

	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		parts := strings.Fields(l)
		if len(parts) >= 2 {
			res[parts[0]] = parts[1]
		}
	}
	return res
}

func isVersionAffected(current, needed string) bool {
	needed = strings.TrimSpace(needed)
	if needed == "" || needed == "released" || needed == "needed" {
		// If DB just says 'released' without a version, we assume affected if installed.
		return true 
	}
	if needed == "not-affected" || needed == "DNE" {
		return false
	}
	
	// Compare versions: `dpkg --compare-versions current lt needed`
	// Return true if current < needed (meaning we are older/vulnerable)
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "dpkg", "--compare-versions", current, "lt", needed)
	if err := cmd.Run(); err == nil {
		// Exit code 0 means condition is true (current < needed)
		return true
	}
	return false
}

func _bytesTrim(b []byte) []byte { return bytes.TrimSpace(b) }
