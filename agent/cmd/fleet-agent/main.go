package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/yourorg/fleet-agent/internal"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ServerURL  string
	AgentID    string
	Labels     map[string]string
	PollEvery  time.Duration
	InvEvery   time.Duration
	HbEvery    time.Duration
	AgentToken string
}

type RegisterPayload struct {
	AgentID   string            `json:"agent_id"`
	Hostname  string            `json:"hostname"`
	FQDN      string            `json:"fqdn,omitempty"`
	OSID      string            `json:"os_id,omitempty"`
	OSVersion string            `json:"os_version,omitempty"`
	Kernel    string            `json:"kernel,omitempty"`
	Labels    map[string]string `json:"labels"`
}

type InventoryPayload struct {
	AgentID         string        `json:"agent_id"`
	CollectedAtUnix int64         `json:"collected_at_unix"`
	Packages        []PackageItem `json:"packages"`
}

type UpdatesInventoryPayload struct {
	AgentID       string       `json:"agent_id"`
	CheckedAtUnix int64        `json:"checked_at_unix"`
	Updates       []UpdateItem `json:"updates"`
}

type UpdateItem struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installed_version,omitempty"`
	CandidateVersion string `json:"candidate_version,omitempty"`
	IsSecurity       bool   `json:"is_security,omitempty"`
}

type PackageItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

type NextJobResponse struct {
	Job *Job `json:"job"`
}

type Job struct {
	JobID       string   `json:"job_id"`
	Type        string   `json:"type"`
	Packages    []string `json:"packages,omitempty"`
	ServiceName string   `json:"service_name,omitempty"`
	Action      string   `json:"action,omitempty"`
	PackageName string   `json:"package_name,omitempty"`
	Refresh     bool     `json:"refresh,omitempty"`
}

type JobEvent struct {
	AgentID  string `json:"agent_id"`
	JobID    string `json:"job_id"`
	Status   string `json:"status"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Error    string `json:"error,omitempty"`
}

func main() {
	log.Println("Fleet agent starting...")
	go internal.StartTerminalServer()

	cfg := loadConfig()
	client := &http.Client{Timeout: 40 * time.Second}
	ctx := context.Background()

	hostname, _ := os.Hostname()

	reg := RegisterPayload{
		AgentID:   cfg.AgentID,
		Hostname:  hostname,
		Labels:    cfg.Labels,
		OSID:      "ubuntu",
		OSVersion: readOSVersion(),
		Kernel:    readKernel(),
	}

	lastRegisterAttempt := time.Time{}
	var regMu sync.Mutex
	registerAgent := func(reason string) {
		regMu.Lock()
		defer regMu.Unlock()
		// Avoid hammering the server if it's down or in a bad state
		if !lastRegisterAttempt.IsZero() && time.Since(lastRegisterAttempt) < 5*time.Second {
			return
		}
		lastRegisterAttempt = time.Now()
		log.Printf("Re-registering agent (reason: %s)...", reason)
		mustPostJSON(client, cfg.ServerURL+"/agent/register", reg, cfg.AgentToken)
	}

	// Initial registration
	registerAgent("startup")

	lastInv := time.Time{}

	// Heartbeat in background so long-polling doesn't block keepalive.
	go func() {
		t := time.NewTicker(cfg.HbEvery)
		defer t.Stop()
		for {
			req, _ := http.NewRequest("POST", cfg.ServerURL+"/agent/heartbeat?agent_id="+cfg.AgentID, nil)
			if cfg.AgentToken != "" {
				req.Header.Set("X-Fleet-Agent-Token", cfg.AgentToken)
			}
			resp, err := client.Do(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				status := resp.StatusCode
				resp.Body.Close()
				if status == 404 {
					// Server lost DB state; re-register promptly
					registerAgent("heartbeat returned 404 unknown agent")
				}
			}
			<-t.C
		}
	}()

	for {
		now := time.Now()

		if lastInv.IsZero() || now.Sub(lastInv) >= cfg.InvEvery {
			pkgs, err := collectDpkgPackages(ctx)
			if err == nil {
				inv := InventoryPayload{
					AgentID:         cfg.AgentID,
					CollectedAtUnix: time.Now().Unix(),
					Packages:        pkgs,
				}
				mustPostJSON(client, cfg.ServerURL+"/agent/inventory/packages", inv, cfg.AgentToken)
				// Also send upgradable package snapshot (no apt-get update here; uses local apt cache)
				if updates, uerr := collectUpgradablePackages(ctx); uerr == nil {
					upInv := UpdatesInventoryPayload{
						AgentID:       cfg.AgentID,
						CheckedAtUnix: time.Now().Unix(),
						Updates:       updates,
					}
					mustPostJSON(client, cfg.ServerURL+"/agent/inventory/package-updates", upInv, cfg.AgentToken)
				}
				lastInv = now
			} else {
				fmt.Fprintf(os.Stderr, "inventory error: %v\n", err)
			}
		}

		job := pollNextJob(client, cfg.ServerURL, cfg.AgentID, registerAgent, cfg.AgentToken)
		if job != nil {
			handleJob(ctx, client, cfg.ServerURL, cfg.AgentID, job, cfg.AgentToken)
		}

		time.Sleep(cfg.PollEvery)
	}
}

func loadConfig() Config {
	server := getenv("FLEET_SERVER_URL", "http://localhost:8000")
	agentID := getenv("FLEET_AGENT_ID", "srv-001")
	labelsRaw := getenv("FLEET_LABELS", "")

	labels := map[string]string{}
	if labelsRaw != "" {
		parts := strings.Split(labelsRaw, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			kv := strings.SplitN(p, "=", 2)
			if len(kv) == 2 {
				labels[kv[0]] = kv[1]
			}
		}
	}

	return Config{
		ServerURL:  server,
		AgentID:    agentID,
		Labels:     labels,
		PollEvery:  2 * time.Second,
		InvEvery:   5 * time.Minute,
		HbEvery:    5 * time.Second,
		AgentToken: getenv("FLEET_AGENT_TOKEN", ""),
	}
}

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}

func mustPostJSON(client *http.Client, url string, payload any, token string) {
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Fleet-Agent-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "POST %s error: %v\n", url, err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "POST %s status: %s\n", url, resp.Status)
	}
}

func collectDpkgPackages(ctx context.Context) ([]PackageItem, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${Package}|${Version}|${Architecture}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	pkgs := make([]PackageItem, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		parts := strings.Split(l, "|")
		if len(parts) != 3 {
			continue
		}
		pkgs = append(pkgs, PackageItem{Name: parts[0], Version: parts[1], Arch: parts[2]})
	}
	return pkgs, nil
}

func collectUpgradablePackages(ctx context.Context) ([]UpdateItem, error) {
	// Best-effort; relies on existing apt cache. Should be cheap and keeps DB warm for UI restarts.
	stdout, _, code, errMsg := queryPkgUpdates(ctx, false)
	if code != 0 || errMsg != "" {
		return nil, fmt.Errorf(errMsg)
	}
	var parsed struct {
		CheckedAt      string       `json:"checked_at"`
		RebootRequired bool         `json:"reboot_required"`
		Updates        []UpdateItem `json:"updates"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		return nil, err
	}
	if parsed.Updates == nil {
		return []UpdateItem{}, nil
	}
	return parsed.Updates, nil
}

func pollNextJob(client *http.Client, serverURL, agentID string, registerAgent func(reason string), token string) *Job {
	u := fmt.Sprintf("%s/agent/next-job?agent_id=%s", serverURL, agentID)
	req, _ := http.NewRequest("GET", u, nil)
	if token != "" {
		req.Header.Set("X-Fleet-Agent-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		// Server restarted/DB reset, and /agent/next-job now enforces that the agent must exist.
		if registerAgent != nil {
			registerAgent("next-job returned 404 unknown agent")
		}
		return nil
	}
	if resp.StatusCode >= 300 {
		return nil
	}
	var r NextJobResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&r); err != nil {
		return nil
	}
	return r.Job
}

func handleJob(ctx context.Context, client *http.Client, serverURL, agentID string, job *Job, token string) {
	mustPostJSON(client, serverURL+"/agent/job-event", JobEvent{AgentID: agentID, JobID: job.JobID, Status: "running"}, token)

	var ev JobEvent
	ev.AgentID = agentID
	ev.JobID = job.JobID

	switch job.Type {
	case "pkg-upgrade":
		stdout, stderr, code, errMsg := runPkgUpgrade(ctx, job.Packages)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "pkg-install":
		stdout, stderr, code, errMsg := runPkgInstall(ctx, job.Packages)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "dist-upgrade":
		stdout, stderr, code, errMsg := runDistUpgrade(ctx)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "pkg-reinstall":
		stdout, stderr, code, errMsg := runPkgReinstall(ctx, job.Packages)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "pkg-remove":
		stdout, stderr, code, errMsg := runPkgRemove(ctx, job.Packages)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "inventory-now":
		stdout, stderr, code, errMsg := runInventoryNow(ctx, client, serverURL, agentID, token)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-pkg-version":
		stdout, stderr, code, errMsg := queryPkgVersions(ctx, job.Packages)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-pkg-info":
		pkgName := strings.TrimSpace(job.PackageName)
		if pkgName == "" {
			// backwards compat: allow passing via service_name
			pkgName = strings.TrimSpace(job.ServiceName)
		}
		stdout, stderr, code, errMsg := queryPkgInfo(ctx, pkgName)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-pkg-updates":
		stdout, stderr, code, errMsg := queryPkgUpdates(ctx, job.Refresh)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-users":
		stdout, stderr, code, errMsg := queryUsers(ctx)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-services":
		stdout, stderr, code, errMsg := queryServices(ctx)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-metrics":
		stdout, stderr, code, errMsg := querySystemMetrics(ctx)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-top-processes":
		stdout, stderr, code, errMsg := queryTopProcesses(ctx)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "service-control":
		stdout, stderr, code, errMsg := controlService(ctx, job.ServiceName, job.Action)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "check-reboot":
		stdout, stderr, code, errMsg := checkRebootRequired(ctx)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "reboot":
		stdout, stderr, code, errMsg := scheduleReboot(ctx)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-df":
		stdout, stderr, code, errMsg := queryDf(ctx)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-service-details":
		name := strings.TrimSpace(job.ServiceName)
		if name == "" {
			name = strings.TrimSpace(job.Action)
		}
		stdout, stderr, code, errMsg := queryServiceDetails(ctx, name)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "query-user-details":
		name := strings.TrimSpace(job.ServiceName)
		if name == "" {
			name = strings.TrimSpace(job.Action)
		}
		stdout, stderr, code, errMsg := queryUserDetails(ctx, name)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "ssh-key-deploy":
		username := strings.TrimSpace(job.ServiceName)
		if username == "" {
			username = strings.TrimSpace(job.Action) // backwards compat
		}
		// We overload fields for now: ServiceName=username, Action=sudo_profile, PackageName=public_key
		pub := strings.TrimSpace(job.PackageName)
		profile := strings.TrimSpace(job.Action)
		stdout, stderr, code, errMsg := deploySSHKey(ctx, username, pub, profile)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return

	case "user-lock", "user-unlock":
		username := job.ServiceName // Use ServiceName field for username
		stdout, stderr, code, errMsg := controlUser(ctx, username, job.Type)
		if code == 0 && errMsg == "" {
			ev.Status = "success"
		} else {
			ev.Status = "failed"
		}
		ev.ExitCode = &code
		ev.Stdout = stdout
		ev.Stderr = stderr
		ev.Error = errMsg
		mustPostJSON(client, serverURL+"/agent/job-event", ev, token)
		return
	}

	code := 2
	mustPostJSON(client, serverURL+"/agent/job-event", JobEvent{
		AgentID: agentID, JobID: job.JobID, Status: "failed", ExitCode: &code, Error: "unknown job type",
	}, token)
}

func queryDf(ctx context.Context) (string, string, int, string) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Prefer stable columns to make it easier to read with multiple disks.
	cmd := exec.CommandContext(queryCtx, "df", "-h", "--output=source,fstype,size,used,avail,pcent,target")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback for older df that doesn't support --output
		cmd2 := exec.CommandContext(queryCtx, "df", "-h")
		out2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			exit := 1
			if ee, ok := err2.(*exec.ExitError); ok {
				exit = ee.ExitCode()
			}
			return string(out2), "", exit, fmt.Sprintf("df -h failed: %v", err2)
		}
		return string(out2), "", 0, ""
	}

	return string(out), "", 0, ""
}

func queryServiceDetails(ctx context.Context, serviceName string) (string, string, int, string) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	name := strings.TrimSpace(serviceName)
	if name == "" {
		return "", "", 1, "service_name is required"
	}
	// Basic safety: reject whitespace.
	if len(strings.Fields(name)) != 1 {
		return "", "", 1, "invalid service name"
	}

	props := []string{
		"FragmentPath",
		"MemoryCurrent",
		"Requires",
		"Wants",
		"WantedBy",
		"ConsistsOf",
		"Conflicts",
		"Before",
		"After",
	}

	args := []string{"show", name}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	args = append(args, "--no-pager")

	cmd := exec.CommandContext(queryCtx, "systemctl", args...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		exit := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		return string(b), "", exit, fmt.Sprintf("systemctl show failed: %v", err)
	}

	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[k] = v
	}

	memCur := m["MemoryCurrent"]
	memBytes := int64(0)
	if memCur != "" {
		if n, err := strconv.ParseInt(memCur, 10, 64); err == nil {
			memBytes = n
		}
	}

	out := map[string]any{
		"name": name,
		"fragment_path": m["FragmentPath"],
		"memory_current": memCur,
		"memory_current_human": formatBytes(memBytes),
		"requires": m["Requires"],
		"wants": m["Wants"],
		"wanted_by": m["WantedBy"],
		"consists_of": m["ConsistsOf"],
		"conflicts": m["Conflicts"],
		"before": m["Before"],
		"after": m["After"],
	}

	j, err := json.Marshal(out)
	if err != nil {
		return "", "", 1, fmt.Sprintf("JSON marshal failed: %v", err)
	}
	return string(j), "", 0, ""
}

func formatBytes(n int64) string {
	if n <= 0 {
		return "0B"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d%s", n, units[i])
	}
	return fmt.Sprintf("%.1f%s", f, units[i])
}

func queryUserDetails(ctx context.Context, username string) (string, string, int, string) {
	queryCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	u := strings.TrimSpace(username)
	if u == "" {
		return "", "", 1, "username is required"
	}
	// strict-ish username validation
	if shellEscape(u) != u {
		return "", "", 1, "invalid username"
	}

	out := map[string]any{"username": u}

	// getent passwd
	cmd := exec.CommandContext(queryCtx, "getent", "passwd", u)
	b, err := cmd.Output()
	if err == nil {
		line := strings.TrimSpace(string(b))
		parts := strings.Split(line, ":")
		if len(parts) >= 7 {
			out["uid"] = parts[2]
			out["gid"] = parts[3]
			out["home"] = parts[5]
			out["shell"] = parts[6]
			out["gecos"] = parts[4]
		}
	}

	// groups
	cmd2 := exec.CommandContext(queryCtx, "id", "-nG", u)
	b2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		out["groups"] = strings.TrimSpace(string(b2))
	}

	// locked?
	cmd3 := exec.CommandContext(queryCtx, "passwd", "-S", u)
	b3, _ := cmd3.CombinedOutput()
	ps := strings.TrimSpace(string(b3))
	out["password_status"] = ps
	out["locked"] = strings.Contains(ps, " L ") || strings.Contains(ps, "LK")

	// sudo rules (best effort)
	cmd4 := exec.CommandContext(queryCtx, "sudo", "-n", "-l", "-U", u)
	b4, err4 := cmd4.CombinedOutput()
	if err4 == nil {
		out["has_sudo"] = true
		out["sudo_rules"] = strings.TrimSpace(string(b4))
	} else {
		out["has_sudo"] = false
		// Still include output; helps debug why sudo check failed.
		out["sudo_rules"] = strings.TrimSpace(string(b4))
	}

	// last login (best effort)
	cmd5 := exec.CommandContext(queryCtx, "lastlog", "-u", u)
	b5, err5 := cmd5.CombinedOutput()
	if err5 == nil {
		out["last_login"] = strings.TrimSpace(string(b5))
	}

	j, err := json.Marshal(out)
	if err != nil {
		return "", "", 1, fmt.Sprintf("JSON marshal failed: %v", err)
	}
	return string(j), "", 0, ""
}

func queryPkgVersions(ctx context.Context, packages []string) (string, string, int, string) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	type PkgVersion struct {
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		Found   bool   `json:"found"`
	}

	out := make([]PkgVersion, 0, len(packages))
	for _, name := range packages {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		cmd := exec.CommandContext(queryCtx, "dpkg-query", "-W", "-f", "${Version}", name)
		b, err := cmd.Output()
		if err != nil {
			out = append(out, PkgVersion{Name: name, Found: false})
			continue
		}
		out = append(out, PkgVersion{Name: name, Version: strings.TrimSpace(string(b)), Found: true})
	}

	res := map[string]any{"packages": out}
	j, err := json.Marshal(res)
	if err != nil {
		return "", "", 1, fmt.Sprintf("JSON marshal failed: %v", err)
	}
	return string(j), "", 0, ""
}

func queryPkgInfo(ctx context.Context, pkgName string) (string, string, int, string) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pkgName = strings.TrimSpace(pkgName)
	if pkgName == "" {
		return "", "", 1, "package_name is required"
	}

	type PkgInfo struct {
		Name             string                 `json:"name"`
		InstalledVersion string                 `json:"installed_version,omitempty"`
		CandidateVersion string                 `json:"candidate_version,omitempty"`
		Architecture     string                 `json:"architecture,omitempty"`
		Section          string                 `json:"section,omitempty"`
		Priority         string                 `json:"priority,omitempty"`
		Maintainer       string                 `json:"maintainer,omitempty"`
		Homepage         string                 `json:"homepage,omitempty"`
		Summary          string                 `json:"summary,omitempty"`
		Description      string                 `json:"description,omitempty"`
		Raw              map[string]interface{} `json:"raw,omitempty"`
	}

	info := PkgInfo{Name: pkgName, Raw: map[string]interface{}{}}

	// dpkg status (installed version, arch, description)
	dpkgCmd := exec.CommandContext(queryCtx, "dpkg", "-s", pkgName)
	dpkgOut, dpkgErr := dpkgCmd.CombinedOutput()
	info.Raw["dpkg_status"] = string(dpkgOut)
	if dpkgErr == nil {
		lines := strings.Split(string(dpkgOut), "\n")
		inDesc := false
		var descLines []string
		for _, line := range lines {
			line = strings.TrimRight(line, "\r")
			if strings.HasPrefix(line, "Version:") {
				info.InstalledVersion = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			} else if strings.HasPrefix(line, "Architecture:") {
				info.Architecture = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
			} else if strings.HasPrefix(line, "Section:") {
				info.Section = strings.TrimSpace(strings.TrimPrefix(line, "Section:"))
			} else if strings.HasPrefix(line, "Priority:") {
				info.Priority = strings.TrimSpace(strings.TrimPrefix(line, "Priority:"))
			} else if strings.HasPrefix(line, "Maintainer:") {
				info.Maintainer = strings.TrimSpace(strings.TrimPrefix(line, "Maintainer:"))
			} else if strings.HasPrefix(line, "Homepage:") {
				info.Homepage = strings.TrimSpace(strings.TrimPrefix(line, "Homepage:"))
			} else if strings.HasPrefix(line, "Description:") {
				info.Summary = strings.TrimSpace(strings.TrimPrefix(line, "Description:"))
				inDesc = true
			} else if inDesc {
				// dpkg description continuation lines often start with space
				if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
					descLines = append(descLines, strings.TrimSpace(line))
				} else if strings.TrimSpace(line) == "" {
					// keep paragraph breaks
					descLines = append(descLines, "")
				} else {
					// stop if we hit another header
					inDesc = false
				}
			}
		}
		if len(descLines) > 0 {
			info.Description = strings.TrimSpace(strings.Join(descLines, "\n"))
		}
	}

	// apt-cache policy (installed/candidate)
	policyCmd := exec.CommandContext(queryCtx, "apt-cache", "policy", pkgName)
	policyOut, _ := policyCmd.CombinedOutput()
	info.Raw["apt_policy"] = string(policyOut)
	for _, line := range strings.Split(string(policyOut), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(line, "Installed:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "Installed:"))
			if v != "" && v != "(none)" {
				info.InstalledVersion = v
			}
		} else if strings.HasPrefix(line, "Candidate:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			if v != "" && v != "(none)" {
				info.CandidateVersion = v
			}
		}
	}

	// apt-cache show (fallback for summary/description if dpkg not installed)
	showCmd := exec.CommandContext(queryCtx, "apt-cache", "show", pkgName)
	showOut, _ := showCmd.CombinedOutput()
	info.Raw["apt_show"] = string(showOut)
	if info.Summary == "" || info.Description == "" || info.Homepage == "" || info.Maintainer == "" || info.Section == "" || info.Priority == "" {
		// parse first stanza
		lines := strings.Split(string(showOut), "\n")
		inDesc := false
		var descLines []string
		for _, line := range lines {
			line = strings.TrimRight(line, "\r")
			if strings.TrimSpace(line) == "" {
				// stop after first stanza
				if inDesc || len(descLines) > 0 || info.Summary != "" {
					break
				}
				continue
			}
			if strings.HasPrefix(line, "Description:") {
				if info.Summary == "" {
					info.Summary = strings.TrimSpace(strings.TrimPrefix(line, "Description:"))
				}
				inDesc = true
				continue
			}
			if inDesc {
				if strings.HasPrefix(line, " ") {
					descLines = append(descLines, strings.TrimSpace(line))
					continue
				}
				inDesc = false
			}
			if strings.HasPrefix(line, "Homepage:") && info.Homepage == "" {
				info.Homepage = strings.TrimSpace(strings.TrimPrefix(line, "Homepage:"))
			} else if strings.HasPrefix(line, "Maintainer:") && info.Maintainer == "" {
				info.Maintainer = strings.TrimSpace(strings.TrimPrefix(line, "Maintainer:"))
			} else if strings.HasPrefix(line, "Section:") && info.Section == "" {
				info.Section = strings.TrimSpace(strings.TrimPrefix(line, "Section:"))
			} else if strings.HasPrefix(line, "Priority:") && info.Priority == "" {
				info.Priority = strings.TrimSpace(strings.TrimPrefix(line, "Priority:"))
			}
		}
		if info.Description == "" && len(descLines) > 0 {
			info.Description = strings.TrimSpace(strings.Join(descLines, "\n"))
		}
	}

	j, err := json.Marshal(info)
	if err != nil {
		return "", "", 1, fmt.Sprintf("JSON marshal failed: %v", err)
	}
	return string(j), "", 0, ""
}

func queryPkgUpdates(ctx context.Context, refresh bool) (string, string, int, string) {
	// Compute list of upgradable packages using apt. Optionally refresh package lists.
	// Also tries to classify which upgrades are security updates via `pro security-status --format json`.
	queryCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	secVersions, secReboot := securityUpdatesFromPro(queryCtx)

	type Up struct {
		Name             string `json:"name"`
		InstalledVersion string `json:"installed_version,omitempty"`
		CandidateVersion string `json:"candidate_version,omitempty"`
		IsSecurity       bool   `json:"is_security,omitempty"`
	}

	out := struct {
		CheckedAt      string `json:"checked_at"`
		RebootRequired bool   `json:"reboot_required"`
		Updates        []Up   `json:"updates"`
	}{
		CheckedAt:      time.Now().UTC().Format(time.RFC3339),
		RebootRequired: secReboot,
		Updates:        []Up{},
	}

	// Refresh package lists if requested (needs sudo)
	if refresh {
		upd := exec.CommandContext(queryCtx, "sudo", "-n", "apt-get", "update")
		updOut, updErr := upd.CombinedOutput()
		if updErr != nil {
			return string(updOut), "", 1, fmt.Sprintf("apt-get update failed: %v", updErr)
		}
	}

	// apt list --upgradable format varies; parse best-effort.
	cmd := exec.CommandContext(queryCtx, "apt", "list", "--upgradable")
	b, err := cmd.CombinedOutput()
	if err != nil {
		// apt returns non-zero sometimes; still may contain useful output
		// We'll treat complete failure as error only if output is empty.
		if len(b) == 0 {
			return "", string(b), 1, fmt.Sprintf("apt list --upgradable failed: %v", err)
		}
	}

	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Listing...") {
			continue
		}
		// Some apt versions can emit warnings on stdout; ignore them.
		if strings.HasPrefix(line, "WARNING:") || strings.HasPrefix(line, "W:") {
			continue
		}
		// Example:
		// dirmngr/jammy-updates 2.2.27-3ubuntu2.4 amd64 [upgradable from: 2.2.27-3ubuntu2.3]
		// or:
		// openssl/jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.17]
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		namePart := parts[0]
		pocket := ""
		if sp := strings.SplitN(namePart, "/", 2); len(sp) == 2 {
			namePart = sp[0]
			pocket = sp[1]
		}
		name := namePart
		// Basic sanity check: dpkg package names are typically [a-z0-9][a-z0-9+.-]+
		if name == "" {
			continue
		}
		valid := true
		for i, ch := range name {
			if i == 0 {
				if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') {
					valid = false
					break
				}
				continue
			}
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '.' || ch == '-' {
				continue
			}
			valid = false
			break
		}
		if !valid {
			continue
		}
		cand := parts[1]
		installed := ""
		if i := strings.Index(line, "[upgradable from:"); i >= 0 {
			frag := line[i:]
			// frag: [upgradable from: X]
			frag = strings.TrimPrefix(frag, "[upgradable from:")
			frag = strings.TrimSuffix(frag, "]")
			installed = strings.TrimSpace(frag)
		}
		// Prefer pro security-status classification; fall back to pocket name.
		isSec := false
		proVer := ""
		if v, ok := secVersions[name]; ok {
			isSec = true
			proVer = strings.TrimSpace(v)
		} else {
			isSec = strings.Contains(pocket, "security") || strings.Contains(pocket, "-security")
		}

		// Important: do NOT generally override apt's candidate version with Pro's version.
		// Pro can report a security version that is *not preferred* (older than -updates).
		// We only pin versions for kernel/meta packages where we want the security stream specifically.
		if proVer != "" && isKernelMetaPackage(name) {
			cand = proVer
		}

		out.Updates = append(out.Updates, Up{Name: name, CandidateVersion: cand, InstalledVersion: installed, IsSecurity: isSec})
	}

	j, jerr := json.Marshal(out)
	if jerr != nil {
		return "", "", 1, fmt.Sprintf("JSON marshal failed: %v", jerr)
	}
	return string(j), "", 0, ""
}

func securityUpdatesFromPro(ctx context.Context) (map[string]string, bool) {
	// Returns map[package]securityVersion for packages that Pro considers security updates,
	// plus a reboot-required flag (best-effort).

	sec := map[string]string{}
	rebootRequired := false

	proCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(proCtx, "pro", "security-status", "--format", "json")
	b, err := cmd.CombinedOutput()
	if err != nil || len(b) == 0 {
		return sec, rebootRequired
	}

	// Minimal structure for parsing.
	type proPkg struct {
		Package     string `json:"package"`
		ServiceName string `json:"service_name"`
		Status      string `json:"status"`
		Version     string `json:"version"`
	}
	type proSummary struct {
		RebootRequired string `json:"reboot_required"`
	}
	type proOut struct {
		Packages []proPkg   `json:"packages"`
		Summary  proSummary `json:"summary"`
	}

	var parsed proOut
	if jerr := json.Unmarshal(b, &parsed); jerr != nil {
		return sec, rebootRequired
	}

	if strings.TrimSpace(strings.ToLower(parsed.Summary.RebootRequired)) == "yes" {
		rebootRequired = true
	}

	for _, p := range parsed.Packages {
		name := strings.TrimSpace(p.Package)
		if name == "" {
			continue
		}
		if strings.TrimSpace(p.ServiceName) != "standard-security" {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(p.Status), "upgrade_available") {
			continue
		}
		sec[name] = strings.TrimSpace(p.Version)
	}

	return sec, rebootRequired
}

func isKernelMetaPackage(name string) bool {
	n := strings.TrimSpace(name)
	if n == "" {
		return false
	}
	// Meta/kernel families that often need pinning or special handling.
	if n == "linux-virtual" || n == "linux-generic" || n == "linux-image-generic" || n == "linux-headers-generic" {
		return true
	}
	if n == "linux-image-virtual" || n == "linux-headers-virtual" {
		return true
	}
	if strings.HasPrefix(n, "linux-headers-") || strings.HasPrefix(n, "linux-image-") || strings.HasPrefix(n, "linux-modules-") {
		return true
	}
	if strings.HasSuffix(n, "-generic") && strings.HasPrefix(n, "linux-") {
		return true
	}
	return false
}

func runPkgUpgrade(ctx context.Context, packages []string) (string, string, int, string) {
	if len(packages) == 0 {
		return "", "", 0, ""
	}

	upd := exec.CommandContext(ctx, "sudo", "-n", "apt-get", "update")
	updOut, updErr := upd.CombinedOutput()
	if updErr != nil {
		return string(updOut), "", 1, fmt.Sprintf("apt-get update failed: %v", updErr)
	}

	args := []string{"-n", "apt-get", "-y", "install", "--only-upgrade"}
	args = append(args, packages...)
	cmd := exec.CommandContext(ctx, "sudo", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		exit := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		return string(append(updOut, out...)), "", exit, fmt.Sprintf("apt-get only-upgrade failed: %v", err)
	}
	return string(append(updOut, out...)), "", 0, ""
}

func runPkgInstall(ctx context.Context, packages []string) (string, string, int, string) {
	// Install specific packages, optionally with explicit versions (e.g. name=1.2.3).
	if len(packages) == 0 {
		return "", "", 0, ""
	}

	upd := exec.CommandContext(ctx, "sudo", "-n", "apt-get", "update")
	updOut, updErr := upd.CombinedOutput()
	if updErr != nil {
		return string(updOut), "", 1, fmt.Sprintf("apt-get update failed: %v", updErr)
	}

	args := []string{"-n", "apt-get", "-y", "install"}
	args = append(args, packages...)
	cmd := exec.CommandContext(ctx, "sudo", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		exit := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		return string(append(updOut, out...)), "", exit, fmt.Sprintf("apt-get install failed: %v", err)
	}
	return string(append(updOut, out...)), "", 0, ""
}

func runDistUpgrade(ctx context.Context) (string, string, int, string) {
	// Full upgrade (apt-get dist-upgrade). Higher blast radius, but most reliable for transitions.
	upgradeCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	upd := exec.CommandContext(upgradeCtx, "sudo", "-n", "apt-get", "update")
	updOut, updErr := upd.CombinedOutput()
	if updErr != nil {
		return string(updOut), "", 1, fmt.Sprintf("apt-get update failed: %v", updErr)
	}

	cmd := exec.CommandContext(upgradeCtx, "sudo", "-n", "apt-get", "-y", "dist-upgrade")
	out, err := cmd.CombinedOutput()
	if err != nil {
		exit := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		return string(append(updOut, out...)), "", exit, fmt.Sprintf("apt-get dist-upgrade failed: %v", err)
	}

	// Cleanup old dependencies to keep machines tidy.
	auto := exec.CommandContext(upgradeCtx, "sudo", "-n", "apt-get", "-y", "autoremove")
	autoOut, autoErr := auto.CombinedOutput()
	if autoErr != nil {
		// Don't fail the whole job; just report it in output.
		combined := append(updOut, out...)
		combined = append(combined, []byte("\n\n[WARN] apt-get autoremove failed: ")...)
		combined = append(combined, []byte(autoErr.Error())...)
		combined = append(combined, []byte("\n")...)
		combined = append(combined, autoOut...)
		return string(combined), "", 0, ""
	}

	combined := append(updOut, out...)
	combined = append(combined, []byte("\n\n[INFO] apt-get autoremove output:\n")...)
	combined = append(combined, autoOut...)
	return string(combined), "", 0, ""
}

func runPkgReinstall(ctx context.Context, packages []string) (string, string, int, string) {
	if len(packages) == 0 {
		return "", "", 0, ""
	}
	upd := exec.CommandContext(ctx, "sudo", "-n", "apt-get", "update")
	updOut, updErr := upd.CombinedOutput()
	if updErr != nil {
		return string(updOut), "", 1, fmt.Sprintf("apt-get update failed: %v", updErr)
	}
	args := []string{"-n", "apt-get", "-y", "install", "--reinstall"}
	args = append(args, packages...)
	cmd := exec.CommandContext(ctx, "sudo", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		exit := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		return string(append(updOut, out...)), "", exit, fmt.Sprintf("apt-get reinstall failed: %v", err)
	}
	return string(append(updOut, out...)), "", 0, ""
}

func runPkgRemove(ctx context.Context, packages []string) (string, string, int, string) {
	if len(packages) == 0 {
		return "", "", 0, ""
	}
	// Removing doesn't require apt-get update; keep it fast.
	args := []string{"-n", "apt-get", "-y", "remove"}
	args = append(args, packages...)
	cmd := exec.CommandContext(ctx, "sudo", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		exit := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		return string(out), "", exit, fmt.Sprintf("apt-get remove failed: %v", err)
	}
	return string(out), "", 0, ""
}

func runInventoryNow(ctx context.Context, client *http.Client, serverURL, agentID string, token string) (string, string, int, string) {
	// Collect and POST inventory immediately, so UI can reflect latest packages/updates on demand.
	queryCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	pkgs, err := collectDpkgPackages(queryCtx)
	if err != nil {
		return "", "", 1, fmt.Sprintf("collect packages failed: %v", err)
	}
	inv := InventoryPayload{
		AgentID:         agentID,
		CollectedAtUnix: time.Now().Unix(),
		Packages:        pkgs,
	}
	mustPostJSON(client, serverURL+"/agent/inventory/packages", inv, token)

	updates, uerr := collectUpgradablePackages(queryCtx)
	if uerr == nil {
		upInv := UpdatesInventoryPayload{
			AgentID:       agentID,
			CheckedAtUnix: time.Now().Unix(),
			Updates:       updates,
		}
		mustPostJSON(client, serverURL+"/agent/inventory/package-updates", upInv, token)
	}

	out := map[string]interface{}{
		"ok":                true,
		"packages":          len(pkgs),
		"updates_collected": uerr == nil,
		"updates": func() int {
			if uerr != nil {
				return 0
			}
			return len(updates)
		}(),
	}
	b, jerr := json.Marshal(out)
	if jerr != nil {
		return "", "", 1, fmt.Sprintf("json marshal failed: %v", jerr)
	}
	return string(b), "", 0, ""
}

func readOSVersion() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VERSION_ID=") {
			return strings.Trim(line[len("VERSION_ID="):], "\"")
		}
	}
	return ""
}

func readKernel() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func queryUsers(ctx context.Context) (string, string, int, string) {
	// Create a context with timeout to prevent hanging
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Get all users from /etc/passwd
	cmd := exec.CommandContext(queryCtx, "getent", "passwd")
	out, err := cmd.Output()
	if err != nil {
		return "", "", 1, fmt.Sprintf("getent passwd failed: %v", err)
	}

	type UserInfo struct {
		Username string `json:"username"`
		UID      string `json:"uid"`
		GID      string `json:"gid"`
		Home     string `json:"home"`
		Shell    string `json:"shell"`
		HasSudo  bool   `json:"has_sudo"`
		IsLocked bool   `json:"is_locked"`
	}

	// Get list of users in sudo group once (more efficient)
	sudoGroupUsers := make(map[string]bool)
	sudoGroupCmd := exec.CommandContext(queryCtx, "getent", "group", "sudo")
	if sudoGroupOut, err := sudoGroupCmd.Output(); err == nil {
		// Parse: sudo:x:27:user1,user2,user3
		parts := strings.Split(strings.TrimSpace(string(sudoGroupOut)), ":")
		if len(parts) >= 4 {
			members := strings.Split(parts[3], ",")
			for _, member := range members {
				if member != "" {
					sudoGroupUsers[member] = true
				}
			}
		}
	}

	// Also check wheel and admin groups
	for _, groupName := range []string{"wheel", "admin"} {
		groupCmd := exec.CommandContext(queryCtx, "getent", "group", groupName)
		if groupOut, err := groupCmd.Output(); err == nil {
			parts := strings.Split(strings.TrimSpace(string(groupOut)), ":")
			if len(parts) >= 4 {
				members := strings.Split(parts[3], ",")
				for _, member := range members {
					if member != "" {
						sudoGroupUsers[member] = true
					}
				}
			}
		}
	}

	var users []UserInfo
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		uid := parts[2]
		gid := parts[3]
		home := parts[5]
		shell := parts[6]

		// Check if user has sudo access (check our pre-built map)
		hasSudo := sudoGroupUsers[username]

		// Check if account is locked by examining multiple factors:
		// 1. Password locked (shadow file has ! prefix)
		// 2. Account expired (expire date in shadow file)
		// 3. Shell set to nologin/false
		isLocked := false
		shadowCmd := exec.CommandContext(queryCtx, "sudo", "-n", "getent", "shadow", username)
		if shadowOut, err := shadowCmd.Output(); err == nil {
			shadowLine := strings.TrimSpace(string(shadowOut))
			parts := strings.Split(shadowLine, ":")
			if len(parts) >= 2 {
				passwordField := parts[1]
				// Check password lock: locked accounts have password field:
				// - "!" or "*" (completely disabled)
				// - "!$6$..." (locked password hash - passwd -l prepends !)
				passwordLocked := passwordField == "!" || passwordField == "*" || strings.HasPrefix(passwordField, "!")

				// Check account expiration (8th field in shadow file)
				// Empty or -1 means never expires, otherwise it's days since epoch
				accountExpired := false
				if len(parts) >= 9 {
					expireField := parts[8]
					if expireField != "" && expireField != "-1" {
						// If expire date is set and in the past, account is expired
						// For our locking, we set it to "1" (1970-01-02), so any small number means expired
						var expireDays int64
						n, err := fmt.Sscanf(expireField, "%d", &expireDays)
						if err == nil && n == 1 {
							// Calculate current days since epoch
							now := time.Now()
							epoch := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
							currentDays := int64(now.Sub(epoch).Hours() / 24)
							if expireDays > 0 && expireDays < currentDays {
								accountExpired = true
							}
						}
					}
				}

				isLocked = passwordLocked || accountExpired
			}
		}

		// Also check if shell is nologin/false (indicates account is disabled)
		if shell == "/usr/sbin/nologin" || shell == "/bin/false" || shell == "/sbin/nologin" {
			isLocked = true
		}

		// Fallback to passwd -S if shadow check failed
		if !isLocked {
			passwdStatusCmd := exec.CommandContext(queryCtx, "sudo", "-n", "passwd", "-S", username)
			if statusOut, err := passwdStatusCmd.Output(); err == nil {
				// Output format: "username P 01/01/2024 0 99999 7 -1"
				// P = password set, L = locked, NP = no password
				statusLine := strings.TrimSpace(string(statusOut))
				statusFields := strings.Fields(statusLine)
				if len(statusFields) >= 2 {
					statusChar := statusFields[1]
					if statusChar == "L" {
						isLocked = true
					}
				}
			}
		}

		// Only include regular users (UID >= 1000) or root
		uidInt := 0
		fmt.Sscanf(uid, "%d", &uidInt)
		if uidInt >= 1000 || uidInt == 0 {
			users = append(users, UserInfo{
				Username: username,
				UID:      uid,
				GID:      gid,
				Home:     home,
				Shell:    shell,
				HasSudo:  hasSudo,
				IsLocked: isLocked,
			})
		}
	}

	result := map[string]interface{}{
		"users": users,
	}
	jsonOut, err := json.Marshal(result)
	if err != nil {
		return "", "", 1, fmt.Sprintf("JSON marshal failed: %v", err)
	}

	return string(jsonOut), "", 0, ""
}

func queryServices(ctx context.Context) (string, string, int, string) {
	// Create a context with timeout to prevent hanging
	queryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	type ServiceInfo struct {
		Name        string `json:"name"`
		Status      string `json:"status"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
	}

	// Map to track services we've seen (by name)
	serviceMap := make(map[string]*ServiceInfo)

	// First, query all units (including failed ones)
	cmd := exec.CommandContext(queryCtx, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
	out, err := cmd.Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Remove bullet character if present (●)
			line = strings.TrimPrefix(line, "●")
			line = strings.TrimSpace(line)

			// Parse systemctl output format: UNIT LOAD ACTIVE SUB DESCRIPTION
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}

			name := fields[0]
			loadState := fields[1]
			activeState := fields[2]
			description := strings.Join(fields[4:], " ")

			// Clean up service name (remove .service suffix)
			name = strings.TrimSuffix(name, ".service")

			// Include all loaded services, and also failed services regardless of load state
			if loadState == "loaded" || activeState == "failed" {
				// Determine status
				status := "inactive"
				if activeState == "active" {
					status = "active"
				} else if activeState == "failed" {
					status = "failed"
				} else if activeState == "activating" {
					status = "activating"
				} else if activeState == "deactivating" {
					status = "deactivating"
				}

				serviceMap[name] = &ServiceInfo{
					Name:        name,
					Status:      status,
					Description: description,
					Enabled:     false, // Will be checked later
				}
			}
		}
	}

	// Also query failed services specifically to catch any that might be missed
	cmd2 := exec.CommandContext(queryCtx, "systemctl", "list-units", "--type=service", "--state=failed", "--no-pager", "--no-legend")
	out2, err2 := cmd2.Output()
	if err2 == nil {
		lines := strings.Split(strings.TrimSpace(string(out2)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Remove bullet character if present
			line = strings.TrimPrefix(line, "●")
			line = strings.TrimSpace(line)

			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}

			name := fields[0]
			description := strings.Join(fields[4:], " ")
			name = strings.TrimSuffix(name, ".service")

			// Add failed service if not already in map
			if _, exists := serviceMap[name]; !exists {
				serviceMap[name] = &ServiceInfo{
					Name:        name,
					Status:      "failed",
					Description: description,
					Enabled:     false, // Will be checked later
				}
			} else {
				// Update existing entry to ensure status is "failed"
				serviceMap[name].Status = "failed"
			}
		}
	}

	// Check enabled state for each service
	for name, svc := range serviceMap {
		// Check if service is enabled using systemctl is-enabled
		enabledCmd := exec.CommandContext(queryCtx, "systemctl", "is-enabled", name+".service")
		enabledOut, err := enabledCmd.Output()
		svc.Enabled = false
		if err == nil {
			enabledState := strings.TrimSpace(string(enabledOut))
			// "enabled" or "enabled-runtime" means enabled
			svc.Enabled = enabledState == "enabled" || enabledState == "enabled-runtime"
		}
		// If command fails (e.g., service not found), Enabled remains false
	}

	// Convert map to slice
	var services []ServiceInfo
	for _, svc := range serviceMap {
		services = append(services, *svc)
	}

	result := map[string]interface{}{
		"services": services,
	}
	jsonOut, err := json.Marshal(result)
	if err != nil {
		return "", "", 1, fmt.Sprintf("JSON marshal failed: %v", err)
	}

	return string(jsonOut), "", 0, ""
}

func querySystemMetrics(ctx context.Context) (string, string, int, string) {
	// Create a context with timeout to prevent hanging
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	type ProcessInfo struct {
		PID     int     `json:"pid"`
		User    string  `json:"user"`
		CPU     float64 `json:"cpu_percent"`
		Mem     float64 `json:"mem_percent"`
		Command string  `json:"command"`
	}

	type SystemMetrics struct {
		TopProcesses []ProcessInfo `json:"top_processes"`
		DiskUsage    struct {
			TotalGB     float64 `json:"total_gb"`
			UsedGB      float64 `json:"used_gb"`
			AvailableGB float64 `json:"available_gb"`
			PercentUsed float64 `json:"percent_used"`
		} `json:"disk_usage"`
		Memory struct {
			TotalGB     float64 `json:"total_gb"`
			UsedGB      float64 `json:"used_gb"`
			AvailableGB float64 `json:"available_gb"`
			PercentUsed float64 `json:"percent_used"`
		} `json:"memory"`
		CPU struct {
			VCPUs     int     `json:"vcpus"`
			Load1Min  float64 `json:"load_1min"`
			Load5Min  float64 `json:"load_5min"`
			Load15Min float64 `json:"load_15min"`
		} `json:"cpu"`
		IPAddresses []string `json:"ip_addresses"`
	}

	var metrics SystemMetrics

	// Top processes by CPU (%CPU), include %MEM as well
	psCmd := exec.CommandContext(queryCtx, "ps", "-eo", "pid,user,pcpu,pmem,comm", "--sort=-pcpu")
	if psOut, err := psCmd.Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(psOut)), "\n")
		// Skip header
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			var p ProcessInfo
			fmt.Sscanf(fields[0], "%d", &p.PID)
			p.User = fields[1]
			fmt.Sscanf(fields[2], "%f", &p.CPU)
			fmt.Sscanf(fields[3], "%f", &p.Mem)
			p.Command = fields[4]
			metrics.TopProcesses = append(metrics.TopProcesses, p)
			if len(metrics.TopProcesses) >= 10 {
				break
			}
		}
	}

	// Get disk usage using df
	dfCmd := exec.CommandContext(queryCtx, "df", "-BG", "/")
	dfOut, err := dfCmd.Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(dfOut)), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 4 {
				var total, used, avail float64
				fmt.Sscanf(fields[1], "%f", &total)
				fmt.Sscanf(fields[2], "%f", &used)
				fmt.Sscanf(fields[3], "%f", &avail)
				metrics.DiskUsage.TotalGB = total
				metrics.DiskUsage.UsedGB = used
				metrics.DiskUsage.AvailableGB = avail
				if total > 0 {
					metrics.DiskUsage.PercentUsed = (used / total) * 100
				}
			}
		}
	}

	// Get memory info from /proc/meminfo
	memCmd := exec.CommandContext(queryCtx, "cat", "/proc/meminfo")
	memOut, err := memCmd.Output()
	if err == nil {
		lines := strings.Split(string(string(memOut)), "\n")
		var memTotal, memAvailable, memFree, buffers, cached int64
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fmt.Sscanf(line, "MemTotal: %d kB", &memTotal)
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fmt.Sscanf(line, "MemAvailable: %d kB", &memAvailable)
			} else if strings.HasPrefix(line, "MemFree:") {
				fmt.Sscanf(line, "MemFree: %d kB", &memFree)
			} else if strings.HasPrefix(line, "Buffers:") {
				fmt.Sscanf(line, "Buffers: %d kB", &buffers)
			} else if strings.HasPrefix(line, "Cached:") {
				fmt.Sscanf(line, "Cached: %d kB", &cached)
			}
		}
		if memTotal > 0 {
			metrics.Memory.TotalGB = float64(memTotal) / 1024.0 / 1024.0
			if memAvailable > 0 {
				metrics.Memory.AvailableGB = float64(memAvailable) / 1024.0 / 1024.0
				metrics.Memory.UsedGB = metrics.Memory.TotalGB - metrics.Memory.AvailableGB
			} else {
				// Fallback: calculate from MemFree + Buffers + Cached
				availableKB := memFree + buffers + cached
				metrics.Memory.AvailableGB = float64(availableKB) / 1024.0 / 1024.0
				metrics.Memory.UsedGB = metrics.Memory.TotalGB - metrics.Memory.AvailableGB
			}
			if metrics.Memory.TotalGB > 0 {
				metrics.Memory.PercentUsed = (metrics.Memory.UsedGB / metrics.Memory.TotalGB) * 100
			}
		}
	}

	// Get CPU info (vCPUs and load)
	// Get vCPU count from /proc/cpuinfo
	cpuInfoCmd := exec.CommandContext(queryCtx, "grep", "-c", "^processor", "/proc/cpuinfo")
	cpuInfoOut, err := cpuInfoCmd.Output()
	if err == nil {
		var vcpus int
		fmt.Sscanf(strings.TrimSpace(string(cpuInfoOut)), "%d", &vcpus)
		metrics.CPU.VCPUs = vcpus
	}

	// Get load average from /proc/loadavg
	loadCmd := exec.CommandContext(queryCtx, "cat", "/proc/loadavg")
	loadOut, err := loadCmd.Output()
	if err == nil {
		var load1, load5, load15 float64
		fmt.Sscanf(strings.TrimSpace(string(loadOut)), "%f %f %f", &load1, &load5, &load15)
		metrics.CPU.Load1Min = load1
		metrics.CPU.Load5Min = load5
		metrics.CPU.Load15Min = load15
	}

	// Get IP addresses using ip or ifconfig
	ipCmd := exec.CommandContext(queryCtx, "ip", "-4", "addr", "show")
	ipOut, err := ipCmd.Output()
	if err == nil {
		lines := strings.Split(string(ipOut), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "inet ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					ip := strings.Split(parts[1], "/")[0]
					if ip != "127.0.0.1" {
						metrics.IPAddresses = append(metrics.IPAddresses, ip)
					}
				}
			}
		}
	} else {
		// Fallback to ifconfig
		ifconfigCmd := exec.CommandContext(queryCtx, "ifconfig")
		ifconfigOut, err2 := ifconfigCmd.Output()
		if err2 == nil {
			lines := strings.Split(string(ifconfigOut), "\n")
			for _, line := range lines {
				if strings.Contains(line, "inet ") && !strings.Contains(line, "127.0.0.1") {
					parts := strings.Fields(line)
					for i, part := range parts {
						if part == "inet" && i+1 < len(parts) {
							ip := strings.Split(parts[i+1], ":")[0]
							if ip != "127.0.0.1" {
								metrics.IPAddresses = append(metrics.IPAddresses, ip)
							}
							break
						}
					}
				}
			}
		}
	}

	result := map[string]interface{}{
		"metrics": metrics,
	}
	jsonOut, err := json.Marshal(result)
	if err != nil {
		return "", "", 1, fmt.Sprintf("JSON marshal failed: %v", err)
	}

	return string(jsonOut), "", 0, ""
}

func queryTopProcesses(ctx context.Context) (string, string, int, string) {
	// Faster path used for frequent polling
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	type ProcessInfo struct {
		PID     int     `json:"pid"`
		User    string  `json:"user"`
		CPU     float64 `json:"cpu_percent"`
		Mem     float64 `json:"mem_percent"`
		Command string  `json:"command"`
	}

	out := make([]ProcessInfo, 0, 10)
	psCmd := exec.CommandContext(queryCtx, "ps", "-eo", "pid,user,pcpu,pmem,comm", "--sort=-pcpu")
	psOut, err := psCmd.CombinedOutput()
	if err != nil {
		return "", string(psOut), 1, fmt.Sprintf("ps failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(psOut)), "\n")
	for _, line := range lines[1:] { // skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		var p ProcessInfo
		fmt.Sscanf(fields[0], "%d", &p.PID)
		p.User = fields[1]
		fmt.Sscanf(fields[2], "%f", &p.CPU)
		fmt.Sscanf(fields[3], "%f", &p.Mem)
		p.Command = fields[4]
		out = append(out, p)
		if len(out) >= 10 {
			break
		}
	}

	result := map[string]interface{}{"top_processes": out}
	jsonOut, err := json.Marshal(result)
	if err != nil {
		return "", "", 1, fmt.Sprintf("JSON marshal failed: %v", err)
	}
	return string(jsonOut), "", 0, ""
}

func controlService(ctx context.Context, serviceName, action string) (string, string, int, string) {
	if serviceName == "" {
		return "", "", 1, "service name is required"
	}

	// Create a context with timeout to prevent hanging
	// Some services may take longer to start/stop, so allow up to 30 seconds
	controlCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch action {
	case "start":
		// Use --no-block to prevent systemctl from waiting for service to fully start
		// This allows the command to return immediately after queuing the start request
		cmd = exec.CommandContext(controlCtx, "sudo", "-n", "systemctl", "start", "--no-block", serviceName)
	case "stop":
		cmd = exec.CommandContext(controlCtx, "sudo", "-n", "systemctl", "stop", serviceName)
	case "restart":
		// Use --no-block to prevent systemctl from waiting for service to fully restart
		// This allows the command to return immediately after queuing the restart request
		cmd = exec.CommandContext(controlCtx, "sudo", "-n", "systemctl", "restart", "--no-block", serviceName)
	case "enable":
		cmd = exec.CommandContext(controlCtx, "sudo", "-n", "systemctl", "enable", serviceName)
	case "disable":
		cmd = exec.CommandContext(controlCtx, "sudo", "-n", "systemctl", "disable", serviceName)
	default:
		return "", "", 1, fmt.Sprintf("invalid action: %s (must be start, stop, restart, enable, or disable)", action)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's a timeout error
		if controlCtx.Err() == context.DeadlineExceeded {
			return string(out), "", 1, fmt.Sprintf("systemctl %s timed out after 30 seconds", action)
		}
		exit := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		return string(out), "", exit, fmt.Sprintf("systemctl %s failed: %v", action, err)
	}

	return string(out), "", 0, ""
}

func checkRebootRequired(ctx context.Context) (string, string, int, string) {
	// Reboot hint file used by many Ubuntu packages.
	// If it exists, a reboot is required.
	_, err := os.Stat("/var/run/reboot-required")
	required := false
	if err == nil {
		required = true
	}
	out := map[string]any{"reboot_required": required}
	b, jerr := json.Marshal(out)
	if jerr != nil {
		return "", "", 1, fmt.Sprintf("json marshal failed: %v", jerr)
	}
	return string(b), "", 0, ""
}

func scheduleReboot(ctx context.Context) (string, string, int, string) {
	// Schedule a reboot slightly in the future so the agent can report job success.
	// shutdown requires sudo and will return immediately after scheduling.
	rebootCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(rebootCtx, "sudo", "-n", "shutdown", "-r", "+1", "fleet reboot")
	out, err := cmd.CombinedOutput()
	if err != nil {
		exit := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		return string(out), "", exit, fmt.Sprintf("shutdown -r failed: %v", err)
	}
	res := map[string]any{"ok": true, "scheduled": true, "when": "+1 minute"}
	b, jerr := json.Marshal(res)
	if jerr != nil {
		return string(out), "", 1, fmt.Sprintf("json marshal failed: %v", jerr)
	}
	// include command output too, but keep it readable
	return string(b) + "\n" + string(out), "", 0, ""
}

func controlUser(ctx context.Context, username, action string) (string, string, int, string) {
	if username == "" {
		return "", "", 1, "username is required"
	}

	// Create a context with timeout to prevent hanging
	controlCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var allOutput strings.Builder

	if action == "user-lock" {
		// To completely disable account (prevent all logins including SSH keys):
		// 1. Lock the password (passwd -l)
		// 2. Expire the account (usermod --expiredate 1) - sets expire date to 1970-01-02
		// 3. Change shell to nologin (usermod -s /usr/sbin/nologin)

		// Lock password
		cmd1 := exec.CommandContext(controlCtx, "sudo", "-n", "passwd", "-l", username)
		out1, err1 := cmd1.CombinedOutput()
		allOutput.WriteString(string(out1))
		if err1 != nil {
			// Check if it's a timeout error
			if controlCtx.Err() == context.DeadlineExceeded {
				return allOutput.String(), "", 1, fmt.Sprintf("passwd -l timed out after 10 seconds")
			}
			// passwd -l might return error even on success, check output
			if !strings.Contains(string(out1), "password expiry information changed") &&
				!strings.Contains(string(out1), "Lock password") {
				return allOutput.String(), "", 1, fmt.Sprintf("passwd -l failed: %v, output: %s", err1, string(out1))
			}
		}

		// Expire account to prevent all logins (including SSH keys)
		cmd2 := exec.CommandContext(controlCtx, "sudo", "-n", "usermod", "--expiredate", "1", username)
		out2, err2 := cmd2.CombinedOutput()
		allOutput.WriteString(string(out2))
		if err2 != nil {
			if controlCtx.Err() == context.DeadlineExceeded {
				return allOutput.String(), "", 1, fmt.Sprintf("usermod --expiredate timed out")
			}
			return allOutput.String(), "", 1, fmt.Sprintf("usermod --expiredate failed: %v, output: %s", err2, string(out2))
		}

		// Change shell to nologin to prevent interactive logins
		cmd3 := exec.CommandContext(controlCtx, "sudo", "-n", "usermod", "-s", "/usr/sbin/nologin", username)
		out3, err3 := cmd3.CombinedOutput()
		allOutput.WriteString(string(out3))
		if err3 != nil {
			if controlCtx.Err() == context.DeadlineExceeded {
				return allOutput.String(), "", 1, fmt.Sprintf("usermod -s timed out")
			}
			return allOutput.String(), "", 1, fmt.Sprintf("usermod -s failed: %v, output: %s", err3, string(out3))
		}

		return allOutput.String(), "", 0, ""

	} else if action == "user-unlock" {
		// To unlock account:
		// 1. Unlock password (passwd -u)
		// 2. Remove expiration (usermod --expiredate "" or future date)
		// 3. Restore original shell (we need to get it from /etc/passwd first)

		// Get original shell from /etc/passwd before we potentially change it
		// We'll try to get it from the current passwd entry
		getentCmd := exec.CommandContext(controlCtx, "getent", "passwd", username)
		getentOut, err := getentCmd.Output()
		originalShell := "/bin/bash" // Default shell if we can't determine
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(getentOut)), ":")
			if len(parts) >= 7 {
				currentShell := parts[6]
				// If shell is nologin or false, use bash as default
				if currentShell != "/usr/sbin/nologin" && currentShell != "/bin/false" && currentShell != "/sbin/nologin" {
					originalShell = currentShell
				}
			}
		}

		// Unlock password
		cmd1 := exec.CommandContext(controlCtx, "sudo", "-n", "passwd", "-u", username)
		out1, err1 := cmd1.CombinedOutput()
		allOutput.WriteString(string(out1))
		if err1 != nil {
			if controlCtx.Err() == context.DeadlineExceeded {
				return allOutput.String(), "", 1, fmt.Sprintf("passwd -u timed out")
			}

			outStr := string(out1)
			// Common case for newly created accounts: unlocking would create a passwordless account.
			// Fix by setting a random password (so it's not passwordless) and then unlock.
			if strings.Contains(outStr, "passwordless account") {
				// generate random password from /dev/urandom (do not log it)
				pwCmd := exec.CommandContext(controlCtx, "bash", "-lc", "tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32")
				pwBytes, pwErr := pwCmd.Output()
				if pwErr == nil {
					pw := strings.TrimSpace(string(pwBytes))
					if pw != "" {
						// set password
						setCmd := exec.CommandContext(controlCtx, "bash", "-lc", fmt.Sprintf("echo %s | sudo -n chpasswd", shellQuote(fmt.Sprintf("%s:%s", username, pw))))
						setOut, setErr := setCmd.CombinedOutput()
						allOutput.WriteString(string(setOut))
						if setErr == nil {
							// retry unlock
							retryCmd := exec.CommandContext(controlCtx, "sudo", "-n", "passwd", "-u", username)
							retryOut, retryErr := retryCmd.CombinedOutput()
							allOutput.WriteString(string(retryOut))
							if retryErr == nil {
								goto passwd_unlocked
							}
						}
					}
				}
			}

			// passwd -u might return error even on success
			if !strings.Contains(outStr, "password expiry information changed") &&
				!strings.Contains(outStr, "Unlock password") {
				return allOutput.String(), "", 1, fmt.Sprintf("passwd -u failed: %v, output: %s", err1, outStr)
			}
		}
		passwd_unlocked:

		// Remove expiration (set to empty string to clear expiration)
		cmd2 := exec.CommandContext(controlCtx, "sudo", "-n", "usermod", "--expiredate", "", username)
		out2, err2 := cmd2.CombinedOutput()
		allOutput.WriteString(string(out2))
		if err2 != nil {
			if controlCtx.Err() == context.DeadlineExceeded {
				return allOutput.String(), "", 1, fmt.Sprintf("usermod --expiredate timed out")
			}
			return allOutput.String(), "", 1, fmt.Sprintf("usermod --expiredate failed: %v, output: %s", err2, string(out2))
		}

		// Restore shell
		cmd3 := exec.CommandContext(controlCtx, "sudo", "-n", "usermod", "-s", originalShell, username)
		out3, err3 := cmd3.CombinedOutput()
		allOutput.WriteString(string(out3))
		if err3 != nil {
			if controlCtx.Err() == context.DeadlineExceeded {
				return allOutput.String(), "", 1, fmt.Sprintf("usermod -s timed out")
			}
			return allOutput.String(), "", 1, fmt.Sprintf("usermod -s failed: %v, output: %s", err3, string(out3))
		}

		return allOutput.String(), "", 0, ""
	} else {
		return "", "", 1, fmt.Sprintf("invalid action: %s (must be user-lock or user-unlock)", action)
	}
}

func deploySSHKey(ctx context.Context, username, publicKey, sudoProfile string) (string, string, int, string) {
	key := strings.TrimSpace(publicKey)
	username = strings.TrimSpace(username)
	if username == "" || key == "" {
		return "", "", 1, "username and public_key required"
	}
	// Security: enforce strict linux username policy.
	if shellEscape(username) != username {
		return "", "", 1, "invalid username (allowed: A-Z a-z 0-9 _ -)"
	}
	// Create user if missing.
	// useradd -m -s /bin/bash <username>
	cmds := []string{
		"set -e",
		fmt.Sprintf("id -u %s >/dev/null 2>&1 || sudo -n useradd -m -s /bin/bash %s", shellEscape(username), shellEscape(username)),
		fmt.Sprintf("sudo -n mkdir -p /home/%s/.ssh", shellEscape(username)),
		fmt.Sprintf("sudo -n chown %s:%s /home/%s/.ssh", shellEscape(username), shellEscape(username), shellEscape(username)),
		fmt.Sprintf("sudo -n chmod 700 /home/%s/.ssh", shellEscape(username)),
		fmt.Sprintf("sudo -n touch /home/%s/.ssh/authorized_keys", shellEscape(username)),
		fmt.Sprintf("sudo -n chmod 600 /home/%s/.ssh/authorized_keys", shellEscape(username)),
		fmt.Sprintf("sudo -n chown %s:%s /home/%s/.ssh/authorized_keys", shellEscape(username), shellEscape(username), shellEscape(username)),
	}

	// Safest key options: disable forwarding/X11/agent, but allow PTY.
	opts := "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc"
	line := fmt.Sprintf("%s %s", opts, key)
	// Append key if not already present (match by key body).
	// NOTE: avoid nested quotes like: sudo bash -lc '... echo '...'' which breaks when the key/comment contains special chars.
	cmds = append(cmds, fmt.Sprintf(
		"sudo -n grep -Fq %s /home/%s/.ssh/authorized_keys || printf %s | sudo -n tee -a /home/%s/.ssh/authorized_keys >/dev/null",
		shellQuote(secondField(key)), shellEscape(username), shellQuote(line+"\n"), shellEscape(username),
	))

	// Sudo profile B: apt + systemctl + reboot (NOPASSWD) with absolute paths.
	if strings.TrimSpace(strings.ToUpper(sudoProfile)) == "B" {
		sudoers := fmt.Sprintf("/etc/sudoers.d/fleet-%s", username)
		content := fmt.Sprintf("%s ALL=(root) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /bin/systemctl, /usr/sbin/reboot, /sbin/reboot\n", username)
		// Avoid nested quoting (same issue as authorized_keys). Write via sudo tee.
		cmds = append(cmds, fmt.Sprintf(
			"printf '%%s' %s | sudo -n tee %s >/dev/null",
			shellQuote(content), shellEscape(sudoers),
		))
		cmds = append(cmds, fmt.Sprintf("sudo -n chmod 440 %s", shellEscape(sudoers)))
	}

	script := strings.Join(cmds, "\n")
	execCmd := exec.CommandContext(ctx, "bash", "-lc", script)
	out, err := execCmd.CombinedOutput()
	if err != nil {
		exit := 1
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		}
		return string(out), "", exit, fmt.Sprintf("ssh-key deploy failed: %v", err)
	}
	return string(out), "", 0, ""
}

func secondField(pub string) string {
	parts := strings.Fields(strings.TrimSpace(pub))
	if len(parts) >= 2 {
		return parts[1]
	}
	return pub
}

func shellEscape(s string) string {
	// very small helper for usernames/paths: allow alnum, _ and - only.
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "invalid"
	}
	return string(out)
}

func shellQuote(s string) string {
	// single-quote for bash -lc
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
