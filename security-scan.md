# Security Scan Report: Linux Central Management

**Date:** 2026-02-20
**Target:** `/home/imre/linux-central-management`
**Status:** ⚠️ Potential Privacy Leaks Found

## 🚨 Critical Findings

### 1. External Data Leak (Agent)
The agent contains code to fetch CVE details directly from Ubuntu's servers.
- **File:** `agent/internal/cve.go`
- **Code:** `url := fmt.Sprintf("https://ubuntu.com/security/%s", cve)`
- **Impact:** This sends the CVE ID you are interested in to `ubuntu.com`. While not sending *your* private data, it reveals what vulnerabilities you are checking, which could fingerprint your system's security posture to an external party.
- **Recommendation:** Disable this fallback or proxy it through your own server if "air-gapped" behavior is required.

### 2. External CDN Usage (Server/UI)
The web interface loads assets (JS/CSS) from `cdn.jsdelivr.net`.
- **Files:**
    - `server/app/templates/index.html`
    - `server/app/templates/terminal_popup.html`
    - `server/app/app_factory.py` (CSP headers allow `cdn.jsdelivr.net`)
- **Impact:** Every time a user opens the dashboard, their browser makes requests to a third-party CDN. This leaks user IP addresses and usage timing to `jsdelivr`.
- **Recommendation:** Download `xterm.js` and `xterm.css` and serve them locally from the `server/app/static` directory.

## ℹ️ Configuration & Secrets

### 3. Default Passwords
- **Observation:** `docker-compose.yml` and `env.example` use default passwords like `change-me-long-random` or `fleet`.
- **Action:** Ensure you set `BOOTSTRAP_PASSWORD` and `POSTGRES_PASSWORD` to strong, unique values in your actual `.env` file before deployment.

### 4. Hardcoded URLs
- **Observation:** `script.sh` defaults to `http://192.168.100.240:8000`.
- **Action:** Verify this IP matches your deployment to avoid connection errors.

## ✅ Safe Practices Observed
- Most internal communication (Agent <-> Server) appears to use configurable `FLEET_SERVER_URL`.
- Secrets in tests (`admin-password-123`) are properly isolated.

---

**Next Steps:**
1. Shall I patch `agent/internal/cve.go` to disable the external Ubuntu check?
2. Shall I download the CDN assets and update the templates to serve them locally?
