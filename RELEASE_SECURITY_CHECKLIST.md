# RELEASE_SECURITY_CHECKLIST.md

Use this checklist before every public release/tag.

## 1) Secrets & sensitive data
- [ ] Secret scan of current tree passed (`gitleaks detect --source . --no-banner`)
- [ ] Secret scan of git history passed (GitHub Action "Security" job or local full-history scan)
- [ ] If anything sensitive was found, secrets were rotated first
- [ ] No real credentials/tokens/passwords in examples or docs
- [ ] No real customer/internal data in repo (IPs, hostnames, emails, webhook URLs, inventories)

## 2) Dependency & code security
- [ ] Semgrep scan passed
- [ ] Python dependency audit passed (`pip-audit -r server/requirements.txt`)
- [ ] Node dependency audit passed (`npm audit --omit=dev`)
- [ ] Go vulnerability scan passed (`govulncheck ./agent/...`)
- [ ] Trivy filesystem scan passed
- [ ] Trivy config/IaC scan passed (`deploy/`)

## 3) Secure deployment defaults
- [ ] `BOOTSTRAP_PASSWORD` is required and non-placeholder
- [ ] `AGENT_SHARED_TOKEN` is required and non-placeholder
- [ ] `MFA_ENCRYPTION_KEY` is required when MFA is enabled
- [ ] Docs clearly require `UI_COOKIE_SECURE=true` behind HTTPS
- [ ] Docs clearly require `AGENT_TERMINAL_SCHEME=wss` when terminal is enabled
- [ ] Production guidance documents `DB_AUTO_CREATE_TABLES=false`
- [ ] High-risk terminal feature is clearly marked and token-gated

## 4) Runtime/egress verification
- [ ] Outbound egress behavior reviewed in a controlled environment
- [ ] Unexpected internet calls investigated/blocked
- [ ] Only expected outbound paths allowed by firewall policy

## 5) Process gates
- [ ] GitHub branch protection requires the **Security** check
- [ ] Pull requests cannot merge while Security checks fail
- [ ] Release notes include any security-relevant changes

## 6) Manual high-risk review (spot check)
- [ ] Terminal/websocket proxy paths
- [ ] Ansible and subprocess execution paths
- [ ] SSH key handling/deployment paths
- [ ] Export/report endpoints for sensitive data leakage
- [ ] Stored XSS and injection checks on rendered host/package/log fields

---

Tip: keep this file strict but lightweight; update it whenever security controls change.
