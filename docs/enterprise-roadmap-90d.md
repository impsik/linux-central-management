# Enterprise Readiness Roadmap (90 Days)

This roadmap turns the current Fleet Ubuntu MVP into a production-grade enterprise platform with strong identity, policy, reliability, and compliance controls.

## Day-90 Outcomes

By the end of this plan:
- SSO (OIDC) is primary auth path.
- Scoped RBAC is safe and admin-friendly (structured UI, previewable scope impact).
- High-risk actions are policy-gated and auditable.
- Audit events are exported to SIEM.
- Job execution is resilient (queue + workers + retries).
- Security/compliance review can be passed with evidence.

---

## Phase A (Weeks 1-3): Identity & Access Hardening

### Week 1 — OIDC Foundation

**Goals**
- Add OIDC login support (Azure AD / Okta / Keycloak compatible).
- Keep local login as fallback via feature flag.

**Implementation**
- Add config keys:
  - `AUTH_OIDC_ENABLED`
  - `AUTH_OIDC_ISSUER`
  - `AUTH_OIDC_CLIENT_ID`
  - `AUTH_OIDC_CLIENT_SECRET`
  - `AUTH_OIDC_REDIRECT_URI`
  - `AUTH_OIDC_SCOPES`
  - `AUTH_OIDC_ALLOWED_EMAIL_DOMAINS`
- Add endpoints:
  - `GET /auth/oidc/login`
  - `GET /auth/oidc/callback`
  - `POST /auth/oidc/logout`
- Add login page button: **Sign in with SSO**.

**Acceptance Criteria**
- User can log in via OIDC and receive a valid app session.
- Invalid issuer/audience/nonce/state are rejected.
- Audit event recorded (`auth.login.oidc`).

### Week 2 — Group/Role Mapping

**Goals**
- Map IdP claims/groups to app roles and optional scope templates.

**Implementation**
- Add mapping config (group -> role, group -> selectors).
- Auto-provision user on first SSO login (if allowed domain).
- Add sync-on-login behavior for role/scope update.

**Acceptance Criteria**
- Role and scope are applied from IdP groups.
- Privilege reduction happens immediately when group removed.
- Audit events for role/scope sync changes.

### Week 3 — Scope UX Replacement

**Goals**
- Replace raw JSON scope editing with structured controls.

**Implementation**
- Admin UI scope editor:
  - key/value selectors (env/team/role/region)
  - multi-value chips
  - dry-run preview count + host list
- Add preview endpoint:
  - `POST /auth/admin/scope-preview`

**Acceptance Criteria**
- Admin can build scopes without raw JSON.
- Preview clearly shows blast radius before save.
- Invalid selectors fail with clear validation errors.

---

## Phase B (Weeks 4-6): Policy & Approval Controls

### Week 4 — Policy Engine v1

**Goals**
- Introduce central policy evaluation for risky actions.

**Implementation**
- Add policy model/table (rule sets + targeting + enforcement mode).
- Evaluate on: dist-upgrade, patch campaigns, reboots, MFA reset.
- Rule examples:
  - blocked outside maintenance window
  - protected labels (`env=prod`)
  - ticket required for protected targets

**Acceptance Criteria**
- Policy decision returns allow/deny + reason codes.
- UI surfaces policy block reason to user.

### Week 5 — Approval Strengthening

**Goals**
- Make approvals deterministic and enterprise-safe.

**Implementation**
- Enforce two-person rule for high-risk actions.
- Add approval expiration and stale-request handling.
- Add policy to require N approvers for selected actions/labels.

**Acceptance Criteria**
- Requester cannot approve own action.
- Expired approvals cannot execute.
- Audit trail includes request/decision/execution references.

### Week 6 — MFA Recovery Controls

**Goals**
- Harden MFA reset flow for enterprise operations.

**Implementation**
- Require mandatory reason/ticket for admin MFA reset.
- Optional dual-approval mode for MFA reset.
- Notify affected user on reset action.

**Acceptance Criteria**
- MFA reset actions always include justification.
- All reset steps are auditable and attributable.

---

## Phase C (Weeks 7-9): Reliability & Scale

### Week 7 — Queue/Worker Execution Model

**Goals**
- Decouple API from job execution.

**Implementation**
- Introduce queue backend (Redis/Rabbit).
- Worker service for execution dispatch.
- Retry/backoff + dead-letter queue.
- Idempotency key enforcement for dispatch.

**Acceptance Criteria**
- API remains responsive under load.
- Worker restarts do not lose in-flight work.

### Week 8 — Observability Baseline

**Goals**
- Make failures visible early.

**Implementation**
- Add metrics:
  - queue depth
  - job latency
  - success/failure rate
  - approval latency
- Add trace/correlation IDs across request->job->agent run.

**Acceptance Criteria**
- Dashboard and alerts exist for key SLO signals.
- A failed action can be traced end-to-end quickly.

### Week 9 — HA Readiness

**Goals**
- Prepare for multi-instance deployment.

**Implementation**
- Move singleton loops to leader-elected workers.
- Document failover behavior and operational limits.
- Add smoke tests for multi-instance routing/locking.

**Acceptance Criteria**
- No duplicate scheduler execution in multi-instance mode.
- Controlled failover documented and tested.

---

## Phase D (Weeks 10-12): Compliance & Enterprise Ops

### Week 10 — Compliance Checks v1

**Goals**
- Add baseline compliance visibility.

**Implementation**
- Checks (initial set):
  - SSH root login disabled
  - password auth policy
  - unattended-upgrades enabled
  - ufw enabled
  - auditd active
  - time sync active
- Host/fleet compliance scoring + trend.

**Acceptance Criteria**
- Per-host and fleet score visible in UI.
- Failed checks are filterable and exportable.

### Week 11 — Audit Export & Evidence

**Goals**
- Integrate with enterprise audit workflows.

**Implementation**
- SIEM export (JSON lines/webhook/syslog).
- Add signed evidence bundle export for time ranges.

**Acceptance Criteria**
- Audit export health is observable.
- Evidence bundle includes actor/action/target/timestamp integrity metadata.

### Week 12 — Operational Readiness

**Goals**
- Ensure recoverability and change safety.

**Implementation**
- Backup/restore drill.
- Migration rollback drill.
- Incident response playbook and escalation matrix.

**Acceptance Criteria**
- Drills completed and documented.
- Residual risks and mitigations recorded.

---

## Cross-Cutting Engineering Guardrails

- One logical change per commit/PR.
- Every schema migration includes rollback notes.
- Auth/RBAC/Policy changes require tests.
- Feature flags for risky rollouts.
- Default deny on ambiguous authorization paths.

---

## Weekly KPI Pack

Track weekly:
- `% users on SSO`
- `% high-risk actions approved per policy`
- `job success rate`
- `p95 job completion latency`
- `policy-blocked risky actions`
- `audit export success rate`

---

## Week 1 Ticket Plan (Immediate Next Sprint)

### Epic: OIDC SSO Foundation

1. **Config schema + docs**
   - Add OIDC env vars and validation in config.
   - Update README deployment/auth sections.

2. **OIDC login and callback router**
   - Implement login redirect, state/nonce generation, callback verification.
   - Create/reuse app session on success.

3. **User provisioning and account linking**
   - Match user by email/username claim.
   - Provision if absent and allowed.

4. **Audit and security checks**
   - Log `auth.login.oidc` events.
   - Reject invalid issuer/audience/signature/nonce/state.

5. **UI changes**
   - Add SSO login button and local-login fallback toggle.

6. **Tests**
   - Unit tests for token validation edge cases.
   - Integration smoke test for login flow.

7. **Rollout plan**
   - Feature flag on staging first.
   - Validate with pilot group.
   - Enable for production with break-glass local admin retained.
