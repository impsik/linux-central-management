# Linux Central Management — Enterprise Top-10 Roadmap

This is the single prioritized enterprise roadmap for the current product.

It replaces the fuzzier split between:
- `docs/next-10-features-roadmap.md`
- `docs/enterprise-roadmap-90d.md`

with one ordered list optimized for:
- enterprise buyer value
- operational safety
- implementation leverage from the current codebase
- reducing production risk before adding more surface area

Current product strengths already in place:
- fleet inventory and host drill-down
- package/service/user management
- ownership-aware host scoping
- MFA / OIDC groundwork / audit logging
- approvals foundation
- reports, cronjobs, SSH key flows

What the product still needs to feel truly enterprise:
- stronger policy and safety controls
- reusable targeting
- compliance visibility
- integration and reporting depth
- more predictable operational governance

---

## Priority 1 — Scoped maintenance windows

Why first:
- strongest safety ROI
- directly affects risky operations already present in the app
- enterprise customers expect policy-aware execution boundaries
- unlocks safer patching/reboot workflows later

Deliverables:
- maintenance windows targeted by labels and/or saved groups
- timezone-aware evaluation
- allow/deny decision with machine-readable reason codes
- UI preview showing whether current target set is inside or outside window
- consistent enforcement for risky actions

Acceptance criteria:
- `env=prod` targets can be blocked while `env=stage` targets are allowed
- API returns structured reason like `maintenance_window_blocked`
- UI shows clear human-readable block explanation
- tests cover timezone and boundary behavior

---

## Priority 2 — Job preflight checks

Why here:
- pairs naturally with maintenance windows
- prevents obvious unsafe jobs before dispatch
- turns failures into explainable policy outcomes instead of messy runtime breakage

Deliverables:
- apt/dpkg lock check
- disk-space threshold check
- host online/heartbeat check standardization
- package DB health check
- dry-run preflight result API
- structured failed-check reporting

Acceptance criteria:
- risky actions can be blocked before queueing
- UI can present exact failed preflight checks
- preflight can run without dispatching a real job

---

## Priority 3 — Health-gated patch and reboot orchestration

Why here:
- patching is one of the most enterprise-relevant workflows in the product
- safer rollouts matter more than adding more buttons

Deliverables:
- canary wave execution
- health gate before next wave
- optional reboot phase
- auto-pause on failure threshold
- rollout state + failure reason visibility

Acceptance criteria:
- rollout pauses automatically when health gate fails
- next wave only begins after success threshold passes
- operators can see why execution paused

---

## Priority 4 — Dynamic host groups

Why here:
- enterprise operations need reusable targeting, not repeated manual filtering
- this multiplies the value of maintenance windows, reporting, notifications, and campaigns

Deliverables:
- smart groups based on labels and fleet state
- preview matched hosts before execution
- saved dynamic cohorts reusable by jobs, reports, and policy

Acceptance criteria:
- groups like `env=prod AND reboot_required=true` are supported
- exact matched hosts are previewable before execution

---

## Priority 5 — Compliance and policy checks v1

Why here:
- moves the product from action console to governance platform
- helps answer “which hosts violate baseline?” instantly

Deliverables:
- baseline checks: SSH root login, password auth, firewall, unattended upgrades, auditd, time sync, required labels
- per-host and fleet-level compliance score
- filter/export for failed checks

Acceptance criteria:
- failed compliance checks are visible and exportable
- compliance status is filterable in the fleet UI

---

## Priority 6 — Notification and webhook rules

Why here:
- enterprise apps should push important events, not require constant watching
- builds on existing audit/events foundations

Deliverables:
- rule-based event notifications
- Slack/email/webhook targets
- dedupe/cooldown controls
- alert routing by severity or event type

Acceptance criteria:
- rollout pauses, approval requests, compliance regressions, offline hosts, and backup failures can trigger notifications

---

## Priority 7 — Safe access governance

Why here:
- very strong enterprise signal
- fits the product’s existing SSH/sudo/user-control model

Deliverables:
- temporary sudo grants with expiry
- temporary SSH key deployments with expiry
- approval-linked access windows
- automatic revocation
- strong audit evidence for elevation/revocation

Acceptance criteria:
- expiring elevated access is enforceable and auditable

---

## Priority 8 — Audit export and evidence bundles

Why here:
- security/compliance teams will ask for this early
- adds credibility without changing core fleet workflows

Deliverables:
- SIEM/syslog/webhook audit export
- signed or integrity-tagged export bundles
- export health visibility

Acceptance criteria:
- audit export can be enabled and monitored
- evidence bundles contain actor/action/target/timestamp metadata

---

## Priority 9 — Agent lifecycle management

Why here:
- enterprise control plane should manage the agent too
- reduces drift and support burden

Deliverables:
- agent version reporting
- stale-version visibility
- controlled agent upgrade waves
- version compliance filtering

Acceptance criteria:
- stale agents can be targeted and upgraded in waves
- fleet view shows version drift clearly

---

## Priority 10 — Runbook library / approved automation catalog

Why here:
- replaces ad hoc risky operations with approved reusable workflows
- increases standardization and auditability

Deliverables:
- named operational actions with parameters
- approval requirements per runbook
- target restrictions
- reusable standard runbooks

Acceptance criteria:
- operators can execute approved actions without constructing raw jobs manually

---

## Recommended execution sequence

### Phase A — Safety core
1. Scoped maintenance windows
2. Job preflight checks
3. Health-gated patch/reboot orchestration

### Phase B — Targeting and governance
4. Dynamic host groups
5. Compliance and policy checks v1
6. Notification and webhook rules

### Phase C — Enterprise operations depth
7. Safe access governance
8. Audit export and evidence bundles
9. Agent lifecycle management
10. Runbook library

---

## What I recommend implementing next

Start with Priority 1 using small slices:
1. backend policy model for scoped maintenance windows
2. evaluation helper returning structured allow/deny reason
3. enforce on one risky route first
4. add UI preview / explanation
5. expand enforcement to other risky routes

That gives the product immediate enterprise value without overreaching.
