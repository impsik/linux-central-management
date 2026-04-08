# Linux Central Management — Best Next 10 Features

This document translates the current product direction into the next 10 highest-value features for a Linux central administration platform.

Current strengths already present in the product:
- fleet inventory and per-host drill-down
- package actions and patch campaign rollout controls
- approvals / high-risk gating foundations
- MFA / OIDC / audit logging
- backup verification
- saved views and notifications

The next step is not adding random dashboards. The next step is making fleet operations safer, more targetable, more explainable, and more automatable.

---

## Priority Order

### 1. Per-group maintenance windows

Why it matters:
- global maintenance windows are too blunt for real fleets
- prod, stage, db, edge, and lab hosts need different execution windows

What to add:
- maintenance windows scoped by labels / saved groups
- timezone-aware schedules
- allow/deny preview before execution
- reason codes in API/UI when a job is blocked

Good acceptance criteria:
- a job targeting `env=prod` can be blocked while the same action on `env=stage` is allowed
- blocked jobs return clear machine-readable reason codes and human-readable explanations

---

### 2. Job preflight checks

Why it matters:
- risky actions should fail before dispatch, not halfway through execution

What to add:
- apt/dpkg lock detection
- disk-space threshold checks
- package DB health checks
- pending reboot detection
- host online/heartbeat health validation
- optional service-specific checks

Good acceptance criteria:
- patch/reboot/upgrade actions can return `blocked_by_preflight` with exact failed checks
- operators can run preflight in dry-run mode before approval or dispatch

---

### 3. Health-gated patch + reboot orchestration

Why it matters:
- patching is not finished when packages install
- real fleet safety needs post-action validation

What to add:
- canary wave patching with health checks before next wave
- optional reboot orchestration after patching
- post-reboot health verification
- automatic pause on failure threshold
- operator-visible failure reasons

Good acceptance criteria:
- a wave only advances if health gate passes
- rollout pauses automatically when error ratio crosses threshold

---

### 4. Dynamic host groups

Why it matters:
- central administration becomes much more powerful when targeting is dynamic instead of manual

What to add:
- smart groups based on labels, OS version, package presence, reboot-required state, update backlog, compliance state
- target preview and host count before execution
- reusable saved dynamic cohorts

Good acceptance criteria:
- users can define a group like `env=prod AND security_updates>0 AND reboot_required=true`
- UI shows exact hosts matched before action execution

---

### 5. Agent version management

Why it matters:
- the control plane should manage the fleet agent lifecycle too

What to add:
- agent version reporting per host
- latest available version visibility
- controlled rolling agent upgrades
- version drift alerts

Good acceptance criteria:
- admin can target stale agent versions and upgrade them in waves
- fleet view shows version compliance status

---

### 6. Compliance / policy checks v1

Why it matters:
- this turns the product from a job runner into an operations governance tool

Starter checks:
- SSH root login disabled
- password auth policy state
- ufw/firewall enabled
- unattended-upgrades enabled
- auditd active
- NTP/time sync active
- required labels present

Good acceptance criteria:
- per-host compliance score exists
- failed checks are filterable and exportable
- drift from expected baseline is visible in UI

---

### 7. Better drift detection and host diff

Why it matters:
- operators often need `what changed?` more than `what exists?`

What to add:
- host-vs-host diff
- host-vs-baseline diff
- compare packages, services, users, labels, sudo/access state, update backlog
- group/fleet drift summaries

Good acceptance criteria:
- an operator can compare two hosts and quickly see operational differences without manual hunting

---

### 8. Notification and webhook rules

Why it matters:
- important fleet events should not require watching the UI constantly

What to add:
- rule-based notifications for approval requests, rollout pauses, job failure spikes, host offline state, compliance regressions, backup stale/failures
- outbound delivery to Teams/Slack/email/webhook
- dedupe + cooldown configuration per rule

Good acceptance criteria:
- alert routing is configurable by severity/event kind
- duplicate spam is prevented while preserving important signal

---

### 9. Safe access governance

Why it matters:
- Linux administration software should be strong at temporary privileged access workflows

What to add:
- temporary sudo grants with expiry
- temporary SSH key deployments with expiry
- access windows tied to approvals
- automatic revoke on expiry
- strong audit trail for who granted what and why

Good acceptance criteria:
- time-bound access can be granted and revoked automatically
- every elevation and revocation is attributable and reviewable

---

### 10. Runbook library / approved automation catalog

Why it matters:
- this is safer than arbitrary ad hoc remote command execution

What to add:
- named operational actions with parameters
- target restrictions
- approval requirements
- reusable runbooks for common Linux admin work

Examples:
- clear apt locks safely
- refresh package cache
- restart nginx safely
- collect diagnostics bundle
- rotate logs
- rotate SSH host keys

Good acceptance criteria:
- operators can execute approved actions consistently without crafting raw custom jobs each time

---

## Recommended Implementation Sequence

### Phase 1 — Safety Core
1. Per-group maintenance windows
2. Job preflight checks
3. Health-gated patch + reboot orchestration

### Phase 2 — Fleet Targeting and Control
4. Dynamic host groups
5. Agent version management
6. Compliance / policy checks v1

### Phase 3 — Operational Leverage
7. Drift detection and host diff
8. Notification and webhook rules
9. Safe access governance
10. Runbook library

---

## Suggested Product Positioning

The product should keep evolving toward:

"Safe centralized operations for Linux fleets: inventory, access governance, patching, compliance, and audited change execution."

That positioning helps reject low-value feature ideas and prioritize the ones that reduce operational risk and toil.

---

## What not to prioritize yet

Do not prioritize these ahead of the list above:
- decorative analytics dashboards
- broad arbitrary shell access expansion
- overbuilt plugin systems
- CMDB-style complexity with weak operational value

The core product should first excel at:
- knowing fleet state
- safely changing fleet state
- explaining why actions succeeded, failed, or were blocked
