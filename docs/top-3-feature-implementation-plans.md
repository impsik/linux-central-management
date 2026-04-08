# Top 3 Feature Implementation Plans

This document expands the top 3 roadmap issues into implementation-ready plans:
1. Per-group maintenance windows
2. Job preflight checks
3. Health-gated patch and reboot orchestration

The plans assume the current codebase already has:
- label-based targeting and saved views
- patch campaign rollout controls
- approvals and policy-related foundations
- host/job audit logging

---

## Plan 1 — Per-group maintenance windows

Goal
Allow risky operations to be evaluated against maintenance windows scoped by labels and/or saved target groups instead of only a single global configuration.

Architecture
Introduce a maintenance window policy model that can match a target set by label selectors or saved group references. Evaluate windows before risky job creation and campaign creation, returning structured allow/deny decisions and operator-facing reasons.

Primary files likely involved
- server/app/models.py
- server/app/schemas.py
- server/app/routers/hosts.py
- server/app/routers/patching.py
- server/app/services/maintenance.py
- server/app/services/targets.py
- server/app/services/audit.py
- server/tests/

Suggested implementation tasks

### Task 1: Add maintenance window policy persistence model
Files:
- Modify: server/app/models.py
- Add migration under: server/alembic/versions/

Add fields such as:
- name
- enabled
- timezone
- schedule_kind or cron-like rule shape
- label_selector JSON
- saved_view_id nullable
- action_scope list/string
- enforcement_mode (warn/block)
- created_by

Acceptance:
- migration applies cleanly
- model can persist multiple windows with different selectors

### Task 2: Add request/response schemas
Files:
- Modify: server/app/schemas.py

Add API schemas for:
- create/update maintenance window policy
- policy preview request
- policy decision response

Acceptance:
- invalid timezone / invalid selector rejected with clear validation errors

### Task 3: Extend maintenance service with target-aware evaluation
Files:
- Modify: server/app/services/maintenance.py
- Modify or add: server/app/services/targets.py

Implement helpers:
- resolve whether a host or target set matches a maintenance window
- evaluate “is now inside allowed window?”
- return reason codes like:
  - maintenance_window_blocked
  - maintenance_window_warn_only
  - no_matching_window

Acceptance:
- decision output is structured, stable, and reusable across UI/API

### Task 4: Add policy preview endpoint
Files:
- Add or modify router: likely server/app/routers/patching.py or dedicated policy router

Endpoint should:
- accept target selector / group / action type
- return matched maintenance windows
- return allowed/blocked now
- include human-readable explanation and machine-readable reason

Acceptance:
- preview works without dispatching a job

### Task 5: Enforce on risky job creation
Files:
- Modify: server/app/routers/hosts.py
- Modify: server/app/routers/patching.py
- Possibly modify: server/app/routers/jobs.py

Apply maintenance evaluation to risky actions like:
- dist-upgrade
- security campaign
- reboot
- other high-risk actions already guarded by policy/approval logic

Acceptance:
- risky actions are blocked or warned according to matched policy
- non-risky actions are unaffected

### Task 6: Add audit events
Files:
- Modify: server/app/services/audit.py

Record:
- maintenance window policy created/updated/deleted
- execution blocked by maintenance window
- preview checks if useful

Acceptance:
- audit timeline shows maintenance policy decisions for blocked risky actions

### Task 7: Add UI support
Files:
- UI templates / JS files related to policy/admin/patching/host actions

Add:
- policy editor form
- preview panel
- blocked-action explanation in modals/forms

Acceptance:
- admin can configure a policy without raw JSON if possible
- blocked actions clearly explain why

### Task 8: Test coverage
Files:
- Add tests under server/tests/

Minimum cases:
- timezone boundary behavior
- prod blocked / stage allowed example
- warn-only mode vs block mode
- selector mismatch means no policy match
- campaign creation blocked by maintenance policy

Acceptance:
- all cases pass in backend suite

---

## Plan 2 — Job preflight checks

Goal
Block clearly unsafe or invalid operations before dispatch and provide exact failure reasons.

Architecture
Create a reusable preflight engine that runs before risky actions. Keep the result structured so it can be reused by the UI, APIs, approvals, and future automation.

Primary files likely involved
- server/app/services/jobs.py
- server/app/services/maintenance.py
- server/app/services/targets.py
- server/app/routers/hosts.py
- server/app/routers/patching.py
- agent/ side job/probe support if needed
- server/tests/

Suggested implementation tasks

### Task 1: Define preflight result model
Files:
- Modify: server/app/schemas.py or add small service-local dataclasses

Structure should include:
- ok: bool
- checks: list of {key, status, detail, severity}
- blocked: bool
- reason_codes: list[str]

Acceptance:
- result is machine-readable and UI-friendly

### Task 2: Implement core preflight checks
Files:
- Add: server/app/services/preflight.py

Initial checks:
- agent online
- apt/dpkg lock detected
- package DB sanity
- disk free threshold
- pending reboot
- maybe stale inventory if action depends on fresh inventory

Acceptance:
- checks can run independently and together

### Task 3: Add host probe/job path where needed
Files:
- server/app/services/host_job_dispatch.py
- agent code if a lightweight probe job is needed

For checks requiring live host state beyond DB snapshots, support a lightweight query/preflight job.

Acceptance:
- risky action preflight can use both cached data and live checks where necessary

### Task 4: Add preflight API preview endpoint
Files:
- server/app/routers/hosts.py or server/app/routers/jobs.py

Endpoint should:
- accept action + targets
- return structured preflight result without dispatch

Acceptance:
- operators can inspect preflight failures before requesting approval or running action

### Task 5: Enforce preflight before risky dispatch
Files:
- server/app/routers/hosts.py
- server/app/routers/patching.py
- maybe server/app/routers/jobs.py

For risky actions:
- run preflight
- if blocked, return structured blocked response
- do not create executable job/campaign when block mode applies

Acceptance:
- blocked actions do not create side-effectful job runs
- API response explains exact failed checks

### Task 6: UI surfacing
Files:
- action modals / patching UI JS/templates

Add:
- preflight preview section
- blocked-action detail list
- operator guidance text

Acceptance:
- users see exact reasons like apt lock / insufficient disk / host offline

### Task 7: Audit integration
Files:
- server/app/services/audit.py

Record preflight failures for risky action attempts with reason codes.

Acceptance:
- blocked risky attempts are auditable

### Task 8: Tests
Files:
- add backend tests under server/tests/

Minimum cases:
- all checks pass
- one check fails and blocks
- multiple checks fail and all are returned
- preview mode vs enforce mode
- blocked actions do not create jobs

Acceptance:
- suite covers result shape and no-side-effect behavior

---

## Plan 3 — Health-gated patch and reboot orchestration

Goal
Make patching and reboot workflows fleet-safe by validating host health before rollout progression.

Architecture
Extend rollout control from time/wave management into health-aware orchestration. Reuse patch campaign state, but add explicit health gates, reboot state, and post-action verification.

Primary files likely involved
- server/app/services/patching.py
- server/app/routers/patching.py
- server/app/models.py
- server/app/schemas.py
- server/app/services/host_job_dispatch.py
- agent-side support for health/validation checks if needed
- server/tests/

Suggested implementation tasks

### Task 1: Extend rollout metadata/state model
Files:
- server/app/models.py
- migration under server/alembic/versions/

Add state for:
- health_gate_status per wave
- reboot_required / reboot_attempted / reboot_verified
- pause reason codes
- last health check result summary

Acceptance:
- rollout metadata can persist health-gate decisions and reboot outcomes cleanly

### Task 2: Define health gate checks
Files:
- add or modify: server/app/services/patching.py
- possibly add: server/app/services/health_checks.py

Initial health checks should be simple and pragmatic:
- host came back online after reboot
- service query reachable
- package/update state consistent
- optional metrics sanity (not under severe resource failure)

Acceptance:
- health gate result is explicit pass/fail with reasons

### Task 3: Add post-patch and post-reboot validation flow
Files:
- server/app/services/patching.py
- maybe use host_job_dispatch helpers

Flow:
- patch wave executes
- evaluate hosts
- if configured, reboot hosts that need it
- wait for hosts to return
- run health checks
- only then allow next wave

Acceptance:
- failed post-reboot validation marks host failure and affects rollout gate

### Task 4: Add automatic pause behavior
Files:
- server/app/services/patching.py

Pause conditions:
- health check failure threshold crossed
- reboot recovery timeout threshold crossed
- canary wave failure above configured ratio

Acceptance:
- rollout enters paused state automatically with clear reason metadata

### Task 5: Add API/UI visibility
Files:
- server/app/routers/patching.py
- patching UI files

Add visibility for:
- gate pass/fail state
- reboot state per host
- paused reason
- whether next wave is blocked by health

Acceptance:
- operator can explain exactly why rollout advanced or paused

### Task 6: Reuse preflight and maintenance logic where relevant
Files:
- integrate with future Issue 1 and 2 work

Use preflight before starting campaign and health gates after execution.

Acceptance:
- rollout lifecycle is coherent across before-run and after-run validation

### Task 7: Tests
Files:
- extend patching rollout test coverage

Minimum cases:
- canary passes -> next wave can proceed
- canary fails -> rollout pauses
- reboot required host fails to recover -> host failure recorded
- automatic pause reason returned in API
- approve-next blocked if health gate is not satisfied

Acceptance:
- patch rollout tests cover gate, reboot, and failure transitions

---

## Suggested execution order across the top 3 plans

Recommended order:
1. Per-group maintenance windows
2. Job preflight checks
3. Health-gated patch and reboot orchestration

Reason:
- maintenance windows and preflight checks define safe conditions before execution
- health-gated orchestration extends that safety model after execution

---

## Delivery note

These plans are detailed enough to turn into implementation tickets or subagent execution plans. If desired, the next step should be breaking each top-3 plan into smaller engineering tasks/PR-sized milestones.
