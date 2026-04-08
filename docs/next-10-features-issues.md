# Next 10 Features — GitHub-Style Issue Drafts

These issue drafts translate `docs/next-10-features-roadmap.md` into implementation-ready GitHub-style tickets.

Sizing guide used here:
- S = small, low-risk change
- M = moderate feature or contained multi-file change
- L = cross-cutting feature with backend + UI + tests
- XL = major feature spanning multiple subsystems / rollout phases

Suggested milestone mapping:
- Milestone A — Safety Core
- Milestone B — Targeting and Fleet Control
- Milestone C — Governance and Operational Leverage

---

## Issue 1 — Per-group maintenance windows

Title:
feat(policy): support maintenance windows scoped by host groups and labels

Labels
- feature
- backend
- frontend
- policy
- operations

Size
- L

Suggested milestone
- Milestone A — Safety Core

Dependencies
- none required
- should align with existing saved views / targeting model

Problem
Current maintenance window behavior is too coarse for real fleets. Production, staging, edge, and lab hosts need different execution windows and timezones.

Goal
Allow risky actions to be evaluated against maintenance windows scoped by labels or saved host groups instead of only a single global policy.

Scope
- maintenance windows scoped by labels and/or saved groups
- timezone-aware evaluation
- reason codes for blocked execution
- UI preview of whether a target set is currently inside or outside its allowed window

Out of scope
- full recurring calendar exceptions UI
- holiday calendars

Acceptance criteria
- a risky action against `env=prod` can be blocked while the same action against `env=stage` is allowed
- API returns machine-readable block reason like `maintenance_window_blocked`
- UI shows human-readable explanation for blocked action
- behavior is covered by tests for timezone and boundary conditions

Suggested implementation notes
- add maintenance window targeting model
- evaluate during risky job and campaign creation
- reuse existing label/group targeting concepts where possible

---

## Issue 2 — Job preflight checks

Title:
feat(jobs): add preflight checks for risky Linux administration actions

Labels
- feature
- backend
- policy
- safety
- operations

Size
- L

Suggested milestone
- Milestone A — Safety Core

Dependencies
- Issue 1 recommended, but not strictly required

Problem
Risky jobs should fail before dispatch if the host is in a clearly unsafe or invalid state.

Goal
Add a reusable preflight layer for patch, reboot, and high-risk maintenance actions.

Scope
- apt/dpkg lock detection
- package DB health validation
- disk-space threshold checks
- reboot-required detection
- host online/heartbeat validation
- preflight dry-run API response

Out of scope
- full compliance engine
- package-manager support beyond current Linux target scope

Acceptance criteria
- risky actions can return `blocked_by_preflight` with structured failed checks
- users can run preflight without dispatching the job
- UI presents exact failed checks and suggested operator action
- tests cover pass/fail and mixed-check scenarios

Suggested implementation notes
- keep preflight results structured and reusable by UI, approval flow, and API clients
- avoid mixing preflight failure with generic job failure states

---

## Issue 3 — Health-gated patch and reboot orchestration

Title:
feat(patching): add health-gated patch and reboot orchestration

Labels
- feature
- backend
- frontend
- patching
- operations
- safety

Size
- XL

Suggested milestone
- Milestone A — Safety Core

Dependencies
- strongly depends on Issue 2
- benefits from Issue 1

Problem
Patching is not safe enough if the platform only knows whether package installation ran. The control plane should verify health before progressing a rollout.

Goal
Add post-action validation and rollout gates for patch and reboot workflows.

Scope
- patch canary wave
- host health check before next wave
- optional reboot orchestration after patching
- post-reboot validation
- automatic pause on failure threshold
- rollout state visible in UI/API

Out of scope
- application-specific drains for every workload type
- Kubernetes-style orchestration

Acceptance criteria
- rollout pauses automatically if health checks fail above threshold
- reboot flow can mark host as failed if post-reboot validation does not recover in time
- next wave only starts after canary health gate passes
- API and UI expose why rollout paused

Suggested implementation notes
- keep health checks extensible but start with simple host-level checks
- persist health-gate decisions in rollout metadata

---

## Issue 4 — Dynamic host groups

Title:
feat(targeting): add dynamic host groups based on labels and fleet state

Labels
- feature
- backend
- frontend
- targeting
- operations

Size
- L

Suggested milestone
- Milestone B — Targeting and Fleet Control

Dependencies
- none required
- should integrate with existing saved views

Problem
Manual target selection does not scale. Operators need reusable dynamic cohorts based on live fleet state.

Goal
Introduce smart groups for targeting, filtering, and automation.

Scope
- groups based on labels
- groups based on OS version / reboot-required / updates pending / online state
- save and reuse smart groups
- target preview showing exact matched hosts before execution

Out of scope
- arbitrary SQL-like query language for end users

Acceptance criteria
- users can save a dynamic group like `env=prod AND reboot_required=true`
- API returns exact matched hosts for preview
- groups can be reused by jobs, campaigns, and notifications
- tests cover target resolution and edge conditions

Suggested implementation notes
- build on existing saved views and selectors instead of inventing a second targeting model

---

## Issue 5 — Agent version management

Title:
feat(agent): add agent version visibility and rolling upgrade support

Labels
- feature
- backend
- frontend
- agent
- fleet-management

Size
- L

Suggested milestone
- Milestone B — Targeting and Fleet Control

Dependencies
- dynamic groups helpful but not required

Problem
Fleet agents will drift over time unless the control plane manages their lifecycle explicitly.

Goal
Make agent version a first-class fleet concept and support controlled upgrades.

Scope
- report agent version per host
- show version drift in UI
- define latest supported version
- support rolling upgrade campaigns for agents
- surface failed agent upgrades and rollback hints

Out of scope
- self-hosted package repository management

Acceptance criteria
- fleet view shows current agent version per host
- admin can filter hosts by stale agent version
- admin can launch a rolling agent upgrade campaign
- upgrade failures are visible and auditable

Suggested implementation notes
- version reporting should be part of heartbeat or agent registration
- do not couple agent upgrade rollout too tightly to package patch rollout logic unless it truly helps

---

## Issue 6 — Compliance checks v1

Title:
feat(compliance): add baseline Linux compliance checks and host scoring

Labels
- feature
- backend
- frontend
- compliance
- security
- operations

Size
- XL

Suggested milestone
- Milestone B — Targeting and Fleet Control

Dependencies
- dynamic groups useful for targeting
- can be launched before full remediation support

Problem
The platform can execute changes, but it still needs a clear way to show whether a host is compliant with baseline administration expectations.

Goal
Add an initial compliance layer for per-host and fleet-level visibility.

Scope
Starter checks:
- SSH root login disabled
- password auth policy status
- firewall enabled
- unattended-upgrades enabled
- auditd active
- time sync active
- required labels present

Out of scope
- full CIS benchmark implementation
- remediation automation in the first issue

Acceptance criteria
- per-host compliance result and score are available
- fleet-level compliance summary is available
- failed checks are filterable/exportable
- compliance checks are auditable and test-covered

Suggested implementation notes
- keep check result format generic enough to support future remediation and trend views

---

## Issue 7 — Drift detection and host diff

Title:
feat(drift): add host-to-host and host-to-baseline drift views

Labels
- feature
- backend
- frontend
- drift
- troubleshooting
- operations

Size
- L

Suggested milestone
- Milestone C — Governance and Operational Leverage

Dependencies
- Issue 6 recommended
- observability and inventory APIs already provide much of the source data

Problem
Operators frequently need to answer “what changed?” and “why is this host different?” quickly.

Goal
Add a practical drift and comparison workflow.

Scope
- compare host vs host
- compare host vs baseline/expected state
- package, service, user, label, sudo/access, update backlog diffs
- UI presentation optimized for operator troubleshooting

Out of scope
- full CMDB or inventory normalization layer

Acceptance criteria
- operator can compare two hosts and see meaningful differences in one view
- drift result can be filtered by domain (packages/services/users/labels)
- diffs are available via API as structured JSON
- tests cover core diff logic and missing-data scenarios

Suggested implementation notes
- prefer normalized comparison output over display-only strings

---

## Issue 8 — Notification and webhook rules

Title:
feat(notifications): add rule-based fleet alerts and outbound webhooks

Labels
- feature
- backend
- frontend
- notifications
- integrations
- operations

Size
- L

Suggested milestone
- Milestone C — Governance and Operational Leverage

Dependencies
- dynamic groups useful for routing/targeting
- existing notification center provides a base event stream

Problem
Important platform events should reach operators without requiring constant dashboard monitoring.

Goal
Support configurable notification rules and webhook delivery.

Scope
- event rules for approval requests, rollout pauses, host offline, job failure spikes, compliance regressions, backup failures/staleness
- Teams / Slack / email / generic webhook support
- rule-level dedupe and cooldown
- delivery audit trail

Out of scope
- full paging/on-call platform replacement

Acceptance criteria
- admin can create a rule tied to an event kind and target channel
- duplicate alert spam is suppressed with configurable cooldown
- delivery failures are observable
- tests cover rule matching and delivery dedupe behavior

Suggested implementation notes
- use a common notification event model so the rule engine stays simple

---

## Issue 9 — Safe access governance

Title:
feat(access): add temporary access grants with expiry and audited revocation

Labels
- feature
- backend
- frontend
- security
- access-control
- operations

Size
- XL

Suggested milestone
- Milestone C — Governance and Operational Leverage

Dependencies
- approval flow foundations already exist
- can benefit from Issue 1 for time-bound execution windows

Problem
Linux central administration software should handle privileged access workflows safely, not just package and service operations.

Goal
Add temporary access governance for SSH and sudo elevation.

Scope
- temporary sudo grants with expiry
- temporary SSH key deployments with expiry
- approval-linked access windows
- automatic revoke on expiry
- full audit trail

Out of scope
- PAM/IdP deep integration for every external system in first pass

Acceptance criteria
- admin can grant temporary access with an expiry time
- access is automatically revoked when expired
- grant/revoke actions are visible in audit timeline
- UI/API clearly show active temporary access grants

Suggested implementation notes
- build on existing SSH key and sudo-mode concepts where possible

---

## Issue 10 — Runbook library / approved automation catalog

Title:
feat(runbooks): add reusable approved runbooks for common Linux operations

Labels
- feature
- backend
- frontend
- automation
- operations
- governance

Size
- XL

Suggested milestone
- Milestone C — Governance and Operational Leverage

Dependencies
- dynamic groups strongly recommended
- approval model useful for protected runbooks

Problem
Operators need reusable automation that is safer than ad hoc custom commands.

Goal
Create a runbook library for approved, parameterized operational actions.

Scope
- named runbooks with parameters
- target restrictions
- optional approval requirements
- reusable UI/API execution path
- audit trail for all executions

Example runbooks
- clear apt locks safely
- refresh package cache
- restart nginx safely
- collect diagnostics bundle
- rotate logs
- rotate SSH host keys

Out of scope
- arbitrary script marketplace
- user-uploaded untrusted code execution in first pass

Acceptance criteria
- admin can define an approved runbook with parameters
- operator can execute allowed runbook against selected targets
- runbook execution is auditable with parameters and target set
- tests cover validation, approval requirements, and execution path

Suggested implementation notes
- use strict parameter schemas instead of raw free-form text where possible

---

## Recommended rollout order

Suggested implementation sequence:
1. Per-group maintenance windows
2. Job preflight checks
3. Health-gated patch and reboot orchestration
4. Dynamic host groups
5. Agent version management
6. Compliance checks v1
7. Drift detection and host diff
8. Notification and webhook rules
9. Safe access governance
10. Runbook library

---

## Backlog hygiene suggestions

When creating real GitHub issues from these drafts, also add:
- milestone
- owner
- dependency links
- risk flag for changes that can affect live fleet actions
- rollout plan / feature flag note for high-risk features
