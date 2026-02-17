# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- Phase 1 groundwork for scoped RBAC by host labels:
  - new `app_user_scopes` table (Alembic migration `20260217_00`)
  - scope utility service (`services/user_scopes.py`) for selector evaluation and target filtering
  - admin APIs to get/set per-user label selectors:
    - `GET /auth/admin/users/{username}/scopes`
    - `POST /auth/admin/users/{username}/scopes`
  - `/auth/me` now returns scope metadata (`scope.limited`, `scope.selectors`)

### Changed
- Target resolution now supports user-aware filtering (`resolve_agent_ids(..., user=...)`).
- Scoped filtering is enforced for job creation (`/jobs/*`), patch campaign target selection, cron target selection, SSH key deployment requests, and terminal websocket host access.
- Read-path scope filtering now applies to host listing (`/hosts`), search endpoints (`/search/packages`, `/search/cve`), and dashboard attention/notifications host visibility.
- Admin Users UI now supports editing per-user label scope selectors inline (JSON array) and saving via the new auth scope endpoints.
- MFA verify modal now includes an explicit **Log out** action for recovery when the user cannot provide MFA code.
- CSRF middleware now allows `/auth/logout` without CSRF token to avoid MFA lock-in/logout dead-ends.
- Added admin MFA recovery path:
  - `POST /auth/mfa/admin/reset` now revokes all user sessions and clears MFA enrollment/secrets/recovery codes
  - accepts optional reset reason (stored in audit metadata)
  - blocks self-reset via admin endpoint (safer control)
  - Admin Users UI now includes **Reset MFA** action per user
- Interactive package actions no longer collect credentials in browser prompts.
- Interactive workflow is now two-step: first click opens terminal for manual login; second click sends the package command.

## [2026-02-15]

### Added
- MFA verify UX improvements:
  - Enter key submit in MFA verification modal
  - robust modal-level Enter handling
  - input auto-focus
- Optional startup session revocation:
  - `UI_REVOKE_ALL_SESSIONS_ON_STARTUP`
- UI cache-busting for local JS/CSS assets via template-injected asset version token.
- Login page `Cache-Control: no-store`.
- Hosts sidebar consistency improvements for fallback rendering.
- Saved Views for host filters:
  - server-side persistence via `/auth/views`
  - shared/team views
  - default startup view
  - URL deep links (`?view=<name>`)
- Morning Brief card with quick drill-down actions.
- Cron prefill from current visible filter/view.
- Run-now/runbook quick actions from filter context.
- In-app Notification Center:
  - unread badge
  - mark all read
  - per-alert open actions
  - snooze 1h/8h/24h
  - unsnooze-all
  - snooze remaining summary
- Microsoft Teams webhook integration:
  - config/env wiring (`TEAMS_WEBHOOK_URL`, `TEAMS_ALERTS_ENABLED`)
  - test and morning-brief endpoints
  - UI buttons to send test/brief
- Reliability smoke tests:
  - dashboard summary
  - notifications feed
  - failed-runs feed
  - cron create/list
  - MFA transient 403 suppression smoke check
  - maintenance-window guardrail enforcement tests
- Maintenance window guardrails for risky actions:
  - configurable window (timezone + start/end)
  - guarded actions list (CSV)
  - enforcement for `dist-upgrade` and `security-campaign`
  - dashboard endpoint: `/dashboard/maintenance-window`
- Two-person approval workflow for high-risk actions:
  - optional enable via env
  - approval-required responses for guarded actions
  - pending/admin approval/rejection endpoints (`/approvals/*`)
  - execution on admin approve (dist-upgrade job or security campaign)
  - frontend toasts updated to show approval-required request IDs
  - requester self-approve/self-reject blocked (true two-person rule)
  - audit events added for request created/approved/rejected/executed/failed
  - admin queue UX improvements: pending/recent toggle, sorting, copy request id, richer row status
  - approval/rejection API responses now include execution summaries (message, target count, refs)
  - added idempotency tests for double-approve, approve-then-reject, and reject-then-approve behavior
- Notification center backend dedupe/cooldown:
  - optional server-side suppression window (configurable seconds)
  - persisted dedupe state in DB (`notification_dedupe_state`)
  - notifications endpoint now returns `suppressed` and `dedupe` metadata
  - new admin observability endpoint: `/dashboard/notifications/dedupe-state`
  - admin UI card for dedupe state (filters + reload)

### Changed
- Overview card layout now uses balanced responsive breakpoints (3/2/1) and better overflow handling.
- Attention table made responsive to avoid bleeding into adjacent cards.
- CI workflow updated:
  - pip cache for backend job
  - fail-fast backend smoke stage before full backend suite
- README refreshed with latest features, Teams setup, API additions, and CI notes.

### Fixed
- Transient 403 error flashes during MFA-gated initial load are suppressed.
- Label filter options are rebuilt when hosts cache is hydrated from reports.
- Failed runs table now loads on initial Overview render.
- Logout now sends CSRF header.
