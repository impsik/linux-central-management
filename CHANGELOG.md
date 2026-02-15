# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

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
