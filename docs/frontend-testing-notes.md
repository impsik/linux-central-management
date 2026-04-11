# Frontend testing notes

## Current coverage

- Python smoke checks (pytest):
  - `server/tests/test_phase3_host_filters_frontend_smoke.py`
  - Verifies split scripts are wired in `index.html`, orchestrator/module references exist, and key CVE/upgrade copy remains present.

- Frontend unit harness (Vitest):
  - `npm run test:frontend`
  - Tests under `server/tests/frontend/`
  - Current suites cover:
    - shared Phase 3 state helpers (`createUiStateAccess`, `stopMetricsPollingLifecycle`)
    - host-filter orchestrator module composition/contract
    - host-filter behavioral flows:
      - CVE upgrade status transitions (pre-check → checked/eligible)
      - select-visible-hosts selection propagation
      - label filter clear/reset interactions

- Browser smoke harness (Playwright):
  - `npm run test:e2e:smoke`
  - Spec: `e2e/smoke.spec.js`
  - Config: `playwright.config.js`
  - Covers boot-critical and authenticated UI smoke flows:
    - login page renders
    - authenticated login flow
    - settings menu opens
    - Hosts tab opens
    - Dashboard tab reopens without permanent `Loading…`
    - Admin tab opens from the settings menu
    - admin can save host metadata on a seeded host
    - owner-scoped readonly user only sees their owned seeded host
    - admin can create and remove a user from the admin panel
    - owner-scoped user can request SSH key deploy and admin can review/reject it
    - admin can create and cancel a one-time cronjob for a seeded host
    - admin can filter hosts by owner in the hosts view
    - admin can assign owner scope and scoped user visibility follows it
    - user can change their own password from the settings menu
    - admin can deactivate and reactivate a user from the admin panel
    - admin can reset another user password from the admin panel
    - reports tab exposes export links and opens the user presence report

- CI wiring:
  - `.github/workflows/ci.yml` runs:
    - `npm run test:frontend`
    - Playwright smoke tests in a dedicated `e2e-smoke` job
    - backend pytest suites
  - The `e2e-smoke` job:
    - seeds deterministic smoke data with `server/scripts/seed_playwright_smoke.py`
    - starts the app with sqlite
    - seeds bootstrap admin password from env
    - disables privileged MFA for CI login
    - runs Playwright against the live app over `http://127.0.0.1:8000`

## Running Playwright smoke locally

1. Install browsers once:

```bash
npx playwright install --with-deps chromium
```

2. Seed local smoke data if you want the richer authenticated scenarios:

```bash
DATABASE_URL='sqlite+pysqlite:///./ci-smoke-local.db' \
DB_AUTO_CREATE_TABLES=true \
DB_REQUIRE_MIGRATIONS_UP_TO_DATE=false \
python3 server/scripts/seed_playwright_smoke.py
```

3. Start the app yourself.

Example:

```bash
DATABASE_URL='sqlite+pysqlite:///./ci-smoke-local.db' \
DB_AUTO_CREATE_TABLES=true \
DB_REQUIRE_MIGRATIONS_UP_TO_DATE=false \
AGENT_SHARED_TOKEN=ci-token \
ALLOW_INSECURE_NO_AGENT_TOKEN=true \
BOOTSTRAP_PASSWORD=ci-admin-password \
MFA_REQUIRE_FOR_PRIVILEGED=false \
UI_COOKIE_SECURE=false \
UI_REVOKE_ALL_SESSIONS_ON_STARTUP=false \
python3 -m uvicorn app.main:app --app-dir server --host 127.0.0.1 --port 8000
```

4. Run the smoke suite against the running app:

```bash
PLAYWRIGHT_BASE_URL=http://127.0.0.1:8000 \
PLAYWRIGHT_USERNAME=admin \
PLAYWRIGHT_PASSWORD='ci-admin-password' \
PLAYWRIGHT_OWNER_USERNAME=owner-viewer \
PLAYWRIGHT_OWNER_PASSWORD='ci-owner-password' \
npm run test:e2e:smoke
```

Useful variants:

```bash
npm run test:e2e:smoke:list
PLAYWRIGHT_BASE_URL=http://127.0.0.1:8000 npm run test:e2e:smoke
```

Notes:
- `PLAYWRIGHT_BASE_URL` defaults to `http://127.0.0.1:8080`
- authenticated smoke checks are skipped unless the relevant credentials are set
- the login-page smoke test still runs without credentials

## CI assumptions for smoke tests

The CI browser smoke job currently assumes:
- `DATABASE_URL=sqlite+pysqlite:///./ci-smoke.db`
- `DB_AUTO_CREATE_TABLES=true`
- `DB_REQUIRE_MIGRATIONS_UP_TO_DATE=false`
- `BOOTSTRAP_PASSWORD=ci-admin-password`
- `PLAYWRIGHT_USERNAME=admin`
- `PLAYWRIGHT_PASSWORD=ci-admin-password`
- `PLAYWRIGHT_OWNER_USERNAME=owner-viewer`
- `PLAYWRIGHT_OWNER_PASSWORD=ci-owner-password`
- `MFA_REQUIRE_FOR_PRIVILEGED=false`
- `UI_COOKIE_SECURE=false`
- `UI_REVOKE_ALL_SESSIONS_ON_STARTUP=false`

That is intentionally CI-only convenience, not a production recommendation.

## Remaining gap

What is still missing after this step:
- artifact/report polish for successful CI smoke runs
- optional dedicated seed/test fixture path instead of relying on bootstrap admin login
- broader browser flows for admin user management and automation/security tabs

Recommended next step:
- expand Playwright into one or two more high-risk authenticated flows:
  - admin user creation/remove path
  - SSH key approval/request flow
