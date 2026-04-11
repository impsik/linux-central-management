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
  - Covers boot-critical UI smoke flows:
    - login page renders
    - authenticated login flow (when credentials are provided)
    - settings menu opens
    - Hosts tab opens
    - Dashboard tab reopens without permanent `Loading…`
    - Admin tab opens from the settings menu

- CI wiring:
  - `.github/workflows/ci.yml` currently runs `npm run test:frontend` on push/PR.
  - Playwright smoke coverage is now available in-repo, but still needs CI wiring and credentials if we want it enforced there.

## Running Playwright smoke locally

1. Install browsers once:

```bash
npx playwright install --with-deps chromium
```

2. Start the app yourself.

Example if you already use Docker Compose:

```bash
docker compose up -d --build --force-recreate server
```

3. Run the smoke suite against the running app:

```bash
PLAYWRIGHT_BASE_URL=http://127.0.0.1:8080 \
PLAYWRIGHT_USERNAME=admin \
PLAYWRIGHT_PASSWORD='your-password' \
npm run test:e2e:smoke
```

Useful variants:

```bash
npm run test:e2e:smoke:list
PLAYWRIGHT_BASE_URL=http://127.0.0.1:8080 npm run test:e2e:smoke
```

Notes:
- `PLAYWRIGHT_BASE_URL` defaults to `http://127.0.0.1:8080`
- authenticated smoke checks are skipped unless both `PLAYWRIGHT_USERNAME` and `PLAYWRIGHT_PASSWORD` are set
- the login-page smoke test still runs without credentials

## Remaining gap

What is still missing after this step:
- CI execution of Playwright smoke tests
- stable CI/dev credentials or a dedicated smoke-test user
- optional richer browser assertions for host selection, metadata save, and scoped visibility flows

Recommended next step:
- wire `npm run test:e2e:smoke` into CI with a disposable smoke user and a known app startup path
