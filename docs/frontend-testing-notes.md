# Frontend testing notes

## Current coverage

- **Python smoke checks** (pytest):
  - `server/tests/test_phase3_host_filters_frontend_smoke.py`
  - Verifies split scripts are wired in `index.html`, orchestrator/module references exist, and key CVE/upgrade copy remains present.

- **Frontend unit harness** (Vitest):
  - `npm run test:frontend`
  - Tests under `server/tests/frontend/`
  - Current suites cover:
    - shared Phase 3 state helpers (`createUiStateAccess`, `stopMetricsPollingLifecycle`)
    - host-filter orchestrator module composition/contract
    - host filtering, selection, sorting, pagination and owner visibility
    - package and CVE upgrade controls, rollout controls and load graph tooltips
    - host onboarding, Console input transport and permission visibility
    - user, service, firewall, report and administration module wiring
    - theme tokens, navigation and page layout contracts

- **CI wiring**:
  - `.github/workflows/ci.yml` runs `npm run test:frontend` on push/PR.

## Remaining gap

- Tests use lightweight DOM fixtures, including simulated click/input flows;
  they do not run a real browser layout engine.
- Visual layout and browser integration still need manual or browser-based
  verification when changes affect rendering or interaction.
