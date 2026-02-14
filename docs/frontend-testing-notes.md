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

## Remaining gap

- Still missing rich DOM-behavior assertions (real click/input flows and rendering behavior under jsdom/browser-like fixtures) for larger modules such as packages, host filters, and overview orchestration.
- Recommended next step: add targeted module-level DOM fixtures for these workflows and run them in CI alongside pytest.
