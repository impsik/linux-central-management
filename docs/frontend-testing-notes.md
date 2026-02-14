# Frontend testing notes (Phase 3 host filters cleanup)

- There is no dedicated browser/frontend unit-test harness (e.g. Vitest/Jest + jsdom) in this repo right now.
- To keep cleanup safe, we added a lightweight pytest smoke check at:
  - `server/tests/test_phase3_host_filters_frontend_smoke.py`
- Scope of the smoke check:
  - Verifies split scripts are wired in `index.html`
  - Verifies host-filter orchestrator references both new modules
  - Verifies key CVE/upgrade status strings remain present after extraction

## Remaining gap

- No DOM-behavioral assertions yet (click/input event simulation in-browser).
- Recommended follow-up: add a small frontend harness (Vitest + jsdom) to assert event wiring and state transitions directly.
