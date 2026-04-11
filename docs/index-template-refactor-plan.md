# Main UI Template Refactor Plan

> For Hermes: use this plan as the execution baseline. Keep the app deployable after every phase. Do not combine multiple risky index.html edits into one change.

Goal: turn server/app/templates/index.html from a fragile application blob into a stable shell, with behavior moved into smaller JS modules and markup split into safer partials/components over time.

Architecture: keep the current server-rendered FastAPI app, but treat index.html as a shell instead of a logic container. Extract boot-critical logic into dedicated assets, define stable context contracts, and add smoke-level regression coverage for the UI boot path before making further large changes.

Tech stack: FastAPI, Starlette templates/static responses, vanilla JS modules under server/app/templates/, Vitest frontend tests under server/tests/frontend, pytest backend tests.

---

## Current problems to solve

Observed repo-specific issues:
- server/app/templates/index.html is extremely large and contains a massive inline script.
- multiple recent regressions came from small index.html edits truncating or corrupting the file tail.
- one broken inline block kills the whole app boot path: menus stop opening, tabs stay Loading…, and unrelated features break.
- module contexts are inconsistent; some modules assume methods exist that are not always injected.
- behavior is split awkwardly: some code is modularized, but the boot chain and major rendering logic are still welded into index.html.
- there is no browser smoke suite guarding the actual rendered UI boot path.

Repo facts discovered during work:
- current modular JS already lives under server/app/templates/fleet-phase3-*.js.
- frontend tests currently use Vitest and are fast and useful, but they do not replace browser-level boot smoke tests.
- owner-scope and admin-user enhancements proved that changing small asset modules is much safer than editing index.html.
- restoring server/app/templates/index.html from commit 88a9072 repeatedly fixed broken UI boot, which means index.html must be treated as a critical artifact.

---

## Refactor principles

1. Index.html is a shell, not the app.
2. No large direct index.html rewrites.
3. Every phase must leave the app deployable.
4. Move behavior before moving markup, unless markup extraction is tiny and reversible.
5. Add smoke tests before major decomposition.
6. Modules must tolerate missing optional context methods gracefully.
7. Prefer new small files over giant edits to old ones.

---

## Phase 0: Stabilization guardrails

Objective: freeze the current working UI baseline and make future regressions easier to catch.

Files:
- Modify: server/app/templates/index.html
- Modify: server/app/templates/fleet-phase3.js
- Create: docs/ui-refactor-checklist.md
- Create: server/tests/frontend/index-shell-integrity.test.js

### Task 0.1: Add an index-shell integrity frontend test

Objective: catch truncated or malformed main template before deploy.

Files:
- Create: server/tests/frontend/index-shell-integrity.test.js

Step 1: Write a failing test that checks for required shell markers

Code:
```js
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('index shell integrity', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const src = fs.readFileSync(path.join(root, 'server/app/templates/index.html'), 'utf8');

  it('ends with the expected closing tags', () => {
    expect(src.trim().endsWith('</html>')).toBe(true);
    expect(src.includes('</body>')).toBe(true);
  });

  it('contains boot-critical markers', () => {
    expect(src).toContain('id="settings-btn"');
    expect(src).toContain('id="nav-overview"');
    expect(src).toContain('safeInit(');
  });
});
```

Step 2: Run test

Run:
```bash
npm run test:frontend
```

Expected: PASS after adding the file.

Step 3: Commit

```bash
git add server/tests/frontend/index-shell-integrity.test.js
git commit -m "test: add main template integrity guard"
```

### Task 0.2: Add a UI refactor safety checklist doc

Objective: define mandatory checks before merging changes touching index.html.

Files:
- Create: docs/ui-refactor-checklist.md

Include:
- run npm run test:frontend
- verify tail of server/app/templates/index.html
- verify menus open after local reload
- verify login/dashboard/hosts/admin tabs load
- avoid unrelated edits in same commit

Step 2: Commit

```bash
git add docs/ui-refactor-checklist.md
git commit -m "docs: add UI refactor safety checklist"
```

### Task 0.3: Add a global safe formatter helper module

Objective: stop repeating context-assumption fixes like ctx.formatShortTime issues.

Files:
- Create: server/app/templates/fleet-phase3-shared.js
- Modify: server/app/templates/index.html
- Modify: server/app/templates/fleet-phase3-overview.js
- Modify: server/app/templates/fleet-phase3-host-list.js

Implementation idea:
- export helpers like safeFormatShortTime(ctx, value)
- export safeOptionalCall(ctx, method, fallback)
- update modules to use these instead of raw ctx.method assumptions

Verification:
- npm run test:frontend
- targeted manual boot check after rebuild

---

## Phase 1: Extract remaining inline boot logic from index.html

Objective: move boot-critical JS out of the huge inline script while preserving behavior.

Target outcome:
- index.html includes only script tags plus minimal shell config
- no large logic functions remain inline

Files likely involved:
- Modify: server/app/templates/index.html
- Create: server/app/templates/fleet-phase3-app-shell.js
- Create: server/app/templates/fleet-phase3-admin-users.js
- Create: server/app/templates/fleet-phase3-settings-menu.js
- Create: server/app/templates/fleet-phase3-host-details.js

### Task 1.1: Extract settings menu logic

Objective: move menu open/close/admin/logout/change-password wiring out of the main template.

Files:
- Create: server/app/templates/fleet-phase3-settings-menu.js
- Modify: server/app/templates/index.html
- Modify: server/app/templates/fleet-phase3-auth-ui.js (if shared helpers stay there temporarily)

Move:
- settings dropdown open/close
- admin menu button behavior
- logout button behavior
- change-password behavior

Verification:
- settings gear opens
- Admin click works
- Logout works
- Change password works

### Task 1.2: Extract admin users table rendering/actions

Objective: stop embedding user-management rendering inside index.html.

Files:
- Create: server/app/templates/fleet-phase3-admin-users.js
- Modify: server/app/templates/index.html
- Modify: server/app/templates/fleet-phase3-owner-scope-ui.js

Move from inline script:
- loadAdminUsers()
- activate/deactivate wiring
- reset MFA wiring
- remove-user wiring
- row rendering

Note:
- keep owner-scope enhancer as an add-on, but make it depend on a stable admin-users module, not raw DOM accidents.

### Task 1.3: Extract host metadata post-save refresh logic

Objective: move metadata refresh logic out of index.html and into host-details/host-actions modules.

Files:
- Create: server/app/templates/fleet-phase3-host-details.js
- Modify: server/app/templates/fleet-phase3-host-actions.js
- Modify: server/app/templates/index.html

Move:
- onMetadataSaved reconciliation into allHosts/current host labels/header
- label refresh logic
- host detail label badge rendering helpers

### Task 1.4: Create a dedicated app-shell initializer

Objective: replace scattered safeInit calls with a single explicit boot module.

Files:
- Create: server/app/templates/fleet-phase3-app-shell.js
- Modify: server/app/templates/index.html

Responsibilities:
- define ordered boot sequence
- call modules with explicit contexts
- log module-specific init failures without killing entire app

Pseudo-shape:
```js
bootModule('auth-state', () => authState.init(...));
bootModule('settings-menu', () => settingsMenu.init(...));
bootModule('host-filters', () => hostFilters.init(...));
bootModule('overview', () => overview.init(...));
```

---

## Phase 2: Split HTML into partials/templates

Objective: reduce the blast radius of markup edits.

Target outcome:
- index.html becomes a composition root
- major sections live in partial files

Files:
- Create: server/app/templates/partials/header.html
- Create: server/app/templates/partials/navigation.html
- Create: server/app/templates/partials/host-details.html
- Create: server/app/templates/partials/host-inventory.html
- Create: server/app/templates/partials/admin-panel.html
- Create: server/app/templates/partials/reports-panel.html
- Create: server/app/templates/partials/modals.html
- Modify: server/app/routers/ui.py
- Modify: server/app/templates/index.html

Two implementation options:

Option A: Jinja/Starlette includes if template rendering supports it cleanly.
Option B: build-time or server-side string composition in ui.py if current rendering path is too custom.

Recommended for this repo:
- use proper template partial includes if feasible.
- if the custom nonce replacement path complicates it, first move to a more normal TemplateResponse path with nonce/context variables.

### Task 2.1: Extract header/settings dropdown markup
### Task 2.2: Extract host inventory block
### Task 2.3: Extract admin panel block
### Task 2.4: Extract modal markup block
### Task 2.5: Keep final index.html under ~400 lines if possible

Verification after each extraction:
- frontend tests pass
- visual smoke: header, hosts, admin, reports still render

---

## Phase 3: Normalize context/state contracts

Objective: eliminate context drift like getLabelOwnerFilter missing or formatShortTime missing.

Files:
- Create: server/app/templates/fleet-phase3-contexts.js
- Modify: server/app/templates/fleet-phase3.js
- Modify: server/app/templates/fleet-phase3-overview.js
- Modify: server/app/templates/fleet-phase3-host-list.js
- Modify: server/app/templates/fleet-phase3-host-actions.js
- Modify: server/app/templates/fleet-phase3-host-filters-ui.js

### Task 3.1: Define stable context factories

Create explicit builders:
- createHostListCtx(...)
- createOverviewCtx(...)
- createAdminCtx(...)
- createAuthCtx(...)

Each documents required and optional methods.

### Task 3.2: Replace ad hoc object literals in index.html

Instead of:
```js
return { getLabelEnvFilter: ..., getLabelRoleFilter: ... }
```

Use:
```js
return createHostListCtx(state, deps)
```

### Task 3.3: Add defensive helpers for optional methods

Examples:
- optional formatter
- optional filter getter
- optional load method

### Task 3.4: Add contract-focused frontend tests

Add tests that assert modules still behave when optional ctx methods are absent.

---

## Phase 4: Browser smoke coverage

Objective: catch full-page boot failures before deploy.

Files:
- Create: e2e/playwright.config.js or e2e/playwright.config.ts
- Create: e2e/smoke.spec.js
- Update: README.md or docs/frontend-testing-notes.md

Suggested smoke tests:
1. Login page loads
2. Login succeeds
3. Settings menu opens
4. Dashboard renders without permanent Loading…
5. Hosts tab opens
6. Admin tab opens (for admin)
7. Host metadata save works
8. Regular user only sees owned hosts

Suggested commands:
```bash
npm install -D playwright
npx playwright install --with-deps
npx playwright test
```

Because this repo repeatedly suffered from boot regressions, this phase is not optional long-term.

---

## Phase 5: Backend/UI architecture cleanup for user management

Objective: isolate admin user management as a proper module and reduce fragile coupling.

Files:
- Create: server/app/templates/fleet-phase3-admin-users.js
- Create: server/tests/frontend/admin-users-ui.test.js
- Modify: server/app/routers/auth.py

Potential improvements:
- rename /users/{username}/delete to /users/{username}/deactivate for clarity
- keep /users/{username}/remove as real hard delete
- ensure role vocabulary is consistent everywhere:
  - admin
  - operator
  - readonly
- display “Regular” in UI, map to readonly internally

---

## Recommended implementation order for this repo

Do not execute this out of order.

1. Phase 0.1 index-shell integrity test
2. Phase 0.2 UI refactor checklist doc
3. Phase 1.1 settings menu extraction
4. Phase 1.2 admin users extraction
5. Phase 1.4 app-shell initializer
6. Phase 2 partial extraction (header, inventory, admin, modals)
7. Phase 3 context normalization
8. Phase 4 Playwright smoke tests
9. Phase 5 cleanup/polish

This order is chosen to reduce risk while addressing the repeated break points first.

---

## Concrete anti-regression rules

Before every commit touching server/app/templates/index.html:
- run `npm run test:frontend`
- check `tail -n 20 server/app/templates/index.html`
- verify file ends with `</script>`, `</body>`, `</html>`
- do not mix unrelated feature work into the same commit

Before every PR touching UI boot code:
- verify login
- verify settings menu opens
- verify Hosts tab renders
- verify Admin tab renders

---

## Commands to use during refactor

Frontend tests:
```bash
npm run test:frontend
```

Focused backend tests:
```bash
cd server
./.venv/bin/pytest -q tests/test_auth_user_management.py tests/test_owner_scope_visibility.py tests/test_reports_owner_visibility.py tests/test_host_metadata_update_api.py
```

Template tail check:
```bash
tail -n 20 server/app/templates/index.html
```

Search remaining inline-heavy functions in index.html:
```bash
rg "function .*\(" server/app/templates/index.html
```

---

## Definition of done

This refactor is done when:
- index.html is mostly shell markup and script includes
- no large application logic remains inline
- admin users/settings menu/host metadata boot do not live in index.html
- module contexts are stable and documented
- browser smoke tests catch boot regressions
- editing one area no longer breaks the whole UI

---

## Short executive summary

Enterprise-wise for this repo:
- stop editing giant inline-script index.html for behavior
- move behavior to dedicated modules
- split shell markup into partials
- standardize context contracts
- add browser smoke tests

If we follow this plan, the app becomes less “one file can brick everything” and more “one module can fail without killing the whole product.”
