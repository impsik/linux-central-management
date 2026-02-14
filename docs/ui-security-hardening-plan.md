# UI + Security Hardening Plan

## Goal
Improve production readiness with a staged plan that prioritizes high-impact, low-risk hardening first.

## Phase 1 — Quick wins (this PR)

### Security
1. **Do not publish Postgres by default**
   - Keep DB internal to the docker-compose network.
   - If local debug access is needed, expose `127.0.0.1:5432:5432` via compose override only.

2. **Harden SSH host trust defaults for Ansible**
   - Enable host key checking.
   - Replace `StrictHostKeyChecking=no` + `/dev/null` known_hosts with:
     - `StrictHostKeyChecking=accept-new`
     - `UserKnownHostsFile=/tmp/ansible_known_hosts`

### Outcome
- Reduced accidental DB exposure.
- Better MITM resistance for SSH/Ansible with non-interactive behavior preserved.

## Phase 2 — Medium effort

### Security
1. Add/validate security headers in reverse proxy setup (CSP baseline, frame-ancestors, referrer-policy, x-content-type-options).
2. Enforce secure cookie defaults in production (`UI_COOKIE_SECURE=true`, SameSite policy review).
3. Verify terminal websocket deployment over TLS (`wss`) with explicit production docs.

### UI/UX
1. Improve discoverability of sortable table columns (cursor + hover + sort indicators).
2. Standardize loading/empty/error states for long-running actions.
3. Improve button state consistency (`disabled`, `loading`, `success/error`).

## Phase 3 — Deep refactor

1. Split `server/app/templates/index.html` into modular frontend assets/components.
2. Remove inline JS handlers and large `innerHTML` template blocks where feasible.
3. Move to strict CSP with nonce/hash strategy after JS externalization.
4. Introduce a stricter SSH trust model (managed known_hosts or SSH CA) for production fleets.

## Validation checklist per phase
- Run integration smoke checks (`/health`, auth/login flow, host list, jobs, reports).
- Verify Ansible connectivity in a known environment.
- Confirm terminal and background jobs still function.
- Update README/deploy docs with behavior changes.
