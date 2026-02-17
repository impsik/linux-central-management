# Week 1 OIDC Ticket Plan

This plan breaks down Week 1 of the enterprise roadmap into shippable implementation tickets.

## Sprint Goal
Enable secure OIDC login in parallel with existing local auth, behind a feature flag.

## Ticket 1 — OIDC Config & Validation

**Title:** Add OIDC settings to server config

**Scope**
- Add settings fields:
  - `auth_oidc_enabled: bool`
  - `auth_oidc_issuer: str | None`
  - `auth_oidc_client_id: str | None`
  - `auth_oidc_client_secret: str | None`
  - `auth_oidc_redirect_uri: str | None`
  - `auth_oidc_scopes: str` (default `openid profile email`)
  - `auth_oidc_allowed_email_domains: str | None`
- Add startup validation when enabled.

**Acceptance**
- App fails fast with clear error when required OIDC config is missing.

---

## Ticket 2 — OIDC Login Endpoint

**Title:** Add `GET /auth/oidc/login`

**Scope**
- Generate signed `state` and `nonce`.
- Store temporary state in HTTP-only cookie.
- Redirect to provider authorize URL.

**Acceptance**
- Endpoint returns redirect to valid IdP authorize URL.
- Missing config -> user-friendly 500/400.

---

## Ticket 3 — OIDC Callback Endpoint

**Title:** Add `GET /auth/oidc/callback`

**Scope**
- Validate `state` cookie + query.
- Exchange code for tokens.
- Validate ID token issuer, audience, signature, nonce, expiry.
- Extract principal claims (`sub`, `email`, `preferred_username`, `groups`).

**Acceptance**
- Valid callback creates app session and redirects to `/`.
- Invalid tokens are rejected with audited reason.

---

## Ticket 4 — User Provisioning & Mapping (minimal)

**Title:** Link/provision local AppUser on OIDC login

**Scope**
- Lookup by `username` (or mapped email local-part strategy).
- Auto-create user when not found and domain allowlist passes.
- Default role: `readonly` for first week (safe default).

**Acceptance**
- First OIDC login creates usable account.
- Domain not allowed -> denied.

---

## Ticket 5 — Session + Logout Wiring

**Title:** Reuse app session model for OIDC users

**Scope**
- Issue `fleet_session` + `fleet_csrf` cookies on OIDC callback.
- Add `POST /auth/oidc/logout` (local session clear, optional IdP end-session redirect).

**Acceptance**
- OIDC users can login/logout same as local users.

---

## Ticket 6 — Login UI Changes

**Title:** Add SSO button in login page

**Scope**
- Add “Sign in with SSO” button when OIDC enabled.
- Keep local username/password visible for now.

**Acceptance**
- Button hidden when OIDC disabled.
- Button redirects to `/auth/oidc/login`.

---

## Ticket 7 — Audit Events

**Title:** Add OIDC auth audit events

**Scope**
- Emit:
  - `auth.login.oidc`
  - `auth.login.oidc.failed`
  - `auth.logout.oidc` (if distinct flow)
- Include safe metadata only (issuer, subject hash, reason code; no tokens).

**Acceptance**
- Audit rows present for success/failure.

---

## Ticket 8 — Tests (critical path)

**Title:** Add OIDC flow test coverage

**Scope**
- Unit tests: state/nonce checks, domain allowlist, token claim validation errors.
- Integration smoke: successful callback creates session.

**Acceptance**
- CI includes OIDC auth tests and passes.

---

## Ticket 9 — Documentation

**Title:** Add OIDC deployment docs

**Scope**
- README section: provider setup, env vars, redirect URI examples.
- Migration guidance: local auth + OIDC coexistence.

**Acceptance**
- Fresh operator can configure OIDC from docs only.

---

## Suggested Delivery Order
1. Ticket 1
2. Ticket 2 + 3
3. Ticket 4 + 5
4. Ticket 6 + 7
5. Ticket 8
6. Ticket 9

## Exit Criteria (Week 1)
- Pilot users can sign in with OIDC in staging.
- Local break-glass admin still works.
- Audit trail captures OIDC auth outcomes.
