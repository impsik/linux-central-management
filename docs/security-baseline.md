# Security baseline (Step 1)

This project started as a LAN MVP. This document describes the **minimum security controls** to move toward a production-ready deployment.

## Assumptions
- UI users are humans (operators/admins).
- Agents run on managed hosts and communicate to the server with a shared agent token.
- Exposing the UI beyond a trusted LAN significantly increases risk.

## 1) Transport security
- Run the UI behind **HTTPS only**.
- Set `UI_COOKIE_SECURE=true` (otherwise session cookies can be sent over HTTP).
- Recommended: reverse proxy (Caddy/Nginx/Traefik) that terminates TLS and forwards to `server:8000`.

### Caddy example
See:
- `deploy/docker/Caddyfile.example`
- `deploy/docker/caddy-compose.example.yml`

## 2) Authentication hardening
- MFA (TOTP) is required for `admin` and `operator` by default.
- Set `MFA_ENCRYPTION_KEY` (Fernet key) via environment (do not commit it).
- Consider shortening `UI_SESSION_DAYS` in production.

## 3) Authorization / RBAC
- Keep RBAC (admin/operator/readonly). MFA reduces takeover risk but does not replace least privilege.
- High-risk features:
  - Terminal access
  - Package removals
  - SSH key approvals
  - App user lifecycle (create/reset/deactivate)

## 4) Database schema management
- For production deployments:
  - set `DB_AUTO_CREATE_TABLES=false`
  - keep `DB_REQUIRE_MIGRATIONS_UP_TO_DATE=true`
  - apply migrations during deploy:

```bash
cd deploy/docker
docker compose up -d --build
docker compose exec server alembic upgrade head
```

## 5) Secrets management
Do not commit secrets. Prefer:
- Docker secrets, or
- a host-level secret manager, or
- an out-of-repo `.env` with strict file permissions.

Secrets to protect:
- `BOOTSTRAP_PASSWORD`
- `AGENT_SHARED_TOKEN`
- `AGENT_TERMINAL_TOKEN`
- `MFA_ENCRYPTION_KEY`

## 6) Auditability
- Audit logging is enabled for auth, MFA, user lifecycle, and package actions.
- Admin UI contains an audit viewer.

## 7) Network controls (recommended)
- Restrict UI access to VPN/LAN.
- Restrict agent-to-server access to expected networks.
- Consider firewall rules and rate limiting at the proxy.
