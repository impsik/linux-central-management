from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from passlib.context import CryptContext
from sqlalchemy import select

from app.db import Base, SessionLocal, engine
from app.models import AppUser, AppUserScope, Host


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def ensure_user(db, username: str, password: str, role: str) -> AppUser:
    user = db.execute(select(AppUser).where(AppUser.username == username)).scalar_one_or_none()
    if user is None:
        user = AppUser(
            username=username,
            password_hash=pwd_context.hash(password),
            role=role,
            is_active=True,
            mfa_enabled=False,
        )
        db.add(user)
        db.flush()
    else:
        user.password_hash = pwd_context.hash(password)
        user.role = role
        user.is_active = True
        user.mfa_enabled = False
    return user


def ensure_host(db, agent_id: str, hostname: str, owner: str, env: str, role: str, ip_address: str) -> Host:
    host = db.execute(select(Host).where(Host.agent_id == agent_id)).scalar_one_or_none()
    labels = {
        "owner": owner,
        "env": env,
        "role": role,
        "env_vars": {"env": env},
    }
    if host is None:
        host = Host(
            agent_id=agent_id,
            hostname=hostname,
            fqdn=f"{hostname}.example.internal",
            ip_address=ip_address,
            os_id="ubuntu",
            os_version="24.04",
            kernel="6.8.0-ci",
            labels=labels,
            last_seen=datetime.now(timezone.utc),
            reboot_required=False,
        )
        db.add(host)
    else:
        host.hostname = hostname
        host.fqdn = f"{hostname}.example.internal"
        host.ip_address = ip_address
        host.os_id = "ubuntu"
        host.os_version = "24.04"
        host.kernel = "6.8.0-ci"
        host.labels = labels
        host.last_seen = datetime.now(timezone.utc)
        host.reboot_required = False
    return host


def ensure_owner_scope(db, user: AppUser, owner: str) -> None:
    scope = db.execute(
        select(AppUserScope).where(
            AppUserScope.user_id == user.id,
            AppUserScope.scope_type == "label_selector",
        )
    ).scalar_one_or_none()
    selector = {"owner": [owner]}
    if scope is None:
        scope = AppUserScope(
            id=uuid4(),
            user_id=user.id,
            scope_type="label_selector",
            selector=selector,
        )
        db.add(scope)
    else:
        scope.selector = selector


def main() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        ensure_host(db, "agent-ci-alice", "ci-alice-host", "alice", "prod", "web", "10.20.0.11")
        ensure_host(db, "agent-ci-bob", "ci-bob-host", "bob", "stage", "worker", "10.20.0.12")

        ensure_user(db, "admin", "ci-admin-password", "admin")
        scoped_user = ensure_user(db, "owner-viewer", "ci-owner-password", "readonly")
        ensure_owner_scope(db, scoped_user, "alice")

        db.commit()

    print("seeded playwright smoke data")


if __name__ == "__main__":
    main()
