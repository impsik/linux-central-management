from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from ldap3 import ALL, NTLM, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException

from ..config import settings


_USER_RE = re.compile(r"^[A-Za-z0-9._@\\-]{1,128}$")


@dataclass
class ADAuthResult:
    username: str
    display_name: str | None = None
    email: str | None = None
    dn: str | None = None


def _fernet() -> Fernet:
    raw_key = getattr(settings, "mfa_encryption_key", None)
    if not raw_key:
        raise RuntimeError("MFA_ENCRYPTION_KEY is required to store Active Directory bind passwords")

    key = str(raw_key).strip()
    if len(key) >= 2 and key[0] == key[-1] and key[0] in {'"', "'"}:
        key = key[1:-1].strip()
    return Fernet(key.encode("utf-8"))


def encrypt_password(password: str) -> str:
    return _fernet().encrypt((password or "").encode("utf-8")).decode("utf-8")


def decrypt_password(token: str | None) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(str(token).encode("utf-8")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError("stored AD bind password cannot be decrypted") from e


def normalize_username(username: str) -> str:
    value = (username or "").strip()
    if "\\" in value:
        value = value.rsplit("\\", 1)[-1].strip()
    if "@" in value:
        value = value.split("@", 1)[0].strip()
    if not value or not _USER_RE.match(value):
        raise ValueError("Invalid username or password")
    return value


def _escape_filter_value(value: str) -> str:
    return (
        value.replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _user_principal(username: str, domain: str | None, dn: str | None) -> str:
    domain = (domain or "").strip()
    if domain:
        return f"{username}@{domain}"
    if dn:
        return dn
    return username


def _server_from_uri(server_uri: str, use_ssl_default: bool) -> Server:
    raw = (server_uri or "").strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    scheme = (parsed.scheme or "").lower()
    host = parsed.hostname or raw.split(":", 1)[0]
    if not host:
        raise RuntimeError("Active Directory server URI is invalid")
    use_ssl = True if scheme == "ldaps" else False if scheme == "ldap" else bool(use_ssl_default)
    port = parsed.port or (636 if use_ssl else 389)
    tls = Tls(validate=2) if use_ssl else None
    return Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL)


def authenticate_ad(settings_row, username: str, password: str) -> ADAuthResult:
    if not bool(getattr(settings_row, "ad_enabled", False)):
        raise ValueError("Active Directory login is disabled")

    username_norm = normalize_username(username)
    if not password:
        raise ValueError("Invalid username or password")

    server_uri = (getattr(settings_row, "ad_server_uri", None) or "").strip()
    base_dn = (getattr(settings_row, "ad_base_dn", None) or "").strip()
    bind_dn = (getattr(settings_row, "ad_bind_dn", None) or "").strip()
    user_filter = (getattr(settings_row, "ad_user_filter", None) or "(sAMAccountName={username})").strip()
    if not server_uri or not base_dn or not bind_dn:
        raise RuntimeError("Active Directory settings are incomplete")
    if "{username}" not in user_filter:
        raise RuntimeError("AD user filter must contain {username}")

    bind_password = decrypt_password(getattr(settings_row, "ad_bind_password_enc", None))
    if not bind_password:
        raise RuntimeError("Active Directory bind password is not configured")

    server = _server_from_uri(server_uri, bool(getattr(settings_row, "ad_use_ssl", True)))
    search_filter = user_filter.replace("{username}", _escape_filter_value(username_norm))

    try:
        with Connection(server, user=bind_dn, password=bind_password, auto_bind=True) as conn:
            ok = conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=["distinguishedName", "displayName", "mail", "sAMAccountName", "userPrincipalName"],
                size_limit=2,
            )
            if not ok or len(conn.entries) != 1:
                raise ValueError("Invalid username or password")
            entry = conn.entries[0]
            dn = str(getattr(entry, "distinguishedName", "") or entry.entry_dn or "").strip()
            display_name = str(getattr(entry, "displayName", "") or "").strip() or None
            email = str(getattr(entry, "mail", "") or "").strip() or None
    except ValueError:
        raise
    except LDAPException as e:
        raise RuntimeError(f"Active Directory lookup failed: {e}") from e

    principal = _user_principal(username_norm, getattr(settings_row, "ad_domain", None), dn)
    try:
        kwargs = {"user": principal, "password": password, "auto_bind": True}
        if "\\" in principal:
            kwargs["authentication"] = NTLM
        with Connection(server, **kwargs):
            pass
    except LDAPException as e:
        raise ValueError("Invalid username or password") from e

    return ADAuthResult(username=username_norm, display_name=display_name, email=email, dn=dn)
