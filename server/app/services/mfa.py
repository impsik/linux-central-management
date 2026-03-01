from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Iterable

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from ..config import settings


def _fernet() -> Fernet:
    raw_key = getattr(settings, "mfa_encryption_key", None)
    if not raw_key:
        raise RuntimeError("MFA_ENCRYPTION_KEY is not set")

    key = str(raw_key).strip()
    # Be tolerant of accidentally quoted env values, e.g. "<fernet-key>".
    if len(key) >= 2 and key[0] == key[-1] and key[0] in {'"', "'"}:
        key = key[1:-1].strip()

    try:
        return Fernet(key.encode("utf-8"))
    except Exception as e:
        raise RuntimeError("MFA_ENCRYPTION_KEY is invalid (must be a 32-byte urlsafe base64 Fernet key)") from e


def encrypt_secret(secret_b32: str) -> str:
    f = _fernet()
    return f.encrypt(secret_b32.encode("utf-8")).decode("utf-8")


def decrypt_secret(token: str) -> str:
    f = _fernet()
    try:
        return f.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError("invalid encrypted secret")


def new_totp_secret() -> str:
    return pyotp.random_base32()


def otpauth_uri(username: str, secret_b32: str) -> str:
    issuer = getattr(settings, "mfa_totp_issuer", "linux-central-management")
    totp = pyotp.TOTP(secret_b32)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret_b32: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) not in (6, 7, 8):
        return False
    # allow modest clock skew (±2 steps = ~60s) to reduce false negatives on phones
    # with slightly incorrect time sync.
    return bool(pyotp.TOTP(secret_b32).verify(code, valid_window=2))


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def generate_recovery_codes(n: int = 10) -> list[str]:
    # readable, high-entropy codes (no ambiguous chars)
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    codes: list[str] = []
    for _ in range(n):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(raw)
    return codes


def hash_recovery_codes(codes: Iterable[str]) -> list[str]:
    return [sha256_hex(c) for c in codes]


def recovery_code_matches(stored_hashes: Iterable[str], code: str) -> bool:
    h = sha256_hex((code or "").strip())
    return h in set(stored_hashes or [])


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
