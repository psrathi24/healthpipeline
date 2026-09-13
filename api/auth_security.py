"""
Portal auth crypto, JWT, cookies, and password helpers.

HIPAA-aligned defaults: bcrypt cost 12, RS256 access tokens, hashed refresh
tokens, Fernet-encrypted MFA secrets, httpOnly cookies.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Request, Response, status

_ROOT = Path(__file__).resolve().parent.parent

ACCESS_COOKIE = "portal_access_token"
REFRESH_COOKIE = "portal_refresh_token"
MFA_TEMP_COOKIE = "portal_mfa_temp"
MFA_SETUP_COOKIE = "portal_mfa_setup"

BCRYPT_ROUNDS = 12
PASSWORD_MIN_LENGTH = 12
_PASSWORD_COMPLEXITY = [
    (re.compile(r"[a-z]"), "one lowercase letter"),
    (re.compile(r"[A-Z]"), "one uppercase letter"),
    (re.compile(r"\d"), "one number"),
    (re.compile(r"[^A-Za-z0-9]"), "one special character"),
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _read_key_file(path_str: str) -> str:
    path = Path(path_str)
    if not path.is_absolute():
        path = _ROOT / path
    if not path.is_file():
        raise FileNotFoundError(f"JWT key file not found: {path}")
    return path.read_text(encoding="utf-8")


def load_private_key() -> str:
    return _read_key_file(
        os.environ.get("PORTAL_JWT_PRIVATE_KEY_PATH", "keys/portal_private_key.pem")
    )


def load_public_key() -> str:
    return _read_key_file(
        os.environ.get("PORTAL_JWT_PUBLIC_KEY_PATH", "keys/portal_public_key.pem")
    )


def jwt_algorithm() -> str:
    return os.environ.get("PORTAL_JWT_ALGORITHM", "RS256")


def access_token_ttl() -> timedelta:
    minutes = int(os.environ.get("PORTAL_ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    return timedelta(minutes=minutes)


def refresh_token_ttl() -> timedelta:
    days = int(os.environ.get("PORTAL_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    return timedelta(days=days)


def mfa_temp_ttl() -> timedelta:
    return timedelta(minutes=5)


def cookie_secure() -> bool:
    raw = os.environ.get("PORTAL_COOKIE_SECURE")
    if raw is not None and raw.strip() != "":
        return raw.strip().lower() in {"1", "true", "yes"}
    frontend = os.environ.get("PORTAL_FRONTEND_URL", "")
    return not frontend.startswith("http://localhost") and not frontend.startswith(
        "http://127.0.0.1"
    )


def cookie_domain() -> str | None:
    domain = os.environ.get("PORTAL_COOKIE_DOMAIN", "").strip()
    if not domain or domain in {"localhost", "127.0.0.1"}:
        return None
    return domain


def _fernet() -> Fernet:
    key = os.environ.get("PORTAL_ENCRYPTION_KEY", "").strip()
    if not key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PORTAL_ENCRYPTION_KEY is not configured",
        )
    try:
        return Fernet(key.encode("utf-8") if isinstance(key, str) else key)
    except (ValueError, Exception) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PORTAL_ENCRYPTION_KEY is invalid",
        ) from exc


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to decrypt MFA secret",
        ) from exc


def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
    )
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def validate_password_strength(password: str) -> str | None:
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
    missing = [label for pattern, label in _PASSWORD_COMPLEXITY if not pattern.search(password)]
    if missing:
        return "Password must include " + ", ".join(missing)
    return None


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def new_reset_token() -> str:
    return secrets.token_urlsafe(32)


def create_access_token(
    *,
    user_id: str,
    email: str,
    role: str,
    client_id: str | None,
    ttl: timedelta | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    now = utcnow()
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "client_id": client_id,
        "exp": now + (ttl or access_token_ttl()),
        "iat": now,
        "jti": str(uuid4()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, load_private_key(), algorithm=jwt_algorithm())


def decode_token(token: str, *, audience_purpose: str | None = None) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, load_public_key(), algorithms=[jwt_algorithm()])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "token_expired", "message": "Access token expired"},
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_token", "message": "Invalid token"},
        ) from exc
    if audience_purpose and payload.get("purpose") != audience_purpose:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_token", "message": "Invalid token purpose"},
        )
    return payload


def set_auth_cookies(
    response: Response,
    *,
    access_token: str,
    refresh_token: str,
) -> None:
    common = _cookie_kwargs()
    response.set_cookie(
        ACCESS_COOKIE,
        access_token,
        max_age=int(access_token_ttl().total_seconds()),
        **common,
    )
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age=int(refresh_token_ttl().total_seconds()),
        **common,
    )


def set_mfa_temp_cookie(response: Response, temp_token: str) -> None:
    response.set_cookie(
        MFA_TEMP_COOKIE,
        temp_token,
        max_age=int(mfa_temp_ttl().total_seconds()),
        **_cookie_kwargs(),
    )


def set_mfa_setup_cookie(response: Response, encrypted_secret: str) -> None:
    response.set_cookie(
        MFA_SETUP_COOKIE,
        encrypted_secret,
        max_age=600,
        **_cookie_kwargs(),
    )


def clear_auth_cookies(response: Response) -> None:
    kwargs = _cookie_kwargs()
    for name in (ACCESS_COOKIE, REFRESH_COOKIE, MFA_TEMP_COOKIE, MFA_SETUP_COOKIE):
        response.delete_cookie(name, path=kwargs["path"], domain=kwargs.get("domain"))


def _cookie_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "httponly": True,
        "secure": cookie_secure(),
        "samesite": "strict",
        "path": "/",
    }
    domain = cookie_domain()
    if domain:
        kwargs["domain"] = domain
    return kwargs


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client:
        return request.client.host
    return "unknown"


def user_agent(request: Request) -> str:
    return (request.headers.get("user-agent") or "")[:512]
