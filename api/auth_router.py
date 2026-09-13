"""
Provider portal authentication router.

Verification checklist (manual):
□ POST /auth/login returns httpOnly cookie (DevTools → Application → Cookies,
  confirm HttpOnly and Secure flags are set)
□ GET /auth/me returns user data without exposing token in response body
□ Navigating to /portal without login redirects to /login
□ After 20 min inactivity, SessionTimeoutModal appears
□ After 5 failed logins, account locks for 15 min
□ Admin user sees vendor_management section, billing user does not
□ Every login attempt appears in portal_audit_log
□ Password reset email sends and token expires after 1hr
□ MFA TOTP code verified correctly with Google Authenticator or Authy
"""

from __future__ import annotations

import json
import os
from typing import Any
from uuid import UUID

import pyotp
import requests
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, EmailStr, Field

from .auth_security import (
    ACCESS_COOKIE,
    MFA_SETUP_COOKIE,
    MFA_TEMP_COOKIE,
    REFRESH_COOKIE,
    access_token_ttl,
    clear_auth_cookies,
    client_ip,
    cookie_domain,
    cookie_secure,
    create_access_token,
    decode_token,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    hash_token,
    mfa_temp_ttl,
    new_refresh_token,
    new_reset_token,
    refresh_token_ttl,
    set_auth_cookies,
    set_mfa_setup_cookie,
    set_mfa_temp_cookie,
    user_agent,
    utcnow,
    validate_password_strength,
    verify_password,
)

auth_router = APIRouter(tags=["auth"])

LOCK_AFTER_FAILURES = 5
LOCK_MINUTES = 15
RESET_TOKEN_HOURS = 1
GENERIC_LOGIN_ERROR = "Invalid email or password"
GENERIC_RESET_MESSAGE = (
    "If an account exists for that email, a reset link has been sent."
)


class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class TotpBody(BaseModel):
    totp_code: str = Field(min_length=6, max_length=8)


class ForgotPasswordBody(BaseModel):
    email: EmailStr


class ResetPasswordBody(BaseModel):
    token: str = Field(min_length=16)
    new_password: str = Field(min_length=12)


def _db(request: Request):
    return request.app.state.db


def _cursor(request: Request):
    return _db(request).cursor(cursor_factory=RealDictCursor)


def log_audit_event(
    request: Request,
    *,
    action: str,
    success: bool = True,
    user_id: Any = None,
    user_email: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    error_message: str | None = None,
) -> None:
    conn = _db(request)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO portal_audit_log (
                    user_id, user_email, action, resource_type, resource_id,
                    details, ip_address, user_agent, success, error_message
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(user_id) if user_id else None,
                    user_email,
                    action,
                    resource_type,
                    resource_id,
                    json.dumps(details) if details else None,
                    client_ip(request),
                    user_agent(request),
                    success,
                    error_message,
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def _get_user_by_email(request: Request, email: str) -> dict[str, Any] | None:
    with _cursor(request) as cur:
        cur.execute(
            "SELECT * FROM portal_users WHERE lower(email) = lower(%s) LIMIT 1",
            (email,),
        )
        return cur.fetchone()


def _get_user_by_id(request: Request, user_id: str) -> dict[str, Any] | None:
    with _cursor(request) as cur:
        cur.execute("SELECT * FROM portal_users WHERE id = %s LIMIT 1", (user_id,))
        return cur.fetchone()


def _lock_remaining_minutes(user: dict[str, Any]) -> int | None:
    locked_until = user.get("locked_until")
    if not locked_until:
        return None
    if locked_until.tzinfo is None:
        from datetime import timezone

        locked_until = locked_until.replace(tzinfo=timezone.utc)
    remaining = locked_until - utcnow()
    if remaining.total_seconds() <= 0:
        return None
    return max(1, int((remaining.total_seconds() + 59) // 60))


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(user["id"]),
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"],
        "client_id": user.get("client_id"),
        "mfa_enabled": bool(user.get("mfa_enabled")),
        "last_login_at": user["last_login_at"].isoformat()
        if user.get("last_login_at")
        else None,
    }


def _issue_session(
    request: Request,
    response: Response,
    user: dict[str, Any],
) -> None:
    refresh_raw = new_refresh_token()
    expires = utcnow() + refresh_token_ttl()
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO portal_sessions (
                user_id, refresh_token_hash, ip_address, user_agent, expires_at, last_used_at
            )
            VALUES (%s, %s, %s, %s, %s, NOW())
            RETURNING id
            """,
            (
                str(user["id"]),
                hash_token(refresh_raw),
                client_ip(request),
                user_agent(request),
                expires,
            ),
        )
        session = cur.fetchone()
        cur.execute(
            """
            UPDATE portal_users
            SET failed_login_attempts = 0,
                locked_until = NULL,
                last_login_at = NOW(),
                updated_at = NOW()
            WHERE id = %s
            """,
            (str(user["id"]),),
        )
    conn.commit()
    access = create_access_token(
        user_id=str(user["id"]),
        email=user["email"],
        role=user["role"],
        client_id=user.get("client_id"),
        extra={"sid": str(session["id"])} if session else None,
    )
    set_auth_cookies(response, access_token=access, refresh_token=refresh_raw)
    response.delete_cookie(
        MFA_TEMP_COOKIE,
        path="/",
        domain=cookie_domain(),
        samesite="strict",
        httponly=True,
        secure=cookie_secure(),
    )
    user["last_login_at"] = utcnow()
    user["failed_login_attempts"] = 0


def get_current_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "unauthenticated", "message": "Not authenticated"},
        )
    try:
        payload = decode_token(token)
    except HTTPException as exc:
        if isinstance(exc.detail, dict) and exc.detail.get("code") == "token_expired":
            log_audit_event(
                request,
                action="token_expired",
                success=False,
                user_email=None,
                error_message="Access token expired",
            )
        raise
    if payload.get("purpose"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_token", "message": "Invalid token purpose"},
        )
    user = _get_user_by_id(request, payload["sub"])
    if not user or not user.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "unauthenticated", "message": "Not authenticated"},
        )
    return user


def _send_reset_email(to_email: str, reset_url: str) -> None:
    api_key = os.environ.get("SENDGRID_API_KEY", "").strip()
    from_email = os.environ.get("SENDGRID_FROM_EMAIL", "noreply@kalamon.cloud")
    if not api_key:
        print(f"[portal-auth] Password reset URL for {to_email}: {reset_url}")
        return
    response = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "personalizations": [{"to": [{"email": to_email}]}],
            "from": {"email": from_email},
            "subject": "Reset your Kalamon Provider Portal password",
            "content": [
                {
                    "type": "text/plain",
                    "value": (
                        "You requested a password reset for the Kalamon Provider Portal.\n\n"
                        f"This link expires in {RESET_TOKEN_HOURS} hour:\n{reset_url}\n\n"
                        "If you did not request this, you can ignore this email."
                    ),
                }
            ],
        },
        timeout=20,
    )
    if response.status_code >= 300:
        raise RuntimeError(f"SendGrid error {response.status_code}: {response.text}")


@auth_router.post("/login")
def login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
    email = str(body.email).strip().lower()
    user = _get_user_by_email(request, email)
    if not user or not user.get("is_active"):
        log_audit_event(
            request,
            action="login_failed",
            success=False,
            user_email=email,
            error_message="Unknown or inactive account",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_credentials", "message": GENERIC_LOGIN_ERROR},
        )

    remaining = _lock_remaining_minutes(user)
    if remaining is not None:
        log_audit_event(
            request,
            action="login_locked",
            success=False,
            user_id=user["id"],
            user_email=user["email"],
            error_message="Account locked",
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={
                "code": "account_locked",
                "message": f"Account temporarily locked. Try again in {remaining} minutes.",
                "minutes_remaining": remaining,
            },
        )

    if not verify_password(body.password, user["hashed_password"]):
        conn = _db(request)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE portal_users
                SET failed_login_attempts = failed_login_attempts + 1,
                    locked_until = CASE
                        WHEN failed_login_attempts + 1 >= %s
                        THEN NOW() + (%s || ' minutes')::interval
                        ELSE locked_until
                    END,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING failed_login_attempts, locked_until
                """,
                (LOCK_AFTER_FAILURES, str(LOCK_MINUTES), str(user["id"])),
            )
            updated = cur.fetchone()
        conn.commit()
        attempts = int(updated["failed_login_attempts"]) if updated else 0
        if attempts >= LOCK_AFTER_FAILURES:
            log_audit_event(
                request,
                action="login_locked",
                success=False,
                user_id=user["id"],
                user_email=user["email"],
                error_message="Too many failed login attempts",
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail={
                    "code": "account_locked",
                    "message": f"Account temporarily locked. Try again in {LOCK_MINUTES} minutes.",
                    "minutes_remaining": LOCK_MINUTES,
                },
            )
        log_audit_event(
            request,
            action="login_failed",
            success=False,
            user_id=user["id"],
            user_email=user["email"],
            error_message="Invalid password",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_credentials", "message": GENERIC_LOGIN_ERROR},
        )

    if user.get("mfa_enabled"):
        temp_token = create_access_token(
            user_id=str(user["id"]),
            email=user["email"],
            role=user["role"],
            client_id=user.get("client_id"),
            ttl=mfa_temp_ttl(),
            extra={"purpose": "mfa"},
        )
        set_mfa_temp_cookie(response, temp_token)
        log_audit_event(
            request,
            action="login_success",
            user_id=user["id"],
            user_email=user["email"],
            details={"mfa_required": True},
        )
        return {"mfa_required": True, "temp_token": temp_token}

    _issue_session(request, response, user)
    log_audit_event(
        request,
        action="login_success",
        user_id=user["id"],
        user_email=user["email"],
        details={"mfa_required": False},
    )
    return {"mfa_required": False, "user": _public_user(user)}


@auth_router.post("/mfa/verify")
def mfa_verify(body: TotpBody, request: Request, response: Response) -> dict[str, Any]:
    temp_token = request.cookies.get(MFA_TEMP_COOKIE)
    if not temp_token:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            temp_token = auth[7:].strip()
    if not temp_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "mfa_required", "message": "MFA session expired"},
        )
    payload = decode_token(temp_token, audience_purpose="mfa")
    user = _get_user_by_id(request, payload["sub"])
    if not user or not user.get("mfa_enabled") or not user.get("mfa_secret"):
        log_audit_event(
            request,
            action="mfa_failed",
            success=False,
            user_email=payload.get("email"),
            error_message="MFA not configured",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "mfa_failed", "message": "MFA is not configured"},
        )
    secret = decrypt_secret(user["mfa_secret"])
    totp = pyotp.TOTP(secret)
    if not totp.verify(body.totp_code.strip(), valid_window=1):
        log_audit_event(
            request,
            action="mfa_failed",
            success=False,
            user_id=user["id"],
            user_email=user["email"],
            error_message="Invalid TOTP code",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "mfa_failed", "message": "Invalid verification code"},
        )
    _issue_session(request, response, user)
    log_audit_event(
        request,
        action="login_success",
        user_id=user["id"],
        user_email=user["email"],
        details={"mfa": True},
    )
    return {"mfa_required": False, "user": _public_user(user)}


@auth_router.post("/mfa/setup")
def mfa_setup(
    request: Request,
    response: Response,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, str]:
    secret = pyotp.random_base32()
    issuer = "Kalamon Portal"
    qr_code_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["email"],
        issuer_name=issuer,
    )
    set_mfa_setup_cookie(response, encrypt_secret(secret))
    log_audit_event(
        request,
        action="mfa_setup_initiated",
        user_id=user["id"],
        user_email=user["email"],
    )
    return {"secret": secret, "qr_code_uri": qr_code_uri}


@auth_router.post("/mfa/confirm")
def mfa_confirm(
    body: TotpBody,
    request: Request,
    response: Response,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, bool]:
    pending = request.cookies.get(MFA_SETUP_COOKIE)
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "mfa_setup_required", "message": "Start MFA setup first"},
        )
    secret = decrypt_secret(pending)
    if not pyotp.TOTP(secret).verify(body.totp_code.strip(), valid_window=1):
        log_audit_event(
            request,
            action="mfa_failed",
            success=False,
            user_id=user["id"],
            user_email=user["email"],
            error_message="MFA confirm failed",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "mfa_failed", "message": "Invalid verification code"},
        )
    conn = _db(request)
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE portal_users
            SET mfa_secret = %s, mfa_enabled = TRUE, updated_at = NOW()
            WHERE id = %s
            """,
            (encrypt_secret(secret), str(user["id"])),
        )
    conn.commit()
    response.delete_cookie(MFA_SETUP_COOKIE, path="/")
    log_audit_event(
        request,
        action="mfa_enabled",
        user_id=user["id"],
        user_email=user["email"],
    )
    return {"mfa_enabled": True}


@auth_router.post("/refresh")
def refresh(request: Request, response: Response) -> dict[str, str]:
    raw = request.cookies.get(REFRESH_COOKIE)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "unauthenticated", "message": "Missing refresh token"},
        )
    token_hash = hash_token(raw)
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT s.*, u.email, u.role, u.client_id, u.is_active
            FROM portal_sessions s
            JOIN portal_users u ON u.id = s.user_id
            WHERE s.refresh_token_hash = %s
              AND s.is_active = TRUE
              AND s.revoked_at IS NULL
              AND s.expires_at > NOW()
            LIMIT 1
            """,
            (token_hash,),
        )
        session = cur.fetchone()
        if not session or not session.get("is_active"):
            conn.rollback()
            log_audit_event(
                request,
                action="session_refreshed",
                success=False,
                error_message="Invalid refresh token",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "unauthenticated", "message": "Invalid refresh token"},
            )
        cur.execute(
            """
            UPDATE portal_sessions
            SET last_used_at = NOW()
            WHERE id = %s
            """,
            (str(session["id"]),),
        )
    conn.commit()
    access = create_access_token(
        user_id=str(session["user_id"]),
        email=session["email"],
        role=session["role"],
        client_id=session.get("client_id"),
        extra={"sid": str(session["id"])},
    )
    cookie_kwargs = {
        "httponly": True,
        "secure": cookie_secure(),
        "samesite": "strict",
        "path": "/",
        "max_age": int(access_token_ttl().total_seconds()),
    }
    domain = cookie_domain()
    if domain:
        cookie_kwargs["domain"] = domain
    response.set_cookie(ACCESS_COOKIE, access, **cookie_kwargs)
    log_audit_event(
        request,
        action="session_refreshed",
        user_id=session["user_id"],
        user_email=session["email"],
        resource_type="session",
        resource_id=str(session["id"]),
    )
    return {"status": "ok"}


@auth_router.post("/logout")
def logout(
    request: Request,
    response: Response,
) -> dict[str, bool]:
    user_email = None
    user_id = None
    raw = request.cookies.get(REFRESH_COOKIE)
    access = request.cookies.get(ACCESS_COOKIE)
    if access:
        try:
            payload = decode_token(access)
            user_email = payload.get("email")
            user_id = payload.get("sub")
        except HTTPException:
            pass
    conn = _db(request)
    if raw:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE portal_sessions
                SET revoked_at = NOW(), is_active = FALSE
                WHERE refresh_token_hash = %s AND is_active = TRUE
                RETURNING user_id
                """,
                (hash_token(raw),),
            )
            row = cur.fetchone()
            if row:
                user_id = user_id or row["user_id"]
        conn.commit()
    clear_auth_cookies(response)
    log_audit_event(
        request,
        action="logout",
        user_id=user_id,
        user_email=user_email,
    )
    return {"ok": True}


@auth_router.post("/forgot-password")
def forgot_password(body: ForgotPasswordBody, request: Request) -> dict[str, str]:
    email = str(body.email).strip().lower()
    user = _get_user_by_email(request, email)
    log_audit_event(
        request,
        action="password_reset_requested",
        success=True,
        user_id=user["id"] if user else None,
        user_email=email,
        details={"account_found": bool(user)},
    )
    if user and user.get("is_active"):
        raw = new_reset_token()
        conn = _db(request)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
                VALUES (%s, %s, NOW() + (%s || ' hours')::interval)
                """,
                (str(user["id"]), hash_token(raw), str(RESET_TOKEN_HOURS)),
            )
        conn.commit()
        frontend = os.environ.get("PORTAL_FRONTEND_URL", "https://kalamon.cloud").rstrip(
            "/"
        )
        reset_url = f"{frontend}/reset-password?token={raw}"
        try:
            _send_reset_email(user["email"], reset_url)
        except Exception as exc:
            log_audit_event(
                request,
                action="password_reset_requested",
                success=False,
                user_id=user["id"],
                user_email=user["email"],
                error_message=str(exc),
            )
    return {"message": GENERIC_RESET_MESSAGE}


@auth_router.post("/reset-password")
def reset_password(body: ResetPasswordBody, request: Request) -> dict[str, bool]:
    strength_error = validate_password_strength(body.new_password)
    if strength_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "weak_password", "message": strength_error},
        )
    token_hash = hash_token(body.token)
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT t.*, u.email
            FROM password_reset_tokens t
            JOIN portal_users u ON u.id = t.user_id
            WHERE t.token_hash = %s
            LIMIT 1
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        if (
            not row
            or row.get("used_at") is not None
            or row["expires_at"] <= utcnow()
        ):
            conn.rollback()
            log_audit_event(
                request,
                action="password_reset_completed",
                success=False,
                error_message="Invalid or expired reset token",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "invalid_token",
                    "message": "This reset link is invalid or has expired",
                },
            )
        cur.execute(
            """
            UPDATE portal_users
            SET hashed_password = %s,
                password_changed_at = NOW(),
                failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = NOW()
            WHERE id = %s
            """,
            (hash_password(body.new_password), str(row["user_id"])),
        )
        cur.execute(
            "UPDATE password_reset_tokens SET used_at = NOW() WHERE id = %s",
            (str(row["id"]),),
        )
        cur.execute(
            """
            UPDATE portal_sessions
            SET revoked_at = NOW(), is_active = FALSE
            WHERE user_id = %s AND is_active = TRUE
            """,
            (str(row["user_id"]),),
        )
    conn.commit()
    log_audit_event(
        request,
        action="password_reset_completed",
        user_id=row["user_id"],
        user_email=row["email"],
    )
    return {"ok": True}


@auth_router.get("/me")
def me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return _public_user(user)


@auth_router.get("/sessions")
def list_sessions(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    with _cursor(request) as cur:
        cur.execute(
            """
            SELECT id, ip_address, created_at, last_used_at, expires_at
            FROM portal_sessions
            WHERE user_id = %s AND is_active = TRUE AND revoked_at IS NULL
            ORDER BY last_used_at DESC NULLS LAST, created_at DESC
            """,
            (str(user["id"]),),
        )
        rows = cur.fetchall()
    return [
        {
            "id": str(row["id"]),
            "ip_address": row.get("ip_address"),
            "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
            "last_used": row["last_used_at"].isoformat()
            if row.get("last_used_at")
            else None,
        }
        for row in rows
    ]


@auth_router.delete("/sessions/{session_id}")
def revoke_session(
    session_id: UUID,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, bool]:
    conn = _db(request)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            UPDATE portal_sessions
            SET revoked_at = NOW(), is_active = FALSE
            WHERE id = %s AND user_id = %s AND is_active = TRUE
            RETURNING id
            """,
            (str(session_id), str(user["id"])),
        )
        row = cur.fetchone()
    if not row:
        conn.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    conn.commit()
    log_audit_event(
        request,
        action="session_revoked",
        user_id=user["id"],
        user_email=user["email"],
        resource_type="session",
        resource_id=str(session_id),
    )
    return {"ok": True}
