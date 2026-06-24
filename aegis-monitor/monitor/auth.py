"""Authentication and authorization for the AEGIS monitor service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import defaultdict
from typing import Callable

from fastapi import Depends, HTTPException, Request

from monitor.config import MonitorConfig

logger = logging.getLogger(__name__)


def get_config(request: Request) -> MonitorConfig:
    """FastAPI dependency — retrieve the monitor config from app state."""
    return request.app.state.config


def verify_api_key(
    request: Request, config: MonitorConfig = Depends(get_config),
) -> str:
    """Resolve the caller's role from the Authorization header.

    Returns:
        Role string: "agent", "viewer", "operator", or "open".
    """
    if not config.api_keys:
        if config.allow_open_mode:
            return "open"
        raise HTTPException(status_code=503, detail="Open mode is disabled; configure api_keys or set allow_open_mode")

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        # Check for session cookie before rejecting (placeholder for Task 3)
        session_role = _resolve_session_cookie(request, config)
        if session_role is not None:
            return session_role
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = auth_header[len("Bearer "):]
    for configured_key, role in config.api_keys.items():
        if hmac.compare_digest(token, configured_key):
            return role

    raise HTTPException(status_code=403, detail="Invalid API key")


_SESSION_COOKIE_NAME = "aegis_session"


def create_session_token(
    role: str, api_key: str, secret: str, *, issued_at: float | None = None,
) -> str:
    """Create an HMAC-SHA256 signed session token.

    Format: base64(payload).signature
    Payload: {"role": ..., "key_hash": sha256(api_key), "iat": ..., "nonce": ...}
    """
    payload = {
        "role": role,
        "key_hash": hashlib.sha256(api_key.encode()).hexdigest(),
        "iat": issued_at if issued_at is not None else time.time(),
        "nonce": secrets.token_hex(16),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode()
    sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_session_token(
    token: str, secret: str, *, ttl: int, now: float | None = None,
) -> dict | None:
    """Verify and decode a session token. Returns payload dict or None."""
    try:
        payload_b64, sig = token.rsplit(".", 1)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        expected_sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(payload_bytes)
        current_time = now if now is not None else time.time()
        if current_time - payload.get("iat", 0) > ttl:
            return None
        return payload
    except Exception:
        return None


def _resolve_session_cookie(request: Request, config: MonitorConfig) -> str | None:
    """Check for a valid session cookie. Returns role or None."""
    token = request.cookies.get(_SESSION_COOKIE_NAME)
    if not token or not config.session_secret:
        return None
    payload = verify_session_token(token, config.session_secret, ttl=config.session_ttl_seconds)
    if payload is None:
        return None
    # Verify the originating API key still exists
    key_hash = payload.get("key_hash", "")
    for configured_key in config.api_keys:
        if hashlib.sha256(configured_key.encode()).hexdigest() == key_hash:
            return payload["role"]
    return None  # Key was removed — session invalid


def generate_csrf_token(secret: str, *, issued_at: float | None = None) -> str:
    """Generate a CSRF token: HMAC-signed timestamp + nonce."""
    iat = issued_at if issued_at is not None else time.time()
    nonce = secrets.token_hex(16)
    message = f"{iat}:{nonce}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    payload = base64.urlsafe_b64encode(message).decode()
    return f"{payload}.{sig}"


def verify_csrf_token(
    token: str, secret: str, *, ttl: int, now: float | None = None,
) -> bool:
    """Verify a CSRF token is valid and not expired."""
    try:
        payload_b64, sig = token.rsplit(".", 1)
        message = base64.urlsafe_b64decode(payload_b64)
        expected_sig = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return False
        iat_str = message.decode().split(":")[0]
        current_time = now if now is not None else time.time()
        return (current_time - float(iat_str)) <= ttl
    except Exception:
        return False


def require_csrf(request: Request, config: MonitorConfig = Depends(get_config)) -> None:
    """Enforce CSRF token for cookie-authenticated mutation requests.

    Skipped for Bearer-authenticated requests (not cookie-based).
    Open mode still requires CSRF for cookie-authenticated mutations.
    """
    if request.headers.get("Authorization", "").startswith("Bearer "):
        return  # Bearer auth — not vulnerable to CSRF
    if not config.session_secret:
        return

    csrf_token = request.headers.get("X-CSRF-Token", "")
    if not csrf_token or not verify_csrf_token(csrf_token, config.session_secret, ttl=config.session_ttl_seconds):
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")


def require_role(*allowed_roles: str) -> Callable:
    """FastAPI dependency factory — restrict access to specific roles.

    The "open" role (when no keys are configured) is always accepted.
    """
    async def _check(role: str = Depends(verify_api_key)) -> str:
        if role == "open":
            return role
        if role not in allowed_roles:
            raise HTTPException(status_code=403, detail=f"Role '{role}' not permitted")
        return role
    return _check


class LoginRateLimiter:
    """In-memory per-IP rate limiter for login attempts."""

    def __init__(self, per_minute: int = 10, per_hour: int = 50) -> None:
        self.per_minute = per_minute
        self.per_hour = per_hour
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def check(self, ip: str, *, now: float | None = None) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        current = now if now is not None else time.time()
        attempts = self._attempts[ip]

        # Prune entries older than 1 hour
        cutoff_hour = current - 3600
        self._attempts[ip] = [t for t in attempts if t > cutoff_hour]
        attempts = self._attempts[ip]

        minute_count = sum(1 for t in attempts if t > current - 60)
        if minute_count >= self.per_minute:
            return False
        if len(attempts) >= self.per_hour:
            return False

        attempts.append(current)
        return True


_REPORT_TYPE_MAP: dict[str, type] | None = None


def _get_report_type_map() -> dict[str, type]:
    """Lazy-load report subclass map to avoid import cycles."""
    global _REPORT_TYPE_MAP
    if _REPORT_TYPE_MAP is None:
        from aegis.monitoring.reports import (
            AgentHeartbeat,
            CompromiseReport,
            ThreatEventReport,
            TrustReport,
        )
        _REPORT_TYPE_MAP = {
            "compromise": CompromiseReport,
            "trust": TrustReport,
            "threat_event": ThreatEventReport,
            "heartbeat": AgentHeartbeat,
        }
    return _REPORT_TYPE_MAP


def verify_report_signature(data: dict, config: MonitorConfig) -> tuple[bool, bool]:
    """Verify a report's cryptographic signature.

    Returns:
        (accepted, verified):
        - (True, True): known agent, valid signature
        - (True, False): unknown agent or no keys configured
        - (False, False): known agent, invalid/missing signature
    """
    if not config.agent_public_keys:
        return (True, False)

    agent_id = data.get("agent_id", "")
    agent_key = config.agent_public_keys.get(agent_id)

    if agent_key is None:
        logger.debug("Report from unknown agent %r accepted unverified", agent_id)
        return (True, False)

    sig = data.get("signature", "")
    if not sig:
        logger.warning("Report from known agent %r rejected: missing signature", agent_id)
        return (False, False)

    report_key_type = data.get("key_type", "hmac-sha256")
    if report_key_type != agent_key.key_type:
        logger.warning(
            "Report from agent %r rejected: key_type mismatch (report=%r, config=%r)",
            agent_id, report_key_type, agent_key.key_type,
        )
        return (False, False)

    report_type = data.get("report_type", "")
    type_map = _get_report_type_map()
    report_cls = type_map.get(report_type)
    if report_cls is None:
        logger.warning("Report from agent %r rejected: unknown report_type %r", agent_id, report_type)
        return (False, False)

    try:
        report = report_cls.from_dict(data)
        if report.verify(agent_key.key_bytes):
            return (True, True)
        logger.warning("Report from agent %r rejected: signature verification failed", agent_id)
        return (False, False)
    except Exception:
        logger.warning("Report from agent %r rejected: deserialization/verification error", agent_id, exc_info=True)
        return (False, False)
