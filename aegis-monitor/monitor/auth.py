"""Authentication and authorization for the AEGIS monitor service."""

from __future__ import annotations

import hmac
from typing import Callable

from fastapi import Depends, HTTPException, Request

from monitor.config import MonitorConfig


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
        return "open"

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


def _resolve_session_cookie(request: Request, config: MonitorConfig) -> str | None:
    """Check for a valid session cookie. Returns role or None.

    Placeholder — implemented in Task 3.
    """
    return None


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


def verify_report_signature(report_data: dict, config: MonitorConfig) -> bool:
    """Verify a report's cryptographic signature using agent public keys."""
    if not config.agent_public_keys:
        return True

    agent_id = report_data.get("agent_id", "")
    public_key = config.agent_public_keys.get(agent_id)
    if public_key is None:
        return False

    try:
        from aegis.monitoring.reports import ReportBase
        report = ReportBase.from_dict(report_data)
        return report.verify(public_key)
    except Exception:
        return False
