"""Authentication for the AEGIS monitor service."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from monitor.config import MonitorConfig


def get_config(request: Request) -> MonitorConfig:
    """FastAPI dependency — retrieve the monitor config from app state."""
    return request.app.state.config


def verify_api_key(
    request: Request, config: MonitorConfig = Depends(get_config)
) -> str:
    """FastAPI dependency — verify the ``Authorization: Bearer <key>`` header.

    Returns the validated API key on success.
    Raises 401 if no key provided, 403 if key is invalid.
    If no keys are configured, all requests are allowed (open mode).
    """
    # Open mode: no keys configured → allow everything
    if not config.api_keys:
        return ""

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = auth_header[len("Bearer "):]
    if token not in config.api_keys:
        raise HTTPException(status_code=403, detail="Invalid API key")

    return token


def verify_report_signature(report_data: dict, config: MonitorConfig) -> bool:
    """Verify a report's cryptographic signature using agent public keys.

    Returns True if:
    - No public keys are configured (open mode), or
    - The signature is valid against the agent's registered public key.
    """
    if not config.agent_public_keys:
        return True

    agent_id = report_data.get("agent_id", "")
    public_key = config.agent_public_keys.get(agent_id)
    if public_key is None:
        return False

    try:
        from aegis.coordination.reports import ReportBase

        report = ReportBase.from_dict(report_data)
        return report.verify(public_key)
    except Exception:
        return False
