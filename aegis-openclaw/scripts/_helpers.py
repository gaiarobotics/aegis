"""Shared helpers for AEGIS OpenClaw scripts."""

from __future__ import annotations

import json
import sys
from typing import Any


def build_store(config: Any) -> tuple[Any, dict | None]:
    """Build a StateStore from config, returning (store, error_output).

    If the store cannot be created (disabled or tampered), returns
    ``(None, error_dict)`` where error_dict should be output and the
    script should exit.
    """
    if not config.state_store.enabled:
        return None, {"error": "state_store_disabled"}

    from aegis.core.state_store import StateStore, TamperDetectedError

    try:
        store = StateStore(
            log_dir=config.state_store.log_dir,
            checkpoint_interval=config.state_store.checkpoint_interval,
            anchor_window=config.state_store.anchor_window,
        )
        return store, None
    except TamperDetectedError as exc:
        return None, {"error": "state_log_tampered", "detail": str(exc)}


def build_shield(args: Any) -> Any:
    """Construct a Shield from argparse args (expects .mode and .config)."""
    from aegis.shield import Shield

    kwargs: dict = {}
    if getattr(args, "mode", None):
        kwargs["mode"] = args.mode
    if getattr(args, "config", None):
        kwargs["policy"] = args.config
    return Shield(**kwargs)


def try_send_monitoring(
    shield: Any,
    report_type: str,
    **kwargs: Any,
) -> bool:
    """Best-effort monitoring telemetry.  Never raises."""
    mon_cfg = shield.config.monitoring
    if not mon_cfg.enabled or not mon_cfg.service_url:
        return False
    try:
        from aegis.monitoring.client import MonitoringClient

        client = MonitoringClient(
            config=mon_cfg,
            agent_id=shield.config.agent_id or "self",
            operator_id=shield.config.operator_id or "",
        )
        getattr(client, report_type)(**kwargs)
        return True
    except Exception:  # noqa: BLE001
        return False


def json_output(data: dict, args: Any) -> None:
    """Write JSON output if --json flag is set, otherwise do nothing."""
    if getattr(args, "json_output", False):
        json.dump(data, sys.stdout)
        sys.stdout.write("\n")
