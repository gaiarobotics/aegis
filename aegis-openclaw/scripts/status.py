#!/usr/bin/env python3
"""Show current AEGIS status: mode, enabled modules, integrity.

Usage:
    python status.py
    python status.py --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS status")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    from aegis.core.config import load_config

    if args.config:
        config = load_config(args.config)
    else:
        config = load_config()

    enabled_modules = [name for name, enabled in config.modules.items() if enabled]

    status: dict = {
        "mode": config.mode,
        "agent_id": config.agent_id,
        "modules_enabled": enabled_modules,
        "scanner_sensitivity": config.scanner.sensitivity,
        "scanner_confidence_threshold": config.scanner.confidence_threshold,
        "broker_posture": config.broker.default_posture,
        "state_store_enabled": config.state_store.enabled,
    }

    # Append live state when StateStore is available
    if config.state_store.enabled:
        try:
            from aegis.core.state_store import StateStore, TamperDetectedError

            store = StateStore(
                log_dir=config.state_store.log_dir,
                checkpoint_interval=config.state_store.checkpoint_interval,
                anchor_window=config.state_store.anchor_window,
            )
            agent_id = config.agent_id or "self"
            status["trust_tier"] = store.get_trust_tier(agent_id)
            q = store.get_quarantine()
            status["quarantine_active"] = q.active
            status["quarantine_reason"] = q.reason if q.active else None
            limits = {
                "max_write_tool_calls": config.broker.budgets.max_write_tool_calls,
                "max_posts_messages": config.broker.budgets.max_posts_messages,
                "max_external_http_writes": config.broker.budgets.max_external_http_writes,
                "max_new_domains": config.broker.budgets.max_new_domains,
            }
            status["budget_remaining"] = store.get_budget_remaining(limits)
        except TamperDetectedError as exc:
            status["state_error"] = f"state_log_tampered: {exc}"
        except Exception as exc:  # noqa: BLE001
            status["state_error"] = str(exc)

    if args.json_output:
        json.dump(status, sys.stdout)
        sys.stdout.write("\n")
    else:
        print("AEGIS Status")
        print("============")
        print(f"Mode:                 {status['mode']}")
        print(f"Agent ID:             {status['agent_id']}")
        print(f"Modules enabled:      {', '.join(enabled_modules)}")
        print(f"Scanner sensitivity:  {status['scanner_sensitivity']}")
        print(f"Confidence threshold: {status['scanner_confidence_threshold']}")
        print(f"Broker posture:       {status['broker_posture']}")
        print(f"State store:          {'enabled' if status['state_store_enabled'] else 'disabled'}")
        if "trust_tier" in status:
            tier_names = {0: "untrusted", 1: "provisional", 2: "established", 3: "vouched"}
            print(f"Trust tier:           {status['trust_tier']} ({tier_names.get(status['trust_tier'], 'unknown')})")
        if status.get("quarantine_active"):
            print(f"Quarantine:           ACTIVE — {status['quarantine_reason']}")
        elif "quarantine_active" in status:
            print(f"Quarantine:           none")
        if "budget_remaining" in status:
            br = status["budget_remaining"]
            print(f"Budget remaining:     writes={br['write_tool_calls']} posts={br['posts_messages']} http={br['external_http_writes']} domains={br['new_domains']}")
        if "state_error" in status:
            print(f"State error:          {status['state_error']}")


if __name__ == "__main__":
    main()
