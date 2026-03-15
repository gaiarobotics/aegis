#!/usr/bin/env python3
"""Show remaining budget against configured limits.

Usage:
    python budget.py --json
    python budget.py
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS budget query")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    from aegis.core.config import load_config
    from aegis.core.state_store import StateStore, TamperDetectedError

    config = load_config(args.config) if args.config else load_config()

    if not config.state_store.enabled:
        output = {"error": "state_store_disabled"}
        if args.json_output:
            json.dump(output, sys.stdout)
            sys.stdout.write("\n")
        else:
            print("State store is disabled")
        return

    try:
        store = StateStore(
            log_dir=config.state_store.log_dir,
            checkpoint_interval=config.state_store.checkpoint_interval,
            anchor_window=config.state_store.anchor_window,
        )
    except TamperDetectedError as exc:
        output = {"error": "state_log_tampered", "detail": str(exc)}
        if args.json_output:
            json.dump(output, sys.stdout)
            sys.stdout.write("\n")
        else:
            print(f"State log tampered: {exc}")
        return

    limits = {
        "max_write_tool_calls": config.broker.budgets.max_write_tool_calls,
        "max_posts_messages": config.broker.budgets.max_posts_messages,
        "max_external_http_writes": config.broker.budgets.max_external_http_writes,
        "max_new_domains": config.broker.budgets.max_new_domains,
    }
    remaining = store.get_budget_remaining(limits)
    snap = store.snapshot()
    consumed = snap.get("budgets", {})

    output = {
        "write_tool_calls": {
            "limit": limits["max_write_tool_calls"],
            "consumed": consumed.get("write_tool_calls", 0),
            "remaining": remaining["write_tool_calls"],
        },
        "posts_messages": {
            "limit": limits["max_posts_messages"],
            "consumed": consumed.get("posts_messages", 0),
            "remaining": remaining["posts_messages"],
        },
        "external_http_writes": {
            "limit": limits["max_external_http_writes"],
            "consumed": consumed.get("external_http_writes", 0),
            "remaining": remaining["external_http_writes"],
        },
        "new_domains": {
            "limit": limits["max_new_domains"],
            "consumed": len(consumed.get("seen_domains", [])),
            "remaining": remaining["new_domains"],
        },
    }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        print("AEGIS Budget Status")
        print("====================")
        for category, info in output.items():
            print(f"  {category}: {info['consumed']}/{info['limit']} used, {info['remaining']} remaining")


if __name__ == "__main__":
    main()
