#!/usr/bin/env python3
"""Evaluate a tool action against AEGIS broker policies.

Usage:
    python evaluate_action.py --json --tool "bash" --action-type "tool_call" --target "/bin/rm" --read-write "write"
    echo '{"tool":"bash","action_type":"tool_call","target":"/bin/rm","read_write":"write"}' | python evaluate_action.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS action evaluator")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--tool", default=None, help="Tool name")
    parser.add_argument("--action-type", default="tool_call", help="Action type")
    parser.add_argument("--target", default="", help="Action target")
    parser.add_argument("--read-write", default="read", help="read or write")
    parser.add_argument("--mode", default="enforce", help="AEGIS mode")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    # If no tool specified, try reading from stdin
    tool = args.tool
    action_type = args.action_type
    target = args.target
    read_write = args.read_write

    if tool is None:
        raw = sys.stdin.read().strip()
        if raw:
            data = json.loads(raw)
            tool = data.get("tool", "unknown")
            action_type = data.get("action_type", action_type)
            target = data.get("target", target)
            read_write = data.get("read_write", read_write)
        else:
            tool = "unknown"

    from aegis.broker.actions import ActionRequest
    from aegis.shield import Shield

    shield_kwargs: dict = {"mode": args.mode}
    if args.config:
        shield_kwargs["policy"] = args.config
    shield = Shield(**shield_kwargs)

    action = ActionRequest(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        source_provenance="model_output",
        action_type=action_type,
        read_write=read_write,
        target=target,
        args={"tool": tool},
        risk_hints={},
    )

    result = shield.evaluate_action(action)

    output: dict = {
        "allowed": result.allowed,
        "decision": result.decision,
        "reason": result.reason,
        "tool": tool,
        "action_type": action_type,
        "target": target,
    }

    # Append state context when available
    store = shield.state_store
    if store is not None:
        try:
            agent_id = shield.config.agent_id or "self"
            output["trust_tier"] = store.get_trust_tier(agent_id)
            output["quarantine_active"] = store.is_quarantined()
            limits = {
                "max_write_tool_calls": shield.config.broker.budgets.max_write_tool_calls,
                "max_posts_messages": shield.config.broker.budgets.max_posts_messages,
                "max_external_http_writes": shield.config.broker.budgets.max_external_http_writes,
                "max_new_domains": shield.config.broker.budgets.max_new_domains,
            }
            output["budget_remaining"] = store.get_budget_remaining(limits)
        except Exception:  # noqa: BLE001
            pass

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        status = "ALLOWED" if result.allowed else "DENIED"
        print(f"{status}: {tool} -> {target} ({result.reason})")


if __name__ == "__main__":
    main()
