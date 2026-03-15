#!/usr/bin/env python3
"""Check behavioral baseline and drift data for an agent.

Usage:
    python drift.py --agent-id "agent-name" --json
    python drift.py --agent-id "agent-name"
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS behavioral drift query")
    parser.add_argument("--agent-id", required=True, help="Agent ID to look up")
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

    baseline = store.get_baseline(args.agent_id)

    if baseline is None:
        output: dict = {
            "agent_id": args.agent_id,
            "status": "no_baseline",
            "message": "No behavioral data recorded for agent",
        }
    else:
        output = {
            "agent_id": baseline.agent_id,
            "event_count": baseline.event_count,
            "avg_output_length": baseline.avg_output_length,
            "tool_counts": baseline.tool_counts,
            "content_type_counts": baseline.content_type_counts,
            "frozen": baseline.frozen,
        }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        if baseline is None:
            print(f"No behavioral baseline for agent '{args.agent_id}'")
        else:
            print(f"Agent:              {baseline.agent_id}")
            print(f"Events recorded:    {baseline.event_count}")
            print(f"Avg output length:  {baseline.avg_output_length:.0f}")
            print(f"Baseline frozen:    {baseline.frozen}")
            if baseline.tool_counts:
                print(f"Tool usage:")
                for tool, count in sorted(baseline.tool_counts.items(), key=lambda x: -x[1]):
                    print(f"  {tool}: {count}")
            if baseline.content_type_counts:
                print(f"Content types:")
                for ct, count in sorted(baseline.content_type_counts.items(), key=lambda x: -x[1]):
                    print(f"  {ct}: {count}")


if __name__ == "__main__":
    main()
