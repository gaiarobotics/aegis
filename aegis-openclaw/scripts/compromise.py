#!/usr/bin/env python3
"""Report an agent as compromised, permanently zeroing its trust.

Usage:
    python compromise.py --agent-id "agent-x" --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS compromise reporter")
    parser.add_argument("--agent-id", required=True, help="Agent to mark as compromised")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    from aegis.core.config import load_config

    from _helpers import build_store, json_output, try_send_monitoring

    config = load_config(args.config) if args.config else load_config()
    store, err = build_store(config)
    if err is not None:
        json_output(err, args) if args.json_output else print(err.get("error", "error"))
        return

    store.report_compromise(args.agent_id)

    trust = store.get_trust(args.agent_id)
    tier = store.get_trust_tier(args.agent_id)

    output: dict = {
        "success": True,
        "agent_id": args.agent_id,
        "compromised": trust.compromised if trust else True,
        "tier": tier,
    }

    # Best-effort monitoring report
    try:
        from aegis.shield import Shield

        shield_kwargs: dict = {}
        if args.config:
            shield_kwargs["policy"] = args.config
        shield = Shield(**shield_kwargs)
        sent = try_send_monitoring(
            shield,
            "send_compromise_report",
            compromised_agent_id=args.agent_id,
            source="operator",
        )
        output["monitoring_reported"] = sent
    except Exception:  # noqa: BLE001
        output["monitoring_reported"] = False

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        print(f"Agent '{args.agent_id}' marked as COMPROMISED (tier {tier})")


if __name__ == "__main__":
    main()
