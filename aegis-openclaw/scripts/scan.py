#!/usr/bin/env python3
"""Scan input text for threats using AEGIS Shield.

Usage:
    echo "some text" | python scan.py --json
    python scan.py --text "some text" --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS input scanner")
    parser.add_argument("--text", default=None, help="Text to scan (reads stdin if omitted)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--mode", default="enforce", help="AEGIS mode (observe/enforce)")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    text = args.text
    if text is None:
        text = sys.stdin.read()

    from aegis.shield import Shield

    shield_kwargs: dict = {"mode": args.mode}
    if args.config:
        shield_kwargs["policy"] = args.config
    shield = Shield(**shield_kwargs)

    result = shield.scan_input(text)

    # Record trust interaction in persistent state
    trust_recorded = False
    store = shield.state_store
    if store is not None:
        try:
            agent_id = shield.config.agent_id or "self"
            store.record_trust_interaction(
                agent_id=agent_id,
                clean=not result.is_threat,
                anomaly=result.is_threat,
            )
            trust_recorded = True
        except Exception:  # noqa: BLE001
            pass

    output = {
        "threat_score": result.threat_score,
        "is_threat": result.is_threat,
        "details": result.details,
        "trust_interaction_recorded": trust_recorded,
    }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        print(f"threat_score: {result.threat_score}")
        print(f"is_threat: {result.is_threat}")
        if result.details:
            print(f"details: {result.details}")


if __name__ == "__main__":
    main()
