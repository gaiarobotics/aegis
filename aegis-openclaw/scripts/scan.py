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

    output = {
        "threat_score": result.threat_score,
        "is_threat": result.is_threat,
        "details": result.details,
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
