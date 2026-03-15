#!/usr/bin/env python3
"""Check if the remote killswitch is blocking inference.

Usage:
    python killswitch.py --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS killswitch check")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    from aegis.shield import InferenceBlockedError, Shield

    shield_kwargs: dict = {}
    if args.config:
        shield_kwargs["policy"] = args.config
    shield = Shield(**shield_kwargs)

    blocked = False
    reason = ""
    try:
        shield.check_killswitch()
    except InferenceBlockedError as exc:
        blocked = True
        reason = str(exc)

    output = {
        "blocked": blocked,
        "reason": reason,
        "is_blocked_any": shield.is_blocked,
    }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        if blocked:
            print(f"KILLSWITCH ACTIVE: {reason}")
        else:
            print("Killswitch: not active")
        if shield.is_blocked:
            print("Note: inference is blocked (killswitch/quarantine/integrity)")


if __name__ == "__main__":
    main()
