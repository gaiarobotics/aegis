#!/usr/bin/env python3
"""Trigger time-based trust decay across all agents.

Usage:
    python decay.py --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS trust decay")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    from aegis.core.config import load_config

    from _helpers import build_store, json_output

    config = load_config(args.config) if args.config else load_config()
    store, err = build_store(config)
    if err is not None:
        json_output(err, args) if args.json_output else print(err.get("error", "error"))
        return

    store.apply_trust_decay()

    all_trust = store.get_all_trust()
    scores = {aid: ts.score for aid, ts in all_trust.items()}

    output = {
        "success": True,
        "agents_decayed": len(scores),
        "scores": scores,
    }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        print(f"Trust decay applied to {len(scores)} agent(s)")
        for aid, score in scores.items():
            print(f"  {aid}: {score:.1f}")


if __name__ == "__main__":
    main()
