#!/usr/bin/env python3
"""Record a vouch from one agent to another, granting a trust bonus.

Usage:
    python vouch.py --voucher-id "agent-a" --target-id "agent-b" --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS vouch recorder")
    parser.add_argument("--voucher-id", required=True, help="Agent providing the vouch")
    parser.add_argument("--target-id", required=True, help="Agent receiving the vouch")
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

    store.record_vouch(args.voucher_id, args.target_id)

    trust = store.get_trust(args.target_id)
    tier = store.get_trust_tier(args.target_id)

    output = {
        "success": True,
        "voucher_id": args.voucher_id,
        "target_id": args.target_id,
        "target_tier": tier,
        "target_score": trust.score if trust else 0.0,
        "vouchers": trust.vouchers if trust else [],
    }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        print(f"Vouch recorded: {args.voucher_id} -> {args.target_id}")
        print(f"Target tier: {tier}, score: {trust.score if trust else 0.0}")


if __name__ == "__main__":
    main()
