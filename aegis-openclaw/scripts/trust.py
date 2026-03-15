#!/usr/bin/env python3
"""Query trust tier and full trust state for an agent.

Usage:
    python trust.py --agent-id "agent-name" --json
    python trust.py --agent-id "agent-name"
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS trust query")
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

    tier = store.get_trust_tier(args.agent_id)
    trust = store.get_trust(args.agent_id)

    if trust is None:
        output: dict = {
            "agent_id": args.agent_id,
            "status": "no_data",
            "tier": 0,
        }
    else:
        output = {
            "agent_id": trust.agent_id,
            "tier": tier,
            "score": trust.score,
            "earned_score": trust.earned_score,
            "bonus_score": trust.bonus_score,
            "clean_interactions": trust.clean_interactions,
            "total_interactions": trust.total_interactions,
            "anomaly_count": trust.anomaly_count,
            "compromised": trust.compromised,
            "vouchers": trust.vouchers,
        }

    tier_names = {0: "untrusted", 1: "provisional", 2: "established", 3: "vouched"}

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        if trust is None:
            print(f"No trust data for agent '{args.agent_id}' (tier 0: untrusted)")
        else:
            print(f"Agent:              {trust.agent_id}")
            print(f"Trust tier:         {tier} ({tier_names.get(tier, 'unknown')})")
            print(f"Score:              {trust.score:.1f} (earned={trust.earned_score:.1f} bonus={trust.bonus_score:.1f})")
            print(f"Interactions:       {trust.clean_interactions}/{trust.total_interactions} clean")
            print(f"Anomalies:          {trust.anomaly_count}")
            print(f"Compromised:        {trust.compromised}")
            if trust.vouchers:
                print(f"Vouchers:           {', '.join(trust.vouchers)}")


if __name__ == "__main__":
    main()
