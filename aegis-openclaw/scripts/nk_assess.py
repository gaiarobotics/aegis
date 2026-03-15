#!/usr/bin/env python3
"""Run an NK cell immune assessment on an agent.

Usage:
    python nk_assess.py --agent-id "agent-x" --json
    python nk_assess.py --agent-id "agent-x" --scanner-threat-score 0.8 --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS NK cell assessment")
    parser.add_argument("--agent-id", required=True, help="Agent to assess")
    parser.add_argument("--scanner-threat-score", type=float, default=0.0, help="Scanner threat score override")
    parser.add_argument("--drift-sigma", type=float, default=0.0, help="Behavioral drift sigma")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    from aegis.core.config import load_config
    from aegis.identity.nkcell import AgentContext, NKCell

    from _helpers import build_store

    config = load_config(args.config) if args.config else load_config()
    store, err = build_store(config)

    # Build context from available state data
    clean_ratio = 1.0
    comm_count = 0
    if store is not None:
        trust = store.get_trust(args.agent_id)
        if trust is not None:
            total = max(trust.total_interactions, 1)
            clean_ratio = trust.clean_interactions / total
            comm_count = trust.total_interactions

    context = AgentContext(
        agent_id=args.agent_id,
        has_attestation=False,
        attestation_valid=False,
        attestation_expired=False,
        capabilities_within_scope=True,
        drift_sigma=args.drift_sigma,
        clean_interaction_ratio=clean_ratio,
        scanner_threat_score=args.scanner_threat_score,
        communication_count=comm_count,
        purpose_hash_changed=False,
    )

    nkcell = NKCell(config.identity.nkcell)
    verdict = nkcell.assess(context)

    output = {
        "agent_id": args.agent_id,
        "score": round(verdict.score, 4),
        "verdict": verdict.verdict,
        "recommended_action": verdict.recommended_action,
        "activating_signals": {k: round(v, 4) for k, v in verdict.activating_signals.items()},
        "inhibitory_signals": {k: round(v, 4) for k, v in verdict.inhibitory_signals.items()},
    }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        print(f"NK Assessment: {args.agent_id}")
        print(f"  Verdict: {verdict.verdict} (score={verdict.score:.2f})")
        print(f"  Action:  {verdict.recommended_action}")
        if verdict.activating_signals:
            print(f"  Activating: {verdict.activating_signals}")
        if verdict.inhibitory_signals:
            print(f"  Inhibitory: {verdict.inhibitory_signals}")


if __name__ == "__main__":
    main()
