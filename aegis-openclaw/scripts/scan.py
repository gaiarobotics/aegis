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

    # Threat intel contagion check
    try:
        from aegis.core.remote_threat_intel import RemoteThreatIntel

        mon_cfg = shield.config.monitoring
        if mon_cfg.enabled and mon_cfg.service_url:
            intel = RemoteThreatIntel(
                service_url=mon_cfg.service_url,
                api_key=getattr(mon_cfg, "api_key", ""),
            )
            intel._poll()  # noqa: SLF001
            # Hash the input text for contagion matching
            try:
                from aegis.behavior.content_hash import SemanticHasher

                hasher = SemanticHasher()
                content_hash = hasher.hash(text)
                content_hash_hex = format(content_hash, "032x")
                is_suspicious, similarity = intel.check_hash(content_hash_hex)
                output["contagion_check"] = {
                    "suspicious": is_suspicious,
                    "similarity": round(similarity, 4),
                }
            except ImportError:
                pass
    except Exception:  # noqa: BLE001
        pass

    # NK cell assessment
    try:
        from aegis.identity.nkcell import AgentContext, NKCell

        agent_id = shield.config.agent_id or "self"
        clean_ratio = 1.0
        comm_count = 0
        if store is not None:
            trust_state = store.get_trust(agent_id)
            if trust_state is not None:
                total = max(trust_state.total_interactions, 1)
                clean_ratio = trust_state.clean_interactions / total
                comm_count = trust_state.total_interactions

        context = AgentContext(
            agent_id=agent_id,
            has_attestation=False,
            attestation_valid=False,
            attestation_expired=False,
            capabilities_within_scope=True,
            drift_sigma=0.0,
            clean_interaction_ratio=clean_ratio,
            scanner_threat_score=result.threat_score,
            communication_count=comm_count,
            purpose_hash_changed=False,
        )
        nkcell = NKCell(shield.config.identity.nkcell)
        verdict = nkcell.assess(context)
        output["nk_verdict"] = {
            "score": round(verdict.score, 4),
            "verdict": verdict.verdict,
            "action": verdict.recommended_action,
        }
    except Exception:  # noqa: BLE001
        pass

    # Monitoring telemetry
    try:
        from _helpers import try_send_monitoring

        nk_score = output.get("nk_verdict", {}).get("score", 0.0)
        nk_verd = output.get("nk_verdict", {}).get("verdict", "")
        output["monitoring_reported"] = try_send_monitoring(
            shield,
            "send_threat_event",
            threat_score=result.threat_score,
            is_threat=result.is_threat,
            scanner_match_count=len(result.details.get("matches", [])),
            nk_score=nk_score,
            nk_verdict=nk_verd,
        )
    except Exception:  # noqa: BLE001
        pass

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
