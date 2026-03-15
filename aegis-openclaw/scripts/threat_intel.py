#!/usr/bin/env python3
"""Query the threat intelligence feed for compromised agents and content hashes.

Usage:
    python threat_intel.py --check-agent "agent-x" --json
    python threat_intel.py --check-hash "abcdef0123456789" --json
    python threat_intel.py --status --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS threat intelligence query")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-agent", default=None, help="Check if agent is compromised")
    group.add_argument("--check-hash", default=None, help="Check content hash against known threats")
    group.add_argument("--status", action="store_true", help="Show feed status")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    from aegis.core.config import load_config

    config = load_config(args.config) if args.config else load_config()
    mon_cfg = config.monitoring

    if not mon_cfg.enabled or not mon_cfg.service_url:
        output = {"error": "monitoring_disabled", "message": "Threat intel requires monitoring.enabled=true"}
        if args.json_output:
            json.dump(output, sys.stdout)
            sys.stdout.write("\n")
        else:
            print("Monitoring is disabled — threat intel unavailable")
        return

    from aegis.core.remote_threat_intel import RemoteThreatIntel

    intel = RemoteThreatIntel(
        service_url=mon_cfg.service_url,
        api_key=getattr(mon_cfg, "api_key", ""),
    )

    feed_reachable = False
    try:
        intel._poll()  # noqa: SLF001 — synchronous one-shot fetch
        feed_reachable = True
    except Exception:  # noqa: BLE001
        pass

    if args.check_agent:
        compromised = intel.is_agent_compromised(args.check_agent)
        quarantined = intel.is_agent_quarantined(args.check_agent)
        output = {
            "agent_id": args.check_agent,
            "compromised": compromised,
            "quarantined": quarantined,
            "feed_reachable": feed_reachable,
        }
    elif args.check_hash:
        is_suspicious, similarity = intel.check_hash(args.check_hash)
        output = {
            "hash": args.check_hash,
            "suspicious": is_suspicious,
            "similarity": round(similarity, 4),
            "feed_reachable": feed_reachable,
        }
    else:  # --status
        compromised_hashes = intel.get_compromised_hashes()
        output = {
            "feed_reachable": feed_reachable,
            "compromised_agents_count": len(intel._compromised_agents),  # noqa: SLF001
            "compromised_hashes_count": len(compromised_hashes),
        }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        if args.check_agent:
            status = "COMPROMISED" if output["compromised"] else ("QUARANTINED" if output["quarantined"] else "clean")
            print(f"Agent {args.check_agent}: {status}")
        elif args.check_hash:
            status = f"SUSPICIOUS (similarity={output['similarity']})" if output["suspicious"] else "clean"
            print(f"Hash check: {status}")
        else:
            print(f"Feed: {'connected' if feed_reachable else 'disconnected'}")
            print(f"Known compromised agents: {output['compromised_agents_count']}")
            print(f"Known compromised hashes: {output['compromised_hashes_count']}")


if __name__ == "__main__":
    main()
