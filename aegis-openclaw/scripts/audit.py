#!/usr/bin/env python3
"""Read AEGIS telemetry log and print an aggregated audit report.

Usage:
    python audit.py
    python audit.py --log-path /tmp/aegis/telemetry.jsonl --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS telemetry audit")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--log-path", default=None, help="Path to telemetry log")
    args = parser.parse_args(argv)

    # Discover log path
    log_path = args.log_path
    if log_path is None:
        from aegis.core.config import load_config

        config = load_config()
        log_path = config.telemetry.local_log_path

    path = Path(log_path)
    if not path.exists():
        output = {
            "status": "no_log",
            "message": f"No telemetry log found at {log_path}",
            "events": 0,
        }
        if args.json_output:
            json.dump(output, sys.stdout)
            sys.stdout.write("\n")
        else:
            print(f"No telemetry log found at {log_path}")
        return

    # Parse events
    events: list[dict] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    # Aggregate
    event_types = Counter(e.get("event", "unknown") for e in events)
    threats = [e for e in events if e.get("is_threat")]
    blocked = [e for e in events if e.get("event") == "action_decision" and e.get("decision") == "deny"]

    report = {
        "total_events": len(events),
        "event_types": dict(event_types),
        "threats_detected": len(threats),
        "actions_blocked": len(blocked),
    }

    if args.json_output:
        json.dump(report, sys.stdout)
        sys.stdout.write("\n")
    else:
        print(f"AEGIS Audit Report")
        print(f"==================")
        print(f"Total events:     {report['total_events']}")
        print(f"Threats detected: {report['threats_detected']}")
        print(f"Actions blocked:  {report['actions_blocked']}")
        print(f"\nEvent breakdown:")
        for event_type, count in sorted(event_types.items()):
            print(f"  {event_type}: {count}")


if __name__ == "__main__":
    main()
