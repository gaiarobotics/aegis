#!/usr/bin/env python3
"""Check current quarantine status.

Usage:
    python quarantine_check.py --json
    python quarantine_check.py
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS quarantine status")
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

    q = store.get_quarantine()
    output = {
        "active": q.active,
        "reason": q.reason,
        "severity": q.severity,
        "entered_at": q.entered_at,
        "escalated": q.escalated,
        "escalation_reason": q.escalation_reason,
    }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        if q.active:
            entered = datetime.fromtimestamp(q.entered_at, tz=timezone.utc).isoformat() if q.entered_at else "unknown"
            print(f"Quarantine:   ACTIVE")
            print(f"Reason:       {q.reason}")
            print(f"Severity:     {q.severity}")
            print(f"Entered at:   {entered}")
            if q.escalated:
                print(f"Escalated:    yes — {q.escalation_reason}")
        else:
            print("Quarantine:   none")


if __name__ == "__main__":
    main()
