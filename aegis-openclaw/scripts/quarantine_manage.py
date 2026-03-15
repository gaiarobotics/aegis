#!/usr/bin/env python3
"""Enter, exit, or escalate quarantine.

Usage:
    python quarantine_manage.py enter --reason "hostile NK verdict" --severity high --json
    python quarantine_manage.py exit --exit-token "abc123" --json
    python quarantine_manage.py escalate --reason "repeated violations" --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS quarantine manager")
    sub = parser.add_subparsers(dest="action")

    enter_p = sub.add_parser("enter", help="Enter quarantine")
    enter_p.add_argument("--reason", required=True, help="Quarantine reason")
    enter_p.add_argument("--severity", default="high", help="Severity (default: high)")
    enter_p.add_argument("--json", action="store_true", dest="json_output")
    enter_p.add_argument("--config", default=None)

    exit_p = sub.add_parser("exit", help="Exit quarantine")
    exit_p.add_argument("--exit-token", required=True, help="Operator exit token")
    exit_p.add_argument("--json", action="store_true", dest="json_output")
    exit_p.add_argument("--config", default=None)

    esc_p = sub.add_parser("escalate", help="Escalate quarantine")
    esc_p.add_argument("--reason", required=True, help="Escalation reason")
    esc_p.add_argument("--json", action="store_true", dest="json_output")
    esc_p.add_argument("--config", default=None)

    args = parser.parse_args(argv)

    if not args.action:
        parser.print_help()
        return

    from aegis.core.config import load_config

    from _helpers import build_store, json_output

    config = load_config(args.config) if args.config else load_config()
    store, err = build_store(config)
    if err is not None:
        json_output(err, args) if args.json_output else print(err.get("error", "error"))
        return

    if args.action == "enter":
        store.enter_quarantine(args.reason, args.severity)
    elif args.action == "exit":
        expected = os.environ.get("AEGIS_EXIT_TOKEN", "")
        if not expected or args.exit_token != expected:
            output = {"error": "invalid_exit_token"}
            json_output(output, args) if args.json_output else print("Invalid exit token")
            return
        store.exit_quarantine(args.exit_token)
    elif args.action == "escalate":
        store.escalate_quarantine(args.reason)

    q = store.get_quarantine()
    output = {
        "success": True,
        "action": args.action,
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
            print(f"Quarantine: ACTIVE (severity={q.severity}, reason={q.reason})")
            if q.escalated:
                print(f"Escalated: {q.escalation_reason}")
        else:
            print("Quarantine: none")


if __name__ == "__main__":
    main()
