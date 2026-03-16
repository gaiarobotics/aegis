#!/usr/bin/env python3
"""Save, restore, and list context snapshots for multi-turn recovery.

Snapshots are persisted to .aegis/snapshots/ so they survive across invocations.

Usage:
    echo '{"messages": [...]}' | python context_snapshot.py save --description "before risky op" --json
    python context_snapshot.py list --json
    python context_snapshot.py restore --snapshot-id "abc123" --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid


SNAPSHOT_DIR = os.path.join(".aegis", "snapshots")


def _ensure_dir() -> None:
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)


def _save(context: dict, description: str) -> dict:
    _ensure_dir()
    snapshot_id = uuid.uuid4().hex[:12]
    record = {
        "snapshot_id": snapshot_id,
        "timestamp": time.time(),
        "description": description,
        "context": context,
    }
    path = os.path.join(SNAPSHOT_DIR, f"{snapshot_id}.json")
    with open(path, "w") as f:
        json.dump(record, f)
    return {"success": True, "snapshot_id": snapshot_id, "timestamp": record["timestamp"], "description": description}


def _list_snapshots() -> list[dict]:
    _ensure_dir()
    snapshots = []
    for fname in sorted(os.listdir(SNAPSHOT_DIR)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(SNAPSHOT_DIR, fname)
        try:
            with open(path) as f:
                rec = json.load(f)
            snapshots.append({
                "snapshot_id": rec["snapshot_id"],
                "timestamp": rec["timestamp"],
                "description": rec.get("description", ""),
            })
        except Exception:  # noqa: BLE001
            continue
    return snapshots


def _restore(snapshot_id: str) -> dict:
    path = os.path.join(SNAPSHOT_DIR, f"{snapshot_id}.json")
    if not os.path.exists(path):
        return {"error": "snapshot_not_found", "snapshot_id": snapshot_id}
    with open(path) as f:
        rec = json.load(f)
    return {"success": True, "snapshot_id": snapshot_id, "context": rec["context"]}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS context snapshot manager")
    sub = parser.add_subparsers(dest="action")

    save_p = sub.add_parser("save", help="Save a context snapshot")
    save_p.add_argument("--description", default="", help="Snapshot description")
    save_p.add_argument("--json", action="store_true", dest="json_output")

    list_p = sub.add_parser("list", help="List saved snapshots")
    list_p.add_argument("--json", action="store_true", dest="json_output")

    restore_p = sub.add_parser("restore", help="Restore a snapshot")
    restore_p.add_argument("--snapshot-id", required=True, help="Snapshot ID to restore")
    restore_p.add_argument("--json", action="store_true", dest="json_output")

    args = parser.parse_args(argv)

    if not args.action:
        parser.print_help()
        return

    if args.action == "save":
        raw = sys.stdin.read().strip()
        if not raw:
            output = {"error": "no_input"}
        else:
            context = json.loads(raw)
            output = _save(context, args.description)
    elif args.action == "list":
        output = {"snapshots": _list_snapshots()}
    elif args.action == "restore":
        output = _restore(args.snapshot_id)
    else:
        output = {"error": "unknown_action"}

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        if args.action == "save":
            if "error" in output:
                print(f"Error: {output['error']}")
            else:
                print(f"Snapshot saved: {output['snapshot_id']}")
        elif args.action == "list":
            snapshots = output["snapshots"]
            if not snapshots:
                print("No snapshots saved")
            else:
                for s in snapshots:
                    print(f"  {s['snapshot_id']}  {s['description']}")
        elif args.action == "restore":
            if "error" in output:
                print(f"Error: {output['error']}")
            else:
                print(f"Snapshot restored: {output['snapshot_id']}")


if __name__ == "__main__":
    main()
