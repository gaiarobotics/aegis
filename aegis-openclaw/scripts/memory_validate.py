#!/usr/bin/env python3
"""Validate a proposed memory write before persisting it.

Usage:
    echo '{"key":"foo","value":"bar","category":"fact","provenance":"user"}' | python memory_validate.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS memory write validator")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    raw = sys.stdin.read().strip()
    if not raw:
        output = {"error": "no_input", "message": "Expected JSON on stdin"}
        if args.json_output:
            json.dump(output, sys.stdout)
            sys.stdout.write("\n")
        else:
            print("Error: no input on stdin")
        return

    data = json.loads(raw)

    from aegis.memory.guard import MemoryEntry, MemoryGuard
    from aegis.shield import Shield

    shield_kwargs: dict = {}
    if args.config:
        shield_kwargs["policy"] = args.config
    shield = Shield(**shield_kwargs)

    entry = MemoryEntry(
        key=data["key"],
        value=data["value"],
        category=data.get("category", "fact"),
        provenance=data.get("provenance", "unknown"),
        ttl=data.get("ttl"),
        timestamp=data.get("timestamp", time.time()),
        entry_id=data.get("entry_id", str(uuid.uuid4())),
    )

    guard = MemoryGuard(config=shield.config.memory, scanner=shield.scanner)
    result = guard.validate_write(entry)

    output = {
        "allowed": result.allowed,
        "reason": result.reason,
        "sanitized_value": result.sanitized_value,
    }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        status = "ALLOWED" if result.allowed else "DENIED"
        print(f"{status}: {result.reason}")
        if result.sanitized_value is not None:
            print(f"Sanitized value: {result.sanitized_value}")


if __name__ == "__main__":
    main()
