#!/usr/bin/env python3
"""Sanitize output text using AEGIS Shield.

Usage:
    echo "[SYSTEM] secret" | python sanitize.py --json
    python sanitize.py --text "[SYSTEM] secret" --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS output sanitizer")
    parser.add_argument("--text", default=None, help="Text to sanitize (reads stdin if omitted)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    text = args.text
    if text is None:
        text = sys.stdin.read()

    from aegis.shield import Shield

    shield_kwargs: dict = {}
    if args.config:
        shield_kwargs["policy"] = args.config
    shield = Shield(**shield_kwargs)

    result = shield.sanitize_output(text)

    # Record behavior event in persistent state
    behavior_recorded = False
    store = shield.state_store
    if store is not None:
        try:
            agent_id = shield.config.agent_id or "self"
            store.record_behavior_event(
                agent_id=agent_id,
                output_length=len(text),
                tool_used=None,
                content_type="message",
            )
            behavior_recorded = True
        except Exception:  # noqa: BLE001
            pass

    output = {
        "cleaned_text": result.cleaned_text,
        "modifications": result.modifications,
        "was_modified": len(result.modifications) > 0,
        "behavior_event_recorded": behavior_recorded,
    }

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        print(f"cleaned_text: {result.cleaned_text}")
        if result.modifications:
            print(f"modifications: {result.modifications}")


if __name__ == "__main__":
    main()
