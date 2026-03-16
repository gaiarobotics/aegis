#!/usr/bin/env python3
"""Check model file integrity for tampering.

Usage:
    python integrity_check.py --model-name "llama3" --provider "ollama" --json
    python integrity_check.py --model-name "gpt-4" --provider "openai" --model-path "/path/to/model" --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS model integrity check")
    parser.add_argument("--model-name", required=True, help="Model name")
    parser.add_argument("--provider", required=True, help="Model provider")
    parser.add_argument("--model-path", default=None, help="Path to model files")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    from aegis.integrity.monitor import ModelTamperedError
    from aegis.shield import Shield

    shield_kwargs: dict = {}
    if args.config:
        shield_kwargs["policy"] = args.config
    shield = Shield(**shield_kwargs)

    tampered = False
    detail = ""
    file_path = ""
    try:
        shield.check_model_integrity(
            args.model_name,
            args.provider,
            model_path=args.model_path,
        )
    except ModelTamperedError as exc:
        tampered = True
        detail = exc.detail if hasattr(exc, "detail") else str(exc)
        file_path = exc.file_path if hasattr(exc, "file_path") else ""

    output = {
        "tampered": tampered,
        "model_name": args.model_name,
        "provider": args.provider,
    }
    if tampered:
        output["detail"] = detail
        output["file_path"] = file_path

    if args.json_output:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    else:
        if tampered:
            print(f"TAMPERED: {args.model_name} ({detail})")
        else:
            print(f"Model integrity OK: {args.model_name}")


if __name__ == "__main__":
    main()
