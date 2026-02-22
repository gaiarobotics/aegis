#!/usr/bin/env python3
"""Show current AEGIS status: mode, enabled modules, integrity.

Usage:
    python status.py
    python status.py --json
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS status")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    parser.add_argument("--config", default=None, help="Path to aegis.yaml")
    args = parser.parse_args(argv)

    from aegis.core.config import load_config

    if args.config:
        config = load_config(args.config)
    else:
        config = load_config()

    enabled_modules = [name for name, enabled in config.modules.items() if enabled]

    status = {
        "mode": config.mode,
        "agent_id": config.agent_id,
        "modules_enabled": enabled_modules,
        "scanner_sensitivity": config.scanner.sensitivity,
        "scanner_confidence_threshold": config.scanner.confidence_threshold,
        "broker_posture": config.broker.default_posture,
    }

    if args.json_output:
        json.dump(status, sys.stdout)
        sys.stdout.write("\n")
    else:
        print("AEGIS Status")
        print("============")
        print(f"Mode:                 {status['mode']}")
        print(f"Agent ID:             {status['agent_id']}")
        print(f"Modules enabled:      {', '.join(enabled_modules)}")
        print(f"Scanner sensitivity:  {status['scanner_sensitivity']}")
        print(f"Confidence threshold: {status['scanner_confidence_threshold']}")
        print(f"Broker posture:       {status['broker_posture']}")


if __name__ == "__main__":
    main()
