"""CLI entry point: ``python -m aegis_proxy``."""

from __future__ import annotations

import argparse
import logging
import sys

from aegis.shield import Shield

from aegis_proxy.config import ProxyConfig
from aegis_proxy.server import create_server


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aegis-proxy",
        description="AEGIS OpenAI-compatible proxy server",
    )
    parser.add_argument("--port", type=int, default=0, help="Listen port (default: 8419)")
    parser.add_argument("--host", default="", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--upstream-url", default="", help="Upstream LLM provider URL")
    parser.add_argument("--upstream-key", default="", help="Default upstream API key")
    parser.add_argument("--mode", default="", choices=["observe", "enforce", ""], help="AEGIS mode")
    parser.add_argument("--config", default="", dest="aegis_config", help="Path to aegis.yaml")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    config = ProxyConfig.from_env(
        upstream_url=args.upstream_url,
        upstream_key=args.upstream_key,
        port=args.port,
        host=args.host,
        mode=args.mode,
        aegis_config=args.aegis_config,
    )

    shield_kwargs: dict = {}
    if config.aegis_config:
        shield_kwargs["policy"] = config.aegis_config
    if config.aegis_mode:
        shield_kwargs["mode"] = config.aegis_mode

    shield = Shield(**shield_kwargs)

    server = create_server(config, shield)
    logging.getLogger(__name__).info(
        "AEGIS proxy listening on %s:%d (mode=%s, upstream=%s)",
        config.host,
        config.port,
        shield.mode,
        config.upstream_url or "(not configured)",
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
