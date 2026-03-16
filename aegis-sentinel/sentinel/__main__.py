"""CLI entry point — ``python -m sentinel``."""

from __future__ import annotations

import argparse
import logging
import signal
import time

from sentinel.config import SentinelConfig
from sentinel.sentinel import Sentinel


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="aegis-sentinel",
        description="AEGIS Sentinel — passive Moltbook compromise detector",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="",
        help="Path to sentinel YAML config file",
    )
    parser.add_argument(
        "--agent-id",
        type=str,
        default="sentinel",
        help="Agent ID for this sentinel instance",
    )
    parser.add_argument(
        "--operator-id",
        type=str,
        default="",
        help="Operator ID",
    )
    parser.add_argument(
        "--monitor-url",
        type=str,
        default="",
        help="AEGIS monitor service URL",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=30.0,
        help="Polling interval in seconds (default: 30)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger = logging.getLogger("aegis-sentinel")

    config = SentinelConfig(
        agent_id=args.agent_id,
        operator_id=args.operator_id,
        monitor_url=args.monitor_url,
        poll_interval_seconds=args.poll_interval,
        profile_path=args.config,
    )

    _sentinel = Sentinel(config=config)

    shutdown = False

    def _handle_signal(signum: int, frame: object) -> None:
        nonlocal shutdown
        logger.info("Received signal %d, shutting down…", signum)
        shutdown = True

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info(
        "Sentinel started: agent_id=%s, mode=%s, poll_interval=%.1fs",
        config.agent_id,
        config.coverage_mode.value,
        config.poll_interval_seconds,
    )

    while not shutdown:
        # In a real deployment this would call the Moltbook API.
        # The event loop is a polling loop: fetch -> process -> sleep.
        #
        # posts = moltbook_client.fetch_new_posts(sentinel._coverage.get_targets())
        # sentinel.process_posts(posts)
        logger.debug("Poll cycle — waiting for Moltbook API integration")
        time.sleep(config.poll_interval_seconds)

    logger.info("Sentinel shut down cleanly.")


if __name__ == "__main__":
    main()
