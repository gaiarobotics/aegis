"""Write budgets and rate limiting for the AEGIS Broker."""

from __future__ import annotations

import threading

from aegis.broker.actions import ActionRequest
from aegis.core.config import AegisConfig


class BudgetTracker:
    """Thread-safe tracker for action budgets and rate limits."""

    def __init__(self, config: AegisConfig | None = None) -> None:
        if config is None:
            config = AegisConfig()

        budgets = config.broker.get("budgets", {})
        self._limits: dict[str, int] = {
            "max_write_tool_calls": budgets.get("max_write_tool_calls", 20),
            "max_posts_messages": budgets.get("max_posts_messages", 5),
            "max_external_http_writes": budgets.get("max_external_http_writes", 10),
            "max_new_domains": budgets.get("max_new_domains", 3),
        }
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {
            "max_write_tool_calls": 0,
            "max_posts_messages": 0,
            "max_external_http_writes": 0,
        }
        self._seen_domains: set[str] = set()

    def check_budget(self, action: ActionRequest) -> bool:
        """Return True if the action is within budget, False otherwise."""
        if action.read_write != "write":
            return True

        with self._lock:
            # Check write tool calls
            if self._counters["max_write_tool_calls"] >= self._limits["max_write_tool_calls"]:
                return False

            # Check post message budget
            if action.action_type == "post_message":
                if self._counters["max_posts_messages"] >= self._limits["max_posts_messages"]:
                    return False

            # Check external HTTP write budget
            if action.action_type == "http_write":
                if (
                    self._counters["max_external_http_writes"]
                    >= self._limits["max_external_http_writes"]
                ):
                    return False

                # Check new domain budget
                if action.target not in self._seen_domains:
                    if len(self._seen_domains) >= self._limits["max_new_domains"]:
                        return False

            return True

    def check_and_record(self, action: ActionRequest) -> bool:
        """Atomically check budget and record the action if within budget.

        Returns True if the action was within budget and recorded,
        False if the budget was exceeded (action is *not* recorded).
        """
        if action.read_write != "write":
            return True

        with self._lock:
            # --- budget check (same logic as check_budget) ---
            if self._counters["max_write_tool_calls"] >= self._limits["max_write_tool_calls"]:
                return False

            if action.action_type == "post_message":
                if self._counters["max_posts_messages"] >= self._limits["max_posts_messages"]:
                    return False

            if action.action_type == "http_write":
                if (
                    self._counters["max_external_http_writes"]
                    >= self._limits["max_external_http_writes"]
                ):
                    return False
                if action.target not in self._seen_domains:
                    if len(self._seen_domains) >= self._limits["max_new_domains"]:
                        return False

            # --- record (same logic as record_action) ---
            self._counters["max_write_tool_calls"] += 1

            if action.action_type == "post_message":
                self._counters["max_posts_messages"] += 1

            if action.action_type == "http_write":
                self._counters["max_external_http_writes"] += 1
                self._seen_domains.add(action.target)

            return True

    def record_action(self, action: ActionRequest) -> None:
        """Record an action, incrementing the appropriate counters."""
        if action.read_write != "write":
            return

        with self._lock:
            self._counters["max_write_tool_calls"] += 1

            if action.action_type == "post_message":
                self._counters["max_posts_messages"] += 1

            if action.action_type == "http_write":
                self._counters["max_external_http_writes"] += 1
                self._seen_domains.add(action.target)

    def remaining(self) -> dict[str, int]:
        """Return remaining budget for each limit."""
        with self._lock:
            return {
                "max_write_tool_calls": (
                    self._limits["max_write_tool_calls"]
                    - self._counters["max_write_tool_calls"]
                ),
                "max_posts_messages": (
                    self._limits["max_posts_messages"]
                    - self._counters["max_posts_messages"]
                ),
                "max_external_http_writes": (
                    self._limits["max_external_http_writes"]
                    - self._counters["max_external_http_writes"]
                ),
                "max_new_domains": (
                    self._limits["max_new_domains"]
                    - len(self._seen_domains)
                ),
            }

    def _reset(self) -> None:
        """Clear all counters and tracked domains."""
        with self._lock:
            for key in self._counters:
                self._counters[key] = 0
            self._seen_domains.clear()

    @property
    def denied_write_count(self) -> int:
        """Get current write tool call count (useful for quarantine triggers)."""
        with self._lock:
            return self._counters["max_write_tool_calls"]

    @property
    def new_domain_count(self) -> int:
        """Get number of unique domains seen."""
        with self._lock:
            return len(self._seen_domains)
