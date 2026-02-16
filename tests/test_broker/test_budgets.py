"""Tests for broker budget tracking."""

import time

from aegis.broker.actions import ActionRequest
from aegis.broker.budgets import BudgetTracker
from aegis.core.config import AegisConfig


def _make_request(
    action_type: str = "tool_call",
    read_write: str = "write",
    target: str = "some_tool",
    req_id: str = "1",
) -> ActionRequest:
    return ActionRequest(
        id=req_id,
        timestamp=time.time(),
        source_provenance="trusted.system",
        action_type=action_type,
        read_write=read_write,
        target=target,
        args={},
        risk_hints={},
    )


class TestBudgetTrackerDefaults:
    def test_default_limits(self):
        tracker = BudgetTracker()
        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 20
        assert remaining["max_posts_messages"] == 5
        assert remaining["max_external_http_writes"] == 10
        assert remaining["max_new_domains"] == 3

    def test_custom_config_limits(self):
        cfg = AegisConfig()
        cfg.broker["budgets"]["max_write_tool_calls"] = 50
        cfg.broker["budgets"]["max_posts_messages"] = 10
        tracker = BudgetTracker(config=cfg)
        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 50
        assert remaining["max_posts_messages"] == 10


class TestBudgetCheckAndRecord:
    def test_check_budget_within_limit(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="tool_call", read_write="write")
        assert tracker.check_budget(req) is True

    def test_check_budget_over_limit(self):
        cfg = AegisConfig()
        cfg.broker["budgets"]["max_write_tool_calls"] = 2
        tracker = BudgetTracker(config=cfg)
        req = _make_request(action_type="tool_call", read_write="write")
        tracker.record_action(req)
        tracker.record_action(req)
        assert tracker.check_budget(req) is False

    def test_record_decrements_remaining(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="tool_call", read_write="write")
        tracker.record_action(req)
        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 19

    def test_read_actions_not_counted_as_writes(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="tool_call", read_write="read")
        tracker.record_action(req)
        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 20

    def test_post_message_budget(self):
        cfg = AegisConfig()
        cfg.broker["budgets"]["max_posts_messages"] = 2
        tracker = BudgetTracker(config=cfg)
        req = _make_request(action_type="post_message", read_write="write")
        tracker.record_action(req)
        tracker.record_action(req)
        assert tracker.check_budget(req) is False

    def test_http_write_budget(self):
        cfg = AegisConfig()
        cfg.broker["budgets"]["max_external_http_writes"] = 1
        tracker = BudgetTracker(config=cfg)
        req = _make_request(action_type="http_write", read_write="write")
        tracker.record_action(req)
        assert tracker.check_budget(req) is False


class TestNewDomainTracking:
    def test_new_domain_counted(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="http_write", read_write="write", target="example.com")
        tracker.record_action(req)
        remaining = tracker.remaining()
        assert remaining["max_new_domains"] == 2

    def test_same_domain_not_counted_twice(self):
        tracker = BudgetTracker()
        req1 = _make_request(action_type="http_write", read_write="write", target="example.com")
        req2 = _make_request(action_type="http_write", read_write="write", target="example.com")
        tracker.record_action(req1)
        tracker.record_action(req2)
        remaining = tracker.remaining()
        assert remaining["max_new_domains"] == 2

    def test_new_domain_burst_exceeds_limit(self):
        cfg = AegisConfig()
        cfg.broker["budgets"]["max_new_domains"] = 2
        tracker = BudgetTracker(config=cfg)

        for i, domain in enumerate(["a.com", "b.com", "c.com"]):
            req = _make_request(
                action_type="http_write",
                read_write="write",
                target=domain,
                req_id=str(i),
            )
            tracker.record_action(req)

        req = _make_request(action_type="http_write", read_write="write", target="d.com")
        assert tracker.check_budget(req) is False


class TestBudgetReset:
    def test_reset_clears_counters(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="tool_call", read_write="write")
        for _ in range(5):
            tracker.record_action(req)
        tracker.reset()
        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 20
        assert remaining["max_posts_messages"] == 5
        assert remaining["max_external_http_writes"] == 10
        assert remaining["max_new_domains"] == 3

    def test_reset_clears_domains(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="http_write", read_write="write", target="example.com")
        tracker.record_action(req)
        tracker.reset()
        remaining = tracker.remaining()
        assert remaining["max_new_domains"] == 3


class TestBudgetThreadSafety:
    def test_concurrent_record_actions(self):
        """Basic thread-safety check: concurrent records should not lose counts."""
        import threading

        tracker = BudgetTracker()
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            req = _make_request(action_type="tool_call", read_write="write")
            tracker.record_action(req)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 10  # 20 - 10
