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
    def test_private_reset_clears_counters(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="tool_call", read_write="write")
        for _ in range(5):
            tracker.record_action(req)
        tracker._reset()
        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 20
        assert remaining["max_posts_messages"] == 5
        assert remaining["max_external_http_writes"] == 10
        assert remaining["max_new_domains"] == 3

    def test_private_reset_clears_domains(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="http_write", read_write="write", target="example.com")
        tracker.record_action(req)
        tracker._reset()
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


class TestCheckAndRecord:
    def test_check_and_record_within_budget(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="tool_call", read_write="write")
        assert tracker.check_and_record(req) is True
        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 19

    def test_check_and_record_over_budget(self):
        cfg = AegisConfig()
        cfg.broker["budgets"]["max_write_tool_calls"] = 2
        tracker = BudgetTracker(config=cfg)
        req = _make_request(action_type="tool_call", read_write="write")
        assert tracker.check_and_record(req) is True
        assert tracker.check_and_record(req) is True
        # Now budget is exhausted
        assert tracker.check_and_record(req) is False
        # Counter should not have incremented on the denied call
        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 0

    def test_check_and_record_read_always_allowed(self):
        tracker = BudgetTracker()
        req = _make_request(action_type="tool_call", read_write="read")
        assert tracker.check_and_record(req) is True
        # No write counter affected
        remaining = tracker.remaining()
        assert remaining["max_write_tool_calls"] == 20

    def test_check_and_record_post_message_budget(self):
        cfg = AegisConfig()
        cfg.broker["budgets"]["max_posts_messages"] = 1
        tracker = BudgetTracker(config=cfg)
        req = _make_request(action_type="post_message", read_write="write")
        assert tracker.check_and_record(req) is True
        assert tracker.check_and_record(req) is False

    def test_check_and_record_http_write_new_domain(self):
        cfg = AegisConfig()
        cfg.broker["budgets"]["max_new_domains"] = 1
        tracker = BudgetTracker(config=cfg)
        req1 = _make_request(action_type="http_write", read_write="write", target="a.com")
        req2 = _make_request(action_type="http_write", read_write="write", target="b.com")
        assert tracker.check_and_record(req1) is True
        assert tracker.check_and_record(req2) is False

    def test_check_and_record_atomic_under_concurrency(self):
        """Atomic check+record should never exceed budget."""
        import threading

        cfg = AegisConfig()
        cfg.broker["budgets"]["max_write_tool_calls"] = 5
        tracker = BudgetTracker(config=cfg)
        barrier = threading.Barrier(10)
        results: list[bool] = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            req = _make_request(action_type="tool_call", read_write="write")
            ok = tracker.check_and_record(req)
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 5 should be True, 5 should be False
        assert results.count(True) == 5
        assert results.count(False) == 5
