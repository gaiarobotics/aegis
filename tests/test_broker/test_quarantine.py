"""Tests for broker quarantine mode."""

from aegis.broker.quarantine import QuarantineManager
from aegis.core.config import AegisConfig


class TestQuarantineBasics:
    def test_not_quarantined_by_default(self):
        qm = QuarantineManager()
        assert qm.is_quarantined() is False

    def test_enter_quarantine(self):
        qm = QuarantineManager()
        qm.enter_quarantine("test reason")
        assert qm.is_quarantined() is True

    def test_exit_quarantine(self):
        qm = QuarantineManager()
        qm.enter_quarantine("test reason")
        qm.exit_quarantine()
        assert qm.is_quarantined() is False

    def test_reason_stored(self):
        qm = QuarantineManager()
        qm.enter_quarantine("suspicious activity")
        assert qm.reason == "suspicious activity"

    def test_reason_cleared_on_exit(self):
        qm = QuarantineManager()
        qm.enter_quarantine("suspicious activity")
        qm.exit_quarantine()
        assert qm.reason is None


class TestQuarantineTriggers:
    def test_trigger_on_denied_writes(self):
        qm = QuarantineManager()
        qm.check_triggers(denied_count=5, new_domain_count=0)
        assert qm.is_quarantined() is True

    def test_no_trigger_below_denied_threshold(self):
        qm = QuarantineManager()
        qm.check_triggers(denied_count=4, new_domain_count=0)
        assert qm.is_quarantined() is False

    def test_trigger_on_new_domain_burst(self):
        qm = QuarantineManager()
        qm.check_triggers(denied_count=0, new_domain_count=3)
        assert qm.is_quarantined() is True

    def test_no_trigger_below_domain_threshold(self):
        qm = QuarantineManager()
        qm.check_triggers(denied_count=0, new_domain_count=2)
        assert qm.is_quarantined() is False

    def test_trigger_on_drift_score(self):
        qm = QuarantineManager()
        qm.check_triggers(denied_count=0, new_domain_count=0, drift_score=3.0)
        assert qm.is_quarantined() is True

    def test_no_trigger_below_drift_threshold(self):
        qm = QuarantineManager()
        qm.check_triggers(denied_count=0, new_domain_count=0, drift_score=2.9)
        assert qm.is_quarantined() is False

    def test_drift_score_none_no_trigger(self):
        qm = QuarantineManager()
        qm.check_triggers(denied_count=0, new_domain_count=0, drift_score=None)
        assert qm.is_quarantined() is False


class TestQuarantineCustomThresholds:
    def test_custom_denied_writes_threshold(self):
        cfg = AegisConfig()
        cfg.broker["quarantine_triggers"]["repeated_denied_writes"] = 10
        qm = QuarantineManager(config=cfg)
        qm.check_triggers(denied_count=9, new_domain_count=0)
        assert qm.is_quarantined() is False
        qm.check_triggers(denied_count=10, new_domain_count=0)
        assert qm.is_quarantined() is True

    def test_custom_domain_burst_threshold(self):
        cfg = AegisConfig()
        cfg.broker["quarantine_triggers"]["new_domain_burst"] = 5
        qm = QuarantineManager(config=cfg)
        qm.check_triggers(denied_count=0, new_domain_count=4)
        assert qm.is_quarantined() is False
        qm.check_triggers(denied_count=0, new_domain_count=5)
        assert qm.is_quarantined() is True

    def test_custom_drift_threshold(self):
        cfg = AegisConfig()
        cfg.broker["quarantine_triggers"]["drift_score_threshold"] = 5.0
        qm = QuarantineManager(config=cfg)
        qm.check_triggers(denied_count=0, new_domain_count=0, drift_score=4.9)
        assert qm.is_quarantined() is False
        qm.check_triggers(denied_count=0, new_domain_count=0, drift_score=5.0)
        assert qm.is_quarantined() is True


class TestQuarantineThreadSafety:
    def test_concurrent_enter_exit(self):
        """Basic thread-safety: concurrent enter/exit should not crash."""
        import threading

        qm = QuarantineManager()
        barrier = threading.Barrier(10)

        def worker(i):
            barrier.wait()
            if i % 2 == 0:
                qm.enter_quarantine(f"reason-{i}")
            else:
                qm.exit_quarantine()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Just check it doesn't crash; final state depends on ordering
        assert isinstance(qm.is_quarantined(), bool)
