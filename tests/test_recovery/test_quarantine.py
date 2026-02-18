"""Tests for RecoveryQuarantine."""

import threading
from unittest.mock import MagicMock

import pytest

from aegis.recovery.quarantine import RecoveryQuarantine


class TestRecoveryQuarantine:
    """Tests for the RecoveryQuarantine class."""

    def test_enter_exit(self):
        """Test entering and exiting quarantine."""
        q = RecoveryQuarantine()
        q.enter(reason="test reason")
        assert q.is_quarantined() is True
        assert q.get_reason() == "test reason"

        q.exit()
        assert q.is_quarantined() is False
        assert q.get_reason() is None

    def test_is_quarantined(self):
        """Test is_quarantined returns correct state."""
        q = RecoveryQuarantine()
        assert q.is_quarantined() is False

        q.enter(reason="checking state")
        assert q.is_quarantined() is True

        q.exit()
        assert q.is_quarantined() is False

    def test_auto_quarantine_hostile_nk(self):
        """Test auto_quarantine triggers on hostile NK verdict."""
        q = RecoveryQuarantine()

        nk_verdict = MagicMock()
        nk_verdict.verdict = "hostile"

        result = q.auto_quarantine(nk_verdict=nk_verdict)
        assert result is True
        assert q.is_quarantined() is True
        assert "hostile" in q.get_reason().lower()

    def test_auto_quarantine_drift(self):
        """Test auto_quarantine triggers on significant drift."""
        q = RecoveryQuarantine()

        drift_result = MagicMock()
        drift_result.is_drifting = True
        drift_result.max_sigma = 4.0

        result = q.auto_quarantine(drift_result=drift_result)
        assert result is True
        assert q.is_quarantined() is True
        assert "drift" in q.get_reason().lower()

    def test_no_quarantine_normal(self):
        """Test auto_quarantine does not trigger on normal conditions."""
        q = RecoveryQuarantine()

        # Non-hostile verdict
        nk_verdict = MagicMock()
        nk_verdict.verdict = "benign"
        result = q.auto_quarantine(nk_verdict=nk_verdict)
        assert result is False
        assert q.is_quarantined() is False

        # Not drifting
        drift_result = MagicMock()
        drift_result.is_drifting = False
        drift_result.max_sigma = 1.0
        result = q.auto_quarantine(drift_result=drift_result)
        assert result is False
        assert q.is_quarantined() is False

        # Drifting but below threshold
        drift_result2 = MagicMock()
        drift_result2.is_drifting = True
        drift_result2.max_sigma = 2.0
        result = q.auto_quarantine(drift_result=drift_result2)
        assert result is False
        assert q.is_quarantined() is False

    def test_thread_safety(self):
        """Test that quarantine operations are thread-safe."""
        q = RecoveryQuarantine()
        errors = []

        def enter_exit():
            try:
                for _ in range(100):
                    q.enter(reason="thread test")
                    q.exit()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=enter_exit) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_config_disables_auto_quarantine(self):
        """Test that config can disable auto quarantine."""
        q = RecoveryQuarantine(config={"auto_quarantine": False})

        nk_verdict = MagicMock()
        nk_verdict.verdict = "hostile"
        result = q.auto_quarantine(nk_verdict=nk_verdict)
        assert result is False
        assert q.is_quarantined() is False

    def test_config_disables_hostile_nk_quarantine(self):
        """Test config can disable quarantine on hostile NK."""
        q = RecoveryQuarantine(config={"quarantine_on_hostile_nk": False})

        nk_verdict = MagicMock()
        nk_verdict.verdict = "hostile"
        result = q.auto_quarantine(nk_verdict=nk_verdict)
        assert result is False
        assert q.is_quarantined() is False

    def test_custom_drift_sigma_threshold_high(self):
        """Custom high threshold should allow drift that default would quarantine."""
        q = RecoveryQuarantine(config={"drift_sigma_threshold": 5.0})

        drift_result = MagicMock()
        drift_result.is_drifting = True
        drift_result.max_sigma = 4.5  # above default 3.0 but below custom 5.0

        result = q.auto_quarantine(drift_result=drift_result)
        assert result is False
        assert q.is_quarantined() is False

    def test_custom_drift_sigma_threshold_low(self):
        """Custom low threshold should quarantine drift that default would allow."""
        q = RecoveryQuarantine(config={"drift_sigma_threshold": 1.5})

        drift_result = MagicMock()
        drift_result.is_drifting = True
        drift_result.max_sigma = 2.0  # below default 3.0 but above custom 1.5

        result = q.auto_quarantine(drift_result=drift_result)
        assert result is True
        assert q.is_quarantined() is True


class TestRecoveryQuarantineExitToken:
    """Tests for token-guarded quarantine exit on RecoveryQuarantine."""

    def test_no_token_exit_works_without_argument(self):
        """When no exit_token is configured, exit works with no argument."""
        q = RecoveryQuarantine()
        q.enter(reason="test")
        q.exit()
        assert q.is_quarantined() is False

    def test_no_token_exit_works_with_any_argument(self):
        """When no exit_token is configured, exit works even if a token is passed."""
        q = RecoveryQuarantine()
        q.enter(reason="test")
        q.exit(token="anything")
        assert q.is_quarantined() is False

    def test_token_exit_with_correct_token(self):
        """When exit_token is configured, exit succeeds with the correct token."""
        q = RecoveryQuarantine(exit_token="recovery-secret")
        q.enter(reason="hostile activity")
        q.exit(token="recovery-secret")
        assert q.is_quarantined() is False
        assert q.get_reason() is None

    def test_token_exit_rejects_wrong_token(self):
        """When exit_token is configured, exit raises ValueError for wrong token."""
        q = RecoveryQuarantine(exit_token="recovery-secret")
        q.enter(reason="hostile activity")
        with pytest.raises(ValueError, match="Invalid exit token"):
            q.exit(token="wrong-token")
        assert q.is_quarantined() is True
        assert q.get_reason() == "hostile activity"

    def test_token_exit_rejects_none_token(self):
        """When exit_token is configured, exit raises ValueError if no token is given."""
        q = RecoveryQuarantine(exit_token="recovery-secret")
        q.enter(reason="locked")
        with pytest.raises(ValueError, match="Invalid exit token"):
            q.exit()
        assert q.is_quarantined() is True

    def test_token_exit_rejects_empty_string_token(self):
        """When exit_token is configured, exit rejects empty string."""
        q = RecoveryQuarantine(exit_token="recovery-secret")
        q.enter(reason="locked")
        with pytest.raises(ValueError, match="Invalid exit token"):
            q.exit(token="")
        assert q.is_quarantined() is True

    def test_token_with_config_and_exit_token(self):
        """exit_token works alongside custom config."""
        q = RecoveryQuarantine(
            config={"drift_sigma_threshold": 5.0},
            exit_token="my-token",
        )
        q.enter(reason="test")
        with pytest.raises(ValueError, match="Invalid exit token"):
            q.exit(token="bad")
        q.exit(token="my-token")
        assert q.is_quarantined() is False

    def test_auto_quarantine_then_token_exit(self):
        """Auto-quarantine state can only be exited with the correct token."""
        q = RecoveryQuarantine(exit_token="auto-exit")
        nk_verdict = MagicMock()
        nk_verdict.verdict = "hostile"
        q.auto_quarantine(nk_verdict=nk_verdict)
        assert q.is_quarantined() is True

        with pytest.raises(ValueError, match="Invalid exit token"):
            q.exit(token="wrong")

        q.exit(token="auto-exit")
        assert q.is_quarantined() is False
