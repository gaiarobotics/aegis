"""Tests for AEGIS message-level drift detection."""

from aegis.behavior.message_drift import MessageDriftDetector, MessageProfile
from aegis.core.config import MessageDriftConfig


class TestMessageProfile:
    def test_compute_profile_basic_text(self):
        text = "Hello there. How are you doing today? I hope everything is fine."
        profile = MessageDriftDetector.compute_profile(text)
        assert isinstance(profile, MessageProfile)
        assert profile.vocabulary_entropy > 0.0
        assert 0.0 < profile.lexical_diversity <= 1.0
        assert profile.avg_sentence_length > 0.0
        # One question out of three sentences
        assert profile.question_frequency > 0.0
        # Normal mixed-case text has low uppercase ratio
        assert 0.0 < profile.uppercase_ratio < 0.5

    def test_compute_profile_empty_text(self):
        profile = MessageDriftDetector.compute_profile("")
        assert profile.vocabulary_entropy == 0.0
        assert profile.lexical_diversity == 0.0
        assert profile.avg_sentence_length == 0.0
        assert profile.question_frequency == 0.0
        assert profile.uppercase_ratio == 0.0


class TestMessageDriftDetector:
    def test_no_drift_during_baseline(self):
        detector = MessageDriftDetector(config=MessageDriftConfig(baseline_size=5))
        for i in range(4):
            sigma = detector.record_and_check(
                "agent-1", f"This is a normal message number {i}."
            )
            assert sigma == 0.0, f"Expected 0.0 during baseline, got {sigma}"

    def test_no_drift_stable_messages(self):
        detector = MessageDriftDetector(config=MessageDriftConfig(baseline_size=5, threshold=2.5))
        # Establish baseline with consistent conversational messages
        base_messages = [
            "Hello, how are you doing today? I hope you are well.",
            "That sounds great. Let me help you with that question.",
            "Sure, I can explain that concept for you in detail.",
            "Here is the information you requested about the topic.",
            "Is there anything else I can help you with today?",
            "I would be happy to assist you with your question.",
            "That is an interesting point. Let me think about it.",
        ]
        for msg in base_messages:
            sigma = detector.record_and_check("agent-1", msg)
        # After baseline, similar messages should produce low sigma
        sigma = detector.record_and_check(
            "agent-1", "Let me provide you with more details on that."
        )
        assert sigma < 2.5, f"Expected stable sigma < 2.5, got {sigma}"

    def test_drift_detected_style_change(self):
        detector = MessageDriftDetector(config=MessageDriftConfig(baseline_size=10, threshold=2.5))
        # Establish baseline with normal conversational text
        for i in range(12):
            detector.record_and_check(
                "agent-1",
                f"This is a calm and collected response number {i}. "
                "I am providing helpful information in a professional manner. "
                "Let me know if you need anything else from me today.",
            )
        # Dramatic style change: ALL CAPS, short, aggressive
        sigma = detector.record_and_check(
            "agent-1",
            "STOP STOP STOP STOP STOP STOP STOP STOP STOP STOP "
            "STOP STOP STOP STOP STOP STOP STOP STOP STOP STOP",
        )
        assert sigma > 2.5, f"Expected drift sigma > 2.5, got {sigma}"

    def test_drift_detected_vocabulary_shift(self):
        detector = MessageDriftDetector(config=MessageDriftConfig(baseline_size=10, threshold=2.5))
        # Baseline: diverse vocabulary
        for i in range(12):
            detector.record_and_check(
                "agent-1",
                f"The {['quick', 'lazy', 'brown', 'clever'][i % 4]} fox "
                f"jumped over the {['tall', 'short', 'wide', 'narrow'][i % 4]} fence. "
                f"Meanwhile the {['curious', 'sleepy', 'playful', 'hungry'][i % 4]} cat "
                "watched from a distance with great interest and amusement.",
            )
        # Shift: extremely repetitive vocabulary (low entropy)
        sigma = detector.record_and_check(
            "agent-1",
            "bad bad bad bad bad bad bad bad bad bad "
            "bad bad bad bad bad bad bad bad bad bad "
            "bad bad bad bad bad bad bad bad bad bad",
        )
        assert sigma > 2.5, f"Expected drift sigma > 2.5 for vocab shift, got {sigma}"

    def test_multiple_agents_independent(self):
        detector = MessageDriftDetector(config=MessageDriftConfig(baseline_size=3))
        for i in range(3):
            detector.record_and_check("agent-a", f"Normal message {i} from agent A.")
        for i in range(3):
            detector.record_and_check("agent-b", f"Different message {i} from agent B.")
        # Agent A's baseline is independent of agent B
        sigma_a = detector.record_and_check("agent-a", "Normal message from agent A.")
        sigma_b = detector.record_and_check("agent-b", "Different message from agent B.")
        assert sigma_a < 2.5
        assert sigma_b < 2.5

    def test_custom_threshold(self):
        detector = MessageDriftDetector(
            config=MessageDriftConfig(baseline_size=5, threshold=10.0)
        )
        assert detector._threshold == 10.0

    def test_thread_safety(self):
        """Concurrent access from multiple threads should not crash."""
        import threading

        detector = MessageDriftDetector(config=MessageDriftConfig(baseline_size=3))
        errors = []

        def worker(agent_id):
            try:
                for i in range(20):
                    detector.record_and_check(
                        agent_id, f"Message {i} from {agent_id}."
                    )
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(f"agent-{j}",))
            for j in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0, f"Thread errors: {errors}"

    def test_window_size_bounded(self):
        detector = MessageDriftDetector(
            config=MessageDriftConfig(window_size=5, baseline_size=3)
        )
        for i in range(20):
            detector.record_and_check("agent-1", f"Message number {i} here.")
        assert len(detector._profiles["agent-1"]) <= 5
