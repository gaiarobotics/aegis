"""Tests for model-aware RemoteThreatIntel."""

import json
from unittest.mock import MagicMock, patch
from aegis.core.remote_threat_intel import RemoteThreatIntel


class TestRemoteThreatIntelModelAware:
    def test_get_compromised_hashes_by_model(self):
        rti = RemoteThreatIntel("http://example.com/api/v1", "key")
        rti._compromised_hashes = {
            "model-a": {0xAAAA},
            "model-b": {0xBBBB},
        }
        assert rti.get_compromised_hashes("model-a") == {0xAAAA}
        assert rti.get_compromised_hashes("model-b") == {0xBBBB}
        assert rti.get_compromised_hashes("model-c") == set()

    def test_get_compromised_hashes_all(self):
        rti = RemoteThreatIntel("http://example.com/api/v1", "key")
        rti._compromised_hashes = {
            "model-a": {0xAAAA},
            "model-b": {0xBBBB},
        }
        all_hashes = rti.get_compromised_hashes(None)
        assert 0xAAAA in all_hashes
        assert 0xBBBB in all_hashes

    def test_check_hash_filters_by_model(self):
        rti = RemoteThreatIntel("http://example.com/api/v1", "key")
        hash_val = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        rti._compromised_hashes = {"model-a": {hash_val}}

        hex_str = f"{hash_val:032x}"
        is_sus, sim = rti.check_hash(hex_str, model="model-a")
        assert sim == 1.0  # exact match

        is_sus, sim = rti.check_hash(hex_str, model="model-b")
        assert sim == 0.0  # different model

    def test_poll_parses_model_keyed_hashes(self):
        rti = RemoteThreatIntel("http://example.com/api/v1", "key")

        response_data = {
            "compromised_agents": ["agent-1"],
            "compromised_hashes": {
                "model-a": ["a" * 32],
                "model-b": ["b" * 32],
            },
            "quarantined_agents": [],
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            rti._poll()

        assert "model-a" in rti._compromised_hashes
        assert "model-b" in rti._compromised_hashes
        assert len(rti._compromised_hashes["model-a"]) == 1
        assert len(rti._compromised_hashes["model-b"]) == 1
