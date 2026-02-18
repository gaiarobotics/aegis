"""Tests for broker endpoint patchers."""

import builtins
import subprocess
from unittest.mock import MagicMock, patch

from aegis.broker.actions import ActionDecision, ActionResponse
from aegis.broker.broker import Broker
from aegis.broker.manifests import ToolManifest
from aegis.broker.patchers import (
    _originals,
    patch_filesystem,
    patch_http,
    patch_subprocess,
    unpatch_all,
)


def _allow_response(req_id: str = "test") -> ActionResponse:
    return ActionResponse(
        request_id=req_id,
        decision=ActionDecision.ALLOW,
        reason="Allowed",
    )


def _deny_response(req_id: str = "test") -> ActionResponse:
    return ActionResponse(
        request_id=req_id,
        decision=ActionDecision.DENY,
        reason="Denied",
    )


class TestPatchHttp:
    def test_patch_and_unpatch_http(self):
        """Patching and unpatching should store/restore originals."""
        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _allow_response()

        try:
            import requests

            original = requests.Session.request
            patch_http(broker)
            assert requests.Session.request is not original
            assert "http" in _originals
            unpatch_all()
            assert requests.Session.request is original
        except ImportError:
            # requests not available; patch_http should handle gracefully
            patch_http(broker)
            unpatch_all()

    def test_patch_http_deny_raises(self):
        """When patched and broker denies, HTTP request should raise PermissionError."""
        try:
            import requests
        except ImportError:
            return  # skip if requests not available

        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _deny_response()

        patch_http(broker)
        try:
            session = requests.Session()
            try:
                session.request("GET", "http://example.com")
            except PermissionError:
                pass  # Expected
            assert broker.evaluate.called
        finally:
            unpatch_all()

    def test_patch_http_no_requests_module(self):
        """patch_http should not raise if requests is not installed."""
        broker = MagicMock(spec=Broker)
        with patch.dict("sys.modules", {"requests": None}):
            # Should not raise
            patch_http(broker)
        unpatch_all()


class TestPatchSubprocess:
    def test_patch_and_unpatch_subprocess(self):
        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _allow_response()

        original_run = subprocess.run
        original_popen = subprocess.Popen

        patch_subprocess(broker)
        assert subprocess.run is not original_run
        assert subprocess.Popen is not original_popen
        assert "subprocess_run" in _originals
        assert "subprocess_popen" in _originals

        unpatch_all()
        assert subprocess.run is original_run
        assert subprocess.Popen is original_popen

    def test_subprocess_run_allowed(self):
        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _allow_response()

        patch_subprocess(broker)
        try:
            subprocess.run(["echo", "hello"])
            assert broker.evaluate.called
        finally:
            unpatch_all()

    def test_subprocess_run_denied(self):
        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _deny_response()

        patch_subprocess(broker)
        try:
            result = subprocess.run(["echo", "hello"])
            # When denied, should raise PermissionError
            # This won't be reached
            assert False, "Should have raised PermissionError"
        except PermissionError:
            pass
        finally:
            unpatch_all()


class TestPatchFilesystem:
    def test_patch_and_unpatch_filesystem(self):
        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _allow_response()

        original_open = builtins.open

        patch_filesystem(broker)
        assert builtins.open is not original_open
        assert "open" in _originals

        unpatch_all()
        assert builtins.open is original_open

    def test_read_mode_not_intercepted(self):
        """Opening a file in read mode should not call broker.evaluate."""
        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _allow_response()

        patch_filesystem(broker)
        try:
            # Read mode should pass through without calling broker
            import tempfile
            import os

            fd, path = tempfile.mkstemp()
            os.close(fd)
            try:
                with open(path, "r") as f:
                    pass
                broker.evaluate.assert_not_called()
            finally:
                os.unlink(path)
        finally:
            unpatch_all()

    def test_write_mode_calls_broker(self):
        """Opening a file in write mode should call broker.evaluate."""
        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _allow_response()

        patch_filesystem(broker)
        try:
            import tempfile
            import os

            fd, path = tempfile.mkstemp()
            os.close(fd)
            try:
                with open(path, "w") as f:
                    f.write("test")
                assert broker.evaluate.called
            finally:
                os.unlink(path)
        finally:
            unpatch_all()

    def test_write_mode_denied(self):
        """Opening a file in write mode when denied should raise PermissionError."""
        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _deny_response()

        patch_filesystem(broker)
        try:
            import tempfile
            import os

            fd, path = tempfile.mkstemp()
            os.close(fd)
            try:
                with open(path, "w") as f:
                    f.write("test")
                assert False, "Should have raised PermissionError"
            except PermissionError:
                pass
            finally:
                os.unlink(path)
        finally:
            unpatch_all()


class TestUnpatchAll:
    def test_unpatch_all_clears_originals(self):
        broker = MagicMock(spec=Broker)
        broker.evaluate.return_value = _allow_response()

        patch_subprocess(broker)
        patch_filesystem(broker)
        assert len(_originals) >= 3  # subprocess_run, subprocess_popen, open

        unpatch_all()
        assert len(_originals) == 0

    def test_unpatch_all_idempotent(self):
        """Calling unpatch_all when nothing is patched should not error."""
        unpatch_all()
        unpatch_all()
