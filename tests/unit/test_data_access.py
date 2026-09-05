"""shared/data_access.py had 0% direct test coverage despite carrying a
High-severity fix: a module-level `raise RuntimeError` on missing
API_URL/TSOC_API_KEY meant importing this module -- including from
`make dashboard`, which sets neither var -- crashed before a single
Streamlit component rendered. These tests exercise the fix directly:
config loading is lazy and never raises past _init_state(), regardless
of what's configured.
"""
import os
from unittest.mock import patch, MagicMock

import pytest

from shared.data_access import DataStreamManager, ConfigError, _load_config


@pytest.fixture(autouse=True)
def _reset_singleton():
    """DataStreamManager caches its one instance on the class; without
    resetting it, whichever test runs first would decide every other
    test's config."""
    DataStreamManager._instance = None
    yield
    DataStreamManager._instance = None


def test_load_config_defaults_to_loopback_http_when_unset(monkeypatch):
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.setenv("TSOC_API_KEY", "k")
    api_url, api_key = _load_config()
    assert api_url == "http://127.0.0.1:8000/api/v1"
    assert api_key == "k"


def test_load_config_rejects_non_https_when_explicitly_set(monkeypatch):
    monkeypatch.setenv("API_URL", "http://example.com/api/v1")
    monkeypatch.setenv("TSOC_API_KEY", "k")
    with pytest.raises(ConfigError, match="HTTPS"):
        _load_config()


def test_load_config_accepts_https(monkeypatch):
    monkeypatch.setenv("API_URL", "https://api.tsoc.local/api/v1")
    monkeypatch.setenv("TSOC_API_KEY", "k")
    api_url, api_key = _load_config()
    assert api_url == "https://api.tsoc.local/api/v1"


def test_load_config_requires_api_key(monkeypatch):
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.delenv("TSOC_API_KEY", raising=False)
    with pytest.raises(ConfigError, match="TSOC_API_KEY"):
        _load_config()


def test_init_state_never_raises_on_missing_config(monkeypatch):
    """The regression test for the actual bug: constructing
    DataStreamManager() with no env vars configured at all must not raise
    -- it previously crashed the whole Streamlit process at import time."""
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.delenv("TSOC_API_KEY", raising=False)
    mgr = DataStreamManager()  # must not raise
    assert mgr.config_error is not None
    assert "TSOC_API_KEY" in mgr.config_error
    assert mgr.broker_healthy is False


def test_start_listeners_is_a_noop_when_misconfigured(monkeypatch):
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.delenv("TSOC_API_KEY", raising=False)
    mgr = DataStreamManager()
    mgr.start_listeners()
    # No poller thread should have started against a URL/key that don't exist.
    assert mgr.is_running is False


def test_poll_api_marks_unhealthy_on_non_200(monkeypatch):
    monkeypatch.setenv("API_URL", "https://api.tsoc.local/api/v1")
    monkeypatch.setenv("TSOC_API_KEY", "k")
    mgr = DataStreamManager()
    mgr.broker_healthy = True  # simulate a previously-healthy poll
    mgr.is_running = True

    fake_response = MagicMock(status_code=401)

    def _stop_after_one_iteration(*a, **kw):
        mgr.is_running = False
        return fake_response

    with patch.object(mgr.session, "get", side_effect=_stop_after_one_iteration), \
         patch("shared.data_access.time.sleep"):
        mgr._poll_api()

    # A non-200 response must not leave a stale "healthy" reading.
    assert mgr.broker_healthy is False
