"""Shared fixtures for the backend tests."""
import pytest


@pytest.fixture(autouse=True)
def _fresh_rate_limits():
    """Every test starts with empty rate-limit windows: the limiters are real (decorator-level, per user), and
    in-process tests that reuse one user across tests would otherwise share a budget."""
    try:
        from backend.utilities import ratelimit
    except ImportError:  # a test that runs without the backend package on the path
        yield
        return
    ratelimit.reset_all()
    yield
    ratelimit.reset_all()
