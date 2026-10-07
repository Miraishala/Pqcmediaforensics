"""conftest.py — shared pytest fixtures and configuration.

Seeds all stdlib random calls for reproducibility. Hypothesis database is kept
in .hypothesis/ (gitignored). pytest.ini registers the 'slow' marker.
"""
import random
import zlib

import pytest


def pytest_configure(config):
    """Register markers declared in pytest.ini (belt-and-suspenders for older pytest)."""
    config.addinivalue_line(
        "markers", "slow: mark test as slow (skipped in fast CI, run with -m slow)"
    )


@pytest.fixture(autouse=True)
def _seed_random(request):
    """Seed Python's random module with a stable per-test seed so tests are reproducible.
    The seed is the test node id's hash, keeping tests independent of each other.
    """
    seed = zlib.crc32(request.node.nodeid.encode())  # str hash() is randomized per process
    random.seed(seed)
    yield
    random.seed(None)  # restore non-deterministic state after each test
