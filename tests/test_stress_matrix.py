"""tests/test_stress_matrix.py — parametrized runner over expected.toml (SPEC §7).

Each scenario in expected.toml becomes one pytest parameter. The fast set runs in CI;
slow scenarios (slow=true) run only with `pytest -m slow` or `evseal stress --full`.

A mismatch between expected and actual results is a BUG IN THE CODE, not a flaky test —
unless SPEC explicitly says otherwise, in which case: STOP and ask.

All scenarios use seed=1 (fixed). The seed is recorded in every result dict.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from evseal.stresslab.runner import Lab, load_expected

EXPECTED_PATH = Path(__file__).parent.parent / "evseal" / "stresslab" / "expected.toml"

# Load scenarios at collection time so parametrize IDs are the scenario 'id' slugs
_ALL_SCENARIOS = load_expected(EXPECTED_PATH)
_FAST = [s for s in _ALL_SCENARIOS if not s.get("slow")]
_SLOW = [s for s in _ALL_SCENARIOS if s.get("slow")]


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("stress_lab")
    return Lab(workdir)


def _run_and_assert(lab, scenario):
    result = lab.run(scenario, seed=1)
    mismatches = result.get("mismatches", [])
    assert not mismatches, (
        f"Scenario '{scenario['id']}' FAILED:\n"
        + "\n".join(f"  • {m}" for m in mismatches)
        + f"\n  actual={result.get('actual')}"
        + f"\n  expected={result.get('expected')}"
        + f"\n  seed={result['seed']}"
    )


@pytest.mark.parametrize("scenario", _FAST, ids=[s["id"] for s in _FAST])
def test_stress_fast(lab, scenario):
    """Fast scenario: runs in normal CI pass."""
    _run_and_assert(lab, scenario)


@pytest.mark.slow
@pytest.mark.parametrize("scenario", _SLOW, ids=[s["id"] for s in _SLOW])
def test_stress_slow(lab, scenario):
    """Slow scenario: marked @pytest.mark.slow, skipped in fast CI."""
    _run_and_assert(lab, scenario)
