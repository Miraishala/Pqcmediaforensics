"""tests/test_bench.py — Benchmarking parameter sweeps (SPEC §6 item 8, SPEC §7F)."""

from __future__ import annotations

from pathlib import Path

import pytest

from evseal.bench.sweep import run_sweep


def test_quick_parameter_sweep(tmp_path):
    """Run quick benchmark sweep across algorithms and EC presets."""
    out_json = tmp_path / "bench_results.json"
    results = run_sweep(quick=True, out_file=out_json)

    assert len(results) >= 4
    assert out_json.is_file()

    for r in results:
        assert r["verified"] is True
        assert r["throughput_mb_s"] > 0
        assert r["overhead_pct"] >= 0
        assert r["wall_time_s"] > 0
        assert "alg" in r
        assert "ec" in r
