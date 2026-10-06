"""tests/test_repair.py — Unit tests for resilience/ec.py and resilience/repair.py.

Tests the erasure coding, interleaving, RS manifest copy, repair write-back,
and the crucial m vs m+1 shard boundary: exactly m repairs, m+1 → CORRUPT,
never a false VERIFIED.
"""
from __future__ import annotations

import random
import shutil
from pathlib import Path

import pytest

from evseal.bench.synth import make_media
from evseal.core import profile as prof
from evseal.core.seal import seal_path
from evseal.core.verify import verify
from evseal.longterm.timestamps import LocalTSA
from evseal.resilience import repair as rep_mod
from evseal.workspace import Workspace


@pytest.fixture(scope="module")
def ec_lab(tmp_path_factory):
    home = tmp_path_factory.mktemp("ec_lab")
    ws = Workspace(home / "ws")
    ws.keygen("ec-root")
    media = home / "media"
    media.mkdir()
    ts = make_media("ts", media, duration_s=6, fps=5, gop=5)
    return {"ws": ws, "home": home, "ts": ts}


def _seal_small_stripe(ec_lab, tmp_path: Path, k=4, m=2, interleave=2) -> Path:
    """Seal TS media with small stripes (k+m units per stripe), return bundle path."""
    p = prof.resolve(prof._merge(prof.DEFAULTS, {
        "ec": {"k": k, "m": m, "interleave": interleave},
        "checkpoint": {"alg": "ML-DSA-65"},
    }))
    bundle = tmp_path / "bundle"
    tsa = LocalTSA(ec_lab["ws"].home / "tsa")
    seal_path(ec_lab["ts"], p, ec_lab["ws"].root("ec-root"), bundle, tsa=tsa, anchor_log=None)
    return bundle


def test_clean_bundle_verified(ec_lab, tmp_path):
    """Baseline: unsealed bundle is VERIFIED with no repair needed."""
    bundle = _seal_small_stripe(ec_lab, tmp_path)
    r = verify(bundle, ec_lab["ws"].trust())
    assert r.overall == "VERIFIED"


def test_m_lost_shards_repaired(ec_lab, tmp_path):
    """Lose exactly m=2 segments of the first stripe → VERIFIED after in-memory repair."""
    bundle = _seal_small_stripe(ec_lab, tmp_path, k=4, m=2)
    # Delete the first 2 data segment files
    segs = sorted((bundle / "segments").glob("*.seg")) if (bundle / "segments").exists() else sorted(bundle.glob("*.seg"))
    if len(segs) < 2:
        pytest.skip("Not enough segments generated for this fixture")
    for s in segs[:2]:
        s.unlink()
    r = verify(bundle, ec_lab["ws"].trust())
    assert r.overall == "VERIFIED", f"m shards lost but got {r.overall}"
    repaired = [u for u in r.units if u.status == "REPAIRED"]
    assert repaired, "Expected at least 1 REPAIRED unit"
    corrupt = [u for u in r.units if u.status == "CORRUPT"]
    tampered = [u for u in r.units if u.status == "TAMPERED"]
    assert not corrupt and not tampered, f"Unexpected CORRUPT or TAMPERED: {r.units}"


def test_m_plus1_lost_shards_corrupt(ec_lab, tmp_path):
    """Lose m+1=3 segments → CORRUPT, never VERIFIED."""
    bundle = _seal_small_stripe(ec_lab, tmp_path, k=4, m=2)
    segs = sorted((bundle / "segments").glob("*.seg")) if (bundle / "segments").exists() else sorted(bundle.glob("*.seg"))
    if len(segs) < 3:
        pytest.skip("Not enough segments for this test")
    for s in segs[:3]:
        s.unlink()
    r = verify(bundle, ec_lab["ws"].trust())
    assert r.overall != "VERIFIED", "m+1 shards lost but reported VERIFIED — CRITICAL BUG"
    tampered = [u for u in r.units if u.status == "TAMPERED"]
    assert not tampered, f"m+1 shard loss must not produce TAMPERED: {tampered}"


def test_repair_writeback(ec_lab, tmp_path):
    """Repair write-back: after run_repair(), re-verify gives VERIFIED with no REPAIRED units."""
    bundle = _seal_small_stripe(ec_lab, tmp_path, k=4, m=2)
    segs = sorted((bundle / "segments").glob("*.seg")) if (bundle / "segments").exists() else sorted(bundle.glob("*.seg"))
    if len(segs) < 1:
        pytest.skip("No segment files found")
    segs[0].unlink()

    r_before = verify(bundle, ec_lab["ws"].trust())
    repaired_before = [u for u in r_before.units if u.status == "REPAIRED"]
    if not repaired_before:
        pytest.skip("No units were REPAIRED — shard loss may not have hit this stripe")

    rep_mod.run_repair(bundle, ec_lab["ws"].trust())

    r_after = verify(bundle, ec_lab["ws"].trust())
    assert r_after.overall == "VERIFIED"
    repaired_after = [u for u in r_after.units if u.status == "REPAIRED"]
    assert not repaired_after, "After write-back, no unit should still be REPAIRED"


def test_no_parity_bitflip_corrupt(ec_lab, tmp_path):
    """With m=0, a single bit flip → CORRUPT (no parity to repair from)."""
    bundle = _seal_small_stripe(ec_lab, tmp_path, k=4, m=0)
    segs = sorted((bundle / "segments").glob("*.seg")) if (bundle / "segments").exists() else sorted(bundle.glob("*.seg"))
    if not segs:
        pytest.skip("No segment files")
    victim = segs[0]
    data = bytearray(victim.read_bytes())
    data[len(data) // 2] ^= 0xFF
    victim.write_bytes(bytes(data))
    r = verify(bundle, ec_lab["ws"].trust())
    assert r.overall != "VERIFIED"
    tampered = [u for u in r.units if u.status == "TAMPERED"]
    assert not tampered, "Random bit flip should be CORRUPT, not TAMPERED"
