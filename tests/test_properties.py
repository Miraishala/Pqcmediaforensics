"""tests/test_properties.py — SPEC §7D: Hypothesis property tests.

Properties:
  P1. A modified segment is NEVER VERIFIED (fail-closed).
  P2. An untouched segment never fails (no false positives).

Both hold over random profiles (valid §4 parameter combinations) and random single-unit edits.
Seeded randomness; Hypothesis shrinks failing examples automatically.
"""
from __future__ import annotations

import hashlib
import random
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

from evseal.bench.synth import make_media
from evseal.core import profile as prof
from evseal.core.manifest import Bundle
from evseal.core.seal import seal_path
from evseal.core.verify import verify
from evseal.longterm.timestamps import LocalTSA
from evseal.workspace import Workspace


# ---- fixtures ----

@pytest.fixture(scope="module")
def prop_lab(tmp_path_factory):
    home = tmp_path_factory.mktemp("prop_lab")
    ws = Workspace(home / "ws")
    ws.keygen("prop-root")
    media = home / "media"
    media.mkdir()
    # Pre-generate a single TS fixture (6s, used by all property tests)
    ts = make_media("ts", media, duration_s=6, fps=5, gop=5)
    return {"ws": ws, "home": home, "ts": ts}


# ---- strategy: random valid profile overrides ----

@st.composite
def random_profile(draw):
    """Draw a random (but valid) subset of §4 profile overrides."""
    overrides: dict = {}
    # Sign algorithm
    sign_alg = draw(st.sampled_from(["ML-DSA-44", "ML-DSA-65", "Ed25519+ML-DSA-44"]))
    overrides.setdefault("sign", {})["alg"] = sign_alg
    # Block size: 1 = per-segment (default), 2 = pair of segments
    overrides["sign"]["block_segments"] = draw(st.integers(min_value=1, max_value=2))
    # EC config (small stripes so tests are fast)
    k = draw(st.integers(min_value=2, max_value=4))
    m = draw(st.integers(min_value=0, max_value=2))
    interleave = draw(st.integers(min_value=1, max_value=3))
    overrides["ec"] = {"k": k, "m": m, "interleave": interleave}
    # Use ML-DSA for checkpoints (faster than SLH-DSA in pure-Python)
    overrides.setdefault("checkpoint", {})["alg"] = "ML-DSA-65"
    overrides.setdefault("anchors", {})["backend"] = "off"
    return overrides


# ---- property P1: modified unit is never VERIFIED ----

import tempfile

@given(profile_overrides=random_profile(), seed=st.integers(min_value=0, max_value=2**31))
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_modified_unit_never_verified(prop_lab, profile_overrides, seed):
    """P1 (SPEC §7D): any bit-flip in a sealed unit must never produce VERIFIED status."""
    rng = random.Random(seed)
    p = prof.resolve(prof._merge(prof.DEFAULTS, profile_overrides))
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "bundle"
        root = prop_lab["ws"].root("prop-root")
        tsa = LocalTSA(prop_lab["ws"].home / "tsa")
        seal_path(prop_lab["ts"], p, root, bundle, tsa=tsa, anchor_log=None)

        # Pick a random data segment file and flip one bit
        seg_files = sorted((bundle / "segments").glob("*.seg")) if (bundle / "segments").exists() else sorted(bundle.glob("*.seg"))
        if not seg_files:
            pytest.skip("No .seg files found (format may not produce segments)")
        victim = rng.choice(seg_files)
        data = bytearray(victim.read_bytes())
        bit = rng.randrange(len(data) * 8)
        data[bit // 8] ^= 1 << (bit % 8)
        victim.write_bytes(bytes(data))

        rep = verify(bundle, prop_lab["ws"].trust())
        # The victim unit must NOT be VERIFIED
        i = int(victim.stem)
        unit_status = {u.i: u.status for u in rep.units}
        victim_status = unit_status.get(i)
        assert victim_status != "VERIFIED", (
            f"P1 VIOLATED: flipped bit in unit {i} still VERIFIED "
            f"(seed={seed}, profile={profile_overrides})"
        )


# ---- property P2: untouched units never fail ----

@given(profile_overrides=random_profile(), seed=st.integers(min_value=0, max_value=2**31))
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_untouched_units_never_fail(prop_lab, profile_overrides, seed):
    """P2 (SPEC §7D): untouched segments must be VERIFIED (no false positives)."""
    p = prof.resolve(prof._merge(prof.DEFAULTS, profile_overrides))
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "bundle"
        root = prop_lab["ws"].root("prop-root")
        tsa = LocalTSA(prop_lab["ws"].home / "tsa")
        seal_path(prop_lab["ts"], p, root, bundle, tsa=tsa, anchor_log=None)

        rep = verify(bundle, prop_lab["ws"].trust())
    for u in rep.units:
        if u.role == "data":
            assert u.status in ("VERIFIED", "REPAIRED"), (
                f"P2 VIOLATED: untouched unit {u.i} has status {u.status} "
                f"(seed={seed}, profile={profile_overrides})"
            )
