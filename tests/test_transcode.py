"""tests/test_transcode.py — SPEC §10: Reproducible transcoding tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from evseal.bench.synth import make_media
from evseal.core import profile as prof
from evseal.core.seal import seal_path
from evseal.media.transcode import (
    create_derivation_record,
    transcode_deterministic,
    verify_derivation,
)
from evseal.workspace import Workspace


@pytest.fixture(scope="module")
def transcode_lab(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("transcode_lab")
    ws = Workspace(workdir / "ws")
    ws.keygen("tc-root")

    media_dir = workdir / "media"
    media_dir.mkdir()
    ts_media = make_media("ts", media_dir, duration_s=4)

    bundle_dir = workdir / "bundle"
    p = prof.resolve(prof.PRESETS["court-grade"])
    seal_path(ts_media, p, ws.root("tc-root"), bundle_dir, tsa=ws.tsa(), anchor_log=ws.anchor_log())

    return {"ws": ws, "src": ts_media, "bundle": bundle_dir}


def test_deterministic_transcode_bit_exact(transcode_lab, tmp_path):
    """Running transcode twice with deterministic settings yields identical output bytes."""
    out1 = tmp_path / "out1.mp4"
    out2 = tmp_path / "out2.mp4"

    transcode_deterministic(transcode_lab["src"], out1)
    transcode_deterministic(transcode_lab["src"], out2)

    assert out1.read_bytes() == out2.read_bytes()


def test_derivation_record_verification(transcode_lab, tmp_path):
    """Signed derivation record verifies bit-exactly against sealed original."""
    transcoded = tmp_path / "derived.mp4"
    transcode_deterministic(transcode_lab["src"], transcoded)

    actor = transcode_lab["ws"].root("tc-root")
    rec = create_derivation_record(
        transcode_lab["bundle"],
        segment_range=(0, 4),
        derived_file=transcoded,
        actor=actor,
    )

    # Verification passes
    ok, msg = verify_derivation(transcode_lab["bundle"], rec, transcoded, transcode_lab["ws"].trust(), retranscode=True)
    assert ok, f"Derivation verification failed: {msg}"


def test_tampered_derived_media_fails(transcode_lab, tmp_path):
    """Tampering with derived copy is detected by derivation verifier."""
    transcoded = tmp_path / "derived.mp4"
    transcode_deterministic(transcode_lab["src"], transcoded)

    actor = transcode_lab["ws"].root("tc-root")
    rec = create_derivation_record(
        transcode_lab["bundle"],
        segment_range=(0, 4),
        derived_file=transcoded,
        actor=actor,
    )

    # Tamper with file
    tampered = bytearray(transcoded.read_bytes())
    tampered[-1] ^= 0x01
    transcoded.write_bytes(bytes(tampered))

    ok, msg = verify_derivation(transcode_lab["bundle"], rec, transcoded, transcode_lab["ws"].trust(), retranscode=False)
    assert not ok
    assert "hash mismatch" in msg
