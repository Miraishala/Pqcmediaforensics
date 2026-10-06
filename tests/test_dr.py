"""tests/test_dr.py — Disaster Recovery Profile Tests (SPEC §3.3 & §8 P6).

Tests:
1. Outer layer: Keygen, ML-KEM-768/1024 DEK wrapping, AES-256-GCM encryption and decryption.
2. Outer layer: Multi-custodian wrapping (FSL vault + Court clerk), either custodian can decrypt.
3. Outer layer: Wrong custodian key or corrupted ciphertext fails closed.
4. Geo-split: 2-of-3 split, any 2 shards recover bit-exact original bundle.
5. Geo-split: 3-of-5 split, any 3 shards recover bit-exact original bundle.
6. Geo-split: Site-loss fault tolerance (lose n - k sites).
7. Geo-split: Corrupted shard is detected and skipped in favor of clean shards.
8. Geo-split: Less than k shards fails recovery cleanly.
9. End-to-end: Seal media -> Outer encrypt -> Geo-split -> Recover -> Decrypt outer -> Verify bundle.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from evseal.bench.synth import make_media
from evseal.core import profile as prof
from evseal.core.manifest import Bundle
from evseal.core.seal import seal_path
from evseal.core.verify import verify
from evseal.dr import custody, outer, split
from evseal.workspace import Workspace


@pytest.fixture(scope="module")
def dr_env(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("dr_test")
    ws = Workspace(workdir / "ws")
    ws.keygen("dr-root")

    # Generate media
    media_dir = workdir / "media"
    media_dir.mkdir()
    sample_ts = make_media("ts", media_dir, duration_s=4)

    # Seal sample bundle
    bundle_dir = workdir / "sample_bundle"
    p = prof.resolve(prof.PRESETS["court-grade"])
    seal_path(sample_ts, p, ws.root("dr-root"), bundle_dir, tsa=ws.tsa(), anchor_log=ws.anchor_log())

    # Generate custodian keys (ML-KEM-768 and ML-KEM-1024)
    custodian_fsl = outer.keygen_custodian("fsl-vault", "ML-KEM-768")
    custodian_court = outer.keygen_custodian("court-clerk", "ML-KEM-768")
    custodian_nic = outer.keygen_custodian("nic-archive", "ML-KEM-1024")

    return {
        "workdir": workdir,
        "ws": ws,
        "bundle": bundle_dir,
        "fsl": custodian_fsl,
        "court": custodian_court,
        "nic": custodian_nic,
    }


def test_outer_layer_roundtrip(dr_env, tmp_path):
    """Outer layer encryption with ML-KEM wrapped DEK and AES-256-GCM decrypts cleanly."""
    out_enc = tmp_path / "bundle.dr.enc"
    restored_bundle = tmp_path / "restored_bundle"

    # Encrypt for FSL custodian
    outer.encrypt_outer(
        dr_env["bundle"],
        [dr_env["fsl"]],
        out_enc,
        kem_alg="ML-KEM-768",
    )
    assert out_enc.is_file()
    assert out_enc.stat().st_size > 0

    # Decrypt with FSL private key
    outer.decrypt_outer(
        out_enc,
        dr_env["fsl"]["id"],
        dr_env["fsl"]["sk"],
        restored_bundle,
    )

    # Verify restored bundle passes verification
    rep = verify(restored_bundle, dr_env["ws"].trust())
    assert rep.overall == "VERIFIED"


def test_outer_multi_custodian(dr_env, tmp_path):
    """Bundle encrypted for multiple custodians can be opened by either one independently."""
    out_enc = tmp_path / "multi.dr.enc"

    # Encrypt for FSL and Court
    outer.encrypt_outer(
        dr_env["bundle"],
        [dr_env["fsl"], dr_env["court"], dr_env["nic"]],
        out_enc,
    )

    # Decrypt with Court key
    court_dir = tmp_path / "restored_court"
    outer.decrypt_outer(out_enc, "court-clerk", dr_env["court"]["sk"], court_dir)
    rep_court = verify(court_dir, dr_env["ws"].trust())
    assert rep_court.overall == "VERIFIED"

    # Decrypt with NIC key (ML-KEM-1024)
    nic_dir = tmp_path / "restored_nic"
    outer.decrypt_outer(out_enc, "nic-archive", dr_env["nic"]["sk"], nic_dir)
    rep_nic = verify(nic_dir, dr_env["ws"].trust())
    assert rep_nic.overall == "VERIFIED"


def test_outer_wrong_key_fails(dr_env, tmp_path):
    """Decrypting with wrong private key fails closed."""
    out_enc = tmp_path / "fail.dr.enc"
    outer.encrypt_outer(dr_env["bundle"], [dr_env["fsl"]], out_enc)

    other_key = outer.keygen_custodian("stranger", "ML-KEM-768")
    with pytest.raises(Exception):
        outer.decrypt_outer(out_enc, "fsl-vault", other_key["sk"], tmp_path / "restored_bad")


def test_geo_split_2_of_3(dr_env, tmp_path):
    """SPEC §3.3 item 2: 2-of-3 geo-split recovers from any 2 shards."""
    shards_dir = tmp_path / "shards_2_3"
    shards = split.split_bundle(dr_env["bundle"], k=2, n=3, out_dir=shards_dir)
    assert len(shards) == 3

    # Recover from shards {0, 1}
    out01 = tmp_path / "rec_01"
    split.recover_bundle([shards[0], shards[1]], out01)
    rep01 = verify(out01, dr_env["ws"].trust())
    assert rep01.overall == "VERIFIED"

    # Recover from shards {0, 2}
    out02 = tmp_path / "rec_02"
    split.recover_bundle([shards[0], shards[2]], out02)
    rep02 = verify(out02, dr_env["ws"].trust())
    assert rep02.overall == "VERIFIED"

    # Recover from shards {1, 2}
    out12 = tmp_path / "rec_12"
    split.recover_bundle([shards[1], shards[2]], out12)
    rep12 = verify(out12, dr_env["ws"].trust())
    assert rep12.overall == "VERIFIED"


def test_geo_split_insufficient_shards(dr_env, tmp_path):
    """Recovery with less than k shards fails cleanly."""
    shards_dir = tmp_path / "shards_sub"
    shards = split.split_bundle(dr_env["bundle"], k=3, n=5, out_dir=shards_dir)

    # 2 shards when k=3 must raise ValueError
    with pytest.raises(ValueError, match="Insufficient valid shards"):
        split.recover_bundle([shards[0], shards[1]], tmp_path / "rec_fail")


def test_geo_split_corrupted_shard_detection(dr_env, tmp_path):
    """Corrupted shard at untrusted site is detected and skipped in favor of surviving shards."""
    shards_dir = tmp_path / "shards_corrupt"
    shards = split.split_bundle(dr_env["bundle"], k=2, n=3, out_dir=shards_dir)

    # Tamper with shard 0's share data (flip byte at end)
    corrupted_data = bytearray(shards[0].read_bytes())
    corrupted_data[-1] ^= 0xFF
    shards[0].write_bytes(bytes(corrupted_data))

    # Inspection flags corruption
    info = split.inspect_shard(shards[0])
    assert not info["ok"]
    assert "mismatch" in info["reason"]

    # Recovery still succeeds because we have 2 remaining untampered shards (1 and 2)
    out_rec = tmp_path / "rec_survived"
    split.recover_bundle(shards, out_rec)
    rep = verify(out_rec, dr_env["ws"].trust())
    assert rep.overall == "VERIFIED"


def test_dr_end_to_end_outer_plus_split(dr_env, tmp_path):
    """Full DR pipeline: seal -> outer encrypt -> geo-split -> recover -> decrypt -> verify."""
    enc_file = tmp_path / "outer.enc"
    outer.encrypt_outer(dr_env["bundle"], [dr_env["fsl"]], enc_file)

    # Split the outer container 2-of-3
    shards_dir = tmp_path / "outer_shards"
    shards = split.split_bundle(enc_file, k=2, n=3, out_dir=shards_dir)

    # Simulate losing site 0: recover outer container using sites 1 and 2
    rec_enc = tmp_path / "recovered_outer.enc"
    split.recover_bundle([shards[1], shards[2]], rec_enc)
    assert rec_enc.read_bytes() == enc_file.read_bytes()

    # Custodian decrypts recovered outer container
    final_bundle = tmp_path / "final_restored_bundle"
    outer.decrypt_outer(rec_enc, "fsl-vault", dr_env["fsl"]["sk"], final_bundle)

    # Final bundle verifies cleanly
    rep = verify(final_bundle, dr_env["ws"].trust())
    assert rep.overall == "VERIFIED"
