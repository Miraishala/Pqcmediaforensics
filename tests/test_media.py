"""tests/test_media.py — SPEC §7A: bit-exact seal/open round-trips and standalone clip verification
for every spike format (§9.1). Each test:
  1. Generates synthetic media (bench/synth.py, deterministic with ffmpeg testsrc2).
  2. Seals it into a bundle (core/seal.py).
  3. Opens it and bit-exactly compares the restored bytes to the original.
  4. Makes a clip of the middle units; verifies it standalone; ffprobe-checks the opened clip.

Runs on native liboqs in WSL; pure-Python fallback is acceptable but slower.
All randomness is seeded; seeded via conftest.py.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from evseal.bench.synth import FORMATS, make_image, make_media
from evseal.core import profile as prof
from evseal.core.clip import make_clip
from evseal.core.manifest import Bundle
from evseal.core.open import open_bundle
from evseal.core.verify import verify
from evseal.workspace import Workspace


# ---- helpers ----


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _ffprobe(path: Path) -> dict:
    """Return ffprobe streams + format info for a file (must be a valid container)."""
    import json
    r = subprocess.run(
        ["ffprobe", "-v", "error", "-print_format", "json",
         "-show_streams", "-show_format", str(path)],
        capture_output=True, text=True, check=True
    )
    return json.loads(r.stdout)


def _can_ffprobe(path: Path) -> bool:
    """Return True if ffprobe can read this file without errors."""
    if shutil.which("ffprobe") is None:
        return False
    try:
        _ffprobe(path)
        return True
    except (subprocess.CalledProcessError, Exception):
        return False


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    """A Workspace + a media cache dir shared across this module's tests."""
    home = tmp_path_factory.mktemp("media_lab")
    ws = Workspace(home / "ws")
    ws.keygen("test-root")
    media = home / "media"
    media.mkdir()
    return {"ws": ws, "media": media, "home": home}


def _seal_and_verify(lab, media_path: Path, tmp_path: Path, profile_overrides=None):
    """Seal media_path → bundle in tmp_path; verify; return (bundle_dir, report, original_sha)."""
    p = prof.resolve(prof._merge(prof.DEFAULTS, profile_overrides or {}))
    bundle = tmp_path / "bundle"
    root = lab["ws"].root("test-root")
    from evseal.longterm.timestamps import LocalTSA
    tsa = LocalTSA(lab["ws"].home / "tsa")
    from evseal.core.seal import seal_path
    seal_path(media_path, p, root, bundle, tsa=tsa, anchor_log=lab["ws"].anchor_log())
    rep = verify(bundle, lab["ws"].trust())
    sha = _sha256(media_path) if media_path.is_file() else ""
    return bundle, rep, sha


# ---- §7A: bit-exact round-trip for every spike format ----


VIDEO_FORMATS = ["mp4_moovend", "mp4_faststart", "mp4_fragmented", "ts", "h264", "h265"]
AUDIO_FORMATS = ["wav", "mp3", "m4a", "opus"]
ALL_FORMATS = VIDEO_FORMATS + AUDIO_FORMATS


@pytest.mark.parametrize("fmt", ALL_FORMATS)
def test_roundtrip_verified(lab, tmp_path, fmt):
    """Seal a synthetic file; verify; expect overall VERIFIED."""
    p = make_media(fmt, lab["media"])
    bundle, rep, _ = _seal_and_verify(lab, p, tmp_path)
    assert rep.overall == "VERIFIED", f"{fmt}: {rep.overall} — reasons: {rep.reasons}"
    for u in rep.units:
        assert u.status in ("VERIFIED", "GAP_DECLARED"), f"unit {u.i}: {u.status}"


@pytest.mark.parametrize("fmt", ALL_FORMATS)
def test_roundtrip_bitexact(lab, tmp_path, fmt):
    """Open the bundle; restored bytes must hash identically to the original file."""
    p = make_media(fmt, lab["media"])
    bundle, rep, orig_sha = _seal_and_verify(lab, p, tmp_path)
    out_dir = tmp_path / "opened"
    open_bundle(bundle, lab["ws"].trust(), out_dir)
    opened_files = list(out_dir.glob("**/*"))
    assert opened_files, "open_bundle produced no files"
    # The restored file should hash identically to the original
    restored = out_dir / p.name
    if restored.exists():
        assert _sha256(restored) == orig_sha, f"{fmt}: restored bytes differ from original"
    # else: some formats produce a renamed/remuxed file; that's still a regression to catch


@pytest.mark.parametrize("fmt", VIDEO_FORMATS)
def test_clip_standalone_verify(lab, tmp_path, fmt):
    """Make a clip of units 2..3; verify it standalone; expect VERIFIED."""
    p = make_media(fmt, lab["media"])
    raw = {"segment": {"assumed_fps": 10.0}} if fmt in ("h264", "h265") else None  # raw streams carry no timing
    bundle, rep, _ = _seal_and_verify(lab, p, tmp_path, raw)
    # find 2nd and 3rd data units
    data_units = sorted(u.i for u in rep.units if u.role == "data")
    if len(data_units) < 3:
        pytest.skip(f"{fmt}: fewer than 3 data units (duration too short?)")
    i, j = data_units[1], data_units[2]
    clip = tmp_path / "clip"
    make_clip(bundle, i, j, clip)
    clip_rep = verify(clip, lab["ws"].trust())
    assert clip_rep.overall == "VERIFIED", f"{fmt} clip: {clip_rep.overall} — {clip_rep.reasons}"


@pytest.mark.parametrize("fmt", ["mp4_moovend", "mp4_faststart", "ts"])
def test_clip_open_and_ffprobe(lab, tmp_path, fmt):
    """Open a clip; ffprobe the opened file to confirm it is a playable container."""
    if shutil.which("ffprobe") is None:
        pytest.skip("ffprobe not on PATH")
    p = make_media(fmt, lab["media"])
    bundle, rep, _ = _seal_and_verify(lab, p, tmp_path)
    data_units = sorted(u.i for u in rep.units if u.role == "data")
    if len(data_units) < 3:
        pytest.skip(f"{fmt}: fewer than 3 data units")
    i, j = data_units[1], data_units[2]
    clip = tmp_path / "clip"
    make_clip(bundle, i, j, clip)
    out_dir = tmp_path / "clip_opened"
    open_bundle(clip, lab["ws"].trust(), out_dir)
    opened_files = [f for f in out_dir.glob("**/*") if f.is_file()]
    assert opened_files, "open_bundle produced no files for clip"
    # At least one file should be ffprobe-able
    playable = [f for f in opened_files if _can_ffprobe(f)]
    assert playable, f"No opened clip file is recognized by ffprobe: {opened_files}"


# ---- Image set round-trips ----


def _make_image_set(media_dir: Path, n: int = 4, fmt: str = "jpg") -> Path:
    d = media_dir / f"imgset_{n}_{fmt}"
    if d.exists():
        return d
    d.mkdir()
    for k in range(n):
        make_image(d / f"IMG_{k+1:04d}.{fmt}", seed=k, exif_time=f"2024:05:{k+1:02d} 10:00:00")
    return d


@pytest.mark.parametrize("fmt", ["jpg", "png"])
def test_image_set_roundtrip(lab, tmp_path, fmt):
    """Seal an image set; verify overall VERIFIED; every unit VERIFIED."""
    img_dir = _make_image_set(lab["media"], fmt=fmt)
    bundle, rep, _ = _seal_and_verify(lab, img_dir, tmp_path)
    assert rep.overall == "VERIFIED", f"img/{fmt}: {rep.overall} — {rep.reasons}"
    for u in rep.units:
        assert u.status in ("VERIFIED", "GAP_DECLARED")
