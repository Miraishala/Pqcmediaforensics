"""Reproducible Transcoding for Derived Copies (SPEC §10).

When a playback or working copy is transcoded:
1. Record encoder, version, and exact deterministic settings (x264 single-threaded, fixed parameters).
2. Sign a derivation record (source segment range -> output hash).
3. The verifier can re-run the transcode from the sealed original and compare bit-exactly.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from evseal.core import crypto
from evseal.core.manifest import Bundle, jcs
from evseal.core.open import open_bundle
from evseal.longterm.keys import KeyPair, Trust

DEFAULT_SETTINGS: dict = {
    "vcodec": "libx264",
    "preset": "ultrafast",
    "crf": 28,
    "pix_fmt": "yuv420p",
    "threads": 1,
    "gop": 25,
    "acodec": "aac",
    "audio_bitrate": "64k",
}


def get_ffmpeg_version() -> str:
    if shutil.which("ffmpeg") is None:
        return "ffmpeg-unknown"
    try:
        r = subprocess.run(["ffmpeg", "-version"], capture_output=True, text=True, check=True)
        return r.stdout.splitlines()[0]
    except Exception:
        return "ffmpeg-unknown"


def transcode_deterministic(
    src_file: Path,
    out_file: Path,
    settings: dict | None = None,
) -> tuple[Path, dict]:
    """Transcode a media file with strictly deterministic ffmpeg parameters."""
    cfg = {**DEFAULT_SETTINGS, **(settings or {})}
    out_file = Path(out_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "ffmpeg", "-y", "-v", "error",
        "-i", str(src_file),
        "-c:v", cfg["vcodec"],
        "-preset", cfg["preset"],
        "-crf", str(cfg["crf"]),
        "-pix_fmt", cfg["pix_fmt"],
        "-threads", str(cfg["threads"]),
        "-g", str(cfg["gop"]),
        "-c:a", cfg["acodec"],
        "-b:a", cfg["audio_bitrate"],
        "-map_metadata", "-1",
        str(out_file),
    ]

    subprocess.run(cmd, check=True)
    out_bytes = out_file.read_bytes()
    out_sha = hashlib.sha256(out_bytes).hexdigest()

    meta = {
        "encoder": "ffmpeg",
        "encoder_version": get_ffmpeg_version(),
        "settings": cfg,
        "output_sha256": out_sha,
        "output_size": len(out_bytes),
    }
    return out_file, meta


def create_derivation_record(
    bundle_path: Path,
    segment_range: tuple[int, int],
    derived_file: Path,
    actor: KeyPair,
    settings: dict | None = None,
) -> dict:
    """Create and sign a derivation record linking sealed bundle range to derived media."""
    m, _ = Bundle(bundle_path).load_manifest()
    if m is None:
        raise ValueError("Invalid bundle manifest")

    rid = m.get("rid", "")
    derived_sha = hashlib.sha256(Path(derived_file).read_bytes()).hexdigest()

    rec = {
        "format": "evseal-derivation-v1",
        "rid": rid,
        "segment_range": list(segment_range),
        "encoder": "ffmpeg",
        "encoder_version": get_ffmpeg_version(),
        "settings": {**DEFAULT_SETTINGS, **(settings or {})},
        "output_sha256": derived_sha,
        "actor_fp": actor.fp,
        "actor_alg": actor.alg,
        "created_at": round(time.time(), 3),
    }

    digest = crypto.hashlib.new(crypto.FINGERPRINT_HASH, jcs(rec)).digest()
    rec["sig"] = actor.sign(digest).hex()
    return rec


def verify_derivation(
    bundle_path: Path,
    derivation_record: dict,
    derived_file: Path,
    trust: Trust,
    retranscode: bool = True,
) -> tuple[bool, str]:
    """Verify derivation record signature, output hash, and optional reproducible transcode."""
    rec = derivation_record
    if rec.get("format") != "evseal-derivation-v1":
        return False, f"unsupported derivation format {rec.get('format')}"

    # 1. Verify actor signature
    actor_fp = rec.get("actor_fp", "")
    key = trust.roots.get(actor_fp)
    if key is None:
        return False, f"derivation signer {actor_fp[:16]}… is not in trusted roots"

    body = {k: v for k, v in rec.items() if k != "sig"}
    digest = crypto.hashlib.new(crypto.FINGERPRINT_HASH, jcs(body)).digest()
    sig_bytes = bytes.fromhex(rec.get("sig", ""))

    if not crypto.verify(key["alg"], bytes.fromhex(key["pk"]), digest, sig_bytes):
        return False, "derivation record signature invalid"

    # 2. Check derived file hash
    derived_data = Path(derived_file).read_bytes()
    actual_sha = hashlib.sha256(derived_data).hexdigest()
    if actual_sha != rec.get("output_sha256"):
        return False, f"derived file hash mismatch (expected {rec.get('output_sha256')}, got {actual_sha})"

    # 3. Optional reproducible transcode verification from opened original
    if retranscode:
        with tempfile.TemporaryDirectory() as td:
            temp_dir = Path(td)
            opened_dir = temp_dir / "opened"
            try:
                rep, outputs = open_bundle(bundle_path, trust, opened_dir)
            except Exception as exc:
                return False, f"cannot open bundle for derivation check: {exc}"

            src_media = outputs.get("restored") or outputs.get("source")
            if not src_media or not Path(src_media).is_file():
                return False, "bundle did not restore source media file"

            test_out = temp_dir / "retranscoded.mp4"
            try:
                _, meta = transcode_deterministic(Path(src_media), test_out, settings=rec.get("settings"))
            except Exception as exc:
                return False, f"re-transcode failed: {exc}"

            if meta["output_sha256"] != rec.get("output_sha256"):
                return False, f"re-transcode bit-exact mismatch: generated {meta['output_sha256']}"

    return True, "verified reproducible derivation"
