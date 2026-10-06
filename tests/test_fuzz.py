"""tests/test_fuzz.py — Automated fuzz testing for manifest and bundle trust boundaries (SPEC §7E)."""

from __future__ import annotations

import io
import os
import random
import zipfile
from pathlib import Path

import pytest

from evseal.core.manifest import Bundle, _parse, hexb, jcs, unpack
from tests.fuzz.fuzz_manifest import TestOneInput


def test_fuzz_manifest_random_inputs():
    """Fuzz _parse and hexb with random byte sequences and mutations."""
    rng = random.Random(42)

    # Completely random junk
    for _ in range(300):
        length = rng.randint(0, 1024)
        junk = rng.randbytes(length)
        TestOneInput(junk)

    # JSON-like corrupted variations
    valid_base = '{"format": "evseal-v1", "version": 1, "rid": "' + "a" * 64 + '"}'
    for _ in range(200):
        chars = list(valid_base)
        for _ in range(rng.randint(1, 5)):
            pos = rng.randint(0, len(chars) - 1)
            chars[pos] = chr(rng.randint(0, 255))
        mutated = "".join(chars).encode("utf-8", errors="ignore")
        TestOneInput(mutated)


def test_bundle_unpack_zip_slip_rejected(tmp_path):
    """Zip slip attempt with relative path traversal must be rejected with ValueError."""
    bad_zip_path = tmp_path / "bad.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.txt", b"malicious content")
    bad_zip_path.write_bytes(buf.getvalue())

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    with pytest.raises(ValueError, match="unsafe path in bundle"):
        unpack(bad_zip_path, dest_dir)


def test_bundle_corrupt_reads_fail_closed(tmp_path):
    """Reading corrupted or truncated bundle files never crashes."""
    fake_bundle = tmp_path / "corrupt_bundle"
    fake_bundle.mkdir()
    (fake_bundle / "manifest.json").write_bytes(b"\x00\xff\xfe\xca\xfe")

    bundle = Bundle(fake_bundle)
    m, src = bundle.load_manifest()
    assert m is None
    assert src in (None, "none")

    # Missing file returns None
    assert bundle.read("nonexistent.seg") is None
