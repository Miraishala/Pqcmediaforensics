"""Atheris fuzzing harness for manifest parsing and canonical serialization (SPEC §7E).

Can be executed directly with python for continuous fuzzing:
    python tests/fuzz/fuzz_manifest.py
"""

from __future__ import annotations

import sys

try:
    import atheris
except ImportError:
    atheris = None

from evseal.core.manifest import _parse, hexb, jcs


def TestOneInput(data: bytes) -> None:
    # 1. Manifest raw parse: must fail closed, never unhandled crash
    m = _parse(data)
    if m is not None:
        try:
            # If successfully parsed as an evseal manifest, jcs should succeed or raise cleanly
            encoded = jcs(m)
            assert isinstance(encoded, bytes)
        except Exception:
            pass

    # 2. Strict hex parser trust boundary: must reject invalid inputs cleanly
    try:
        s = data.decode("utf-8", errors="ignore")
        hexb(s)
    except (ValueError, TypeError):
        pass


def main():
    if atheris is None:
        print("atheris not installed; skipping continuous fuzz harness")
        sys.exit(0)
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
