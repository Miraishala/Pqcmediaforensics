"""DEV stand-in for an external signer (HSM / TPM / signing gateway), speaking the protocol that
`longterm.keys.KeyPair.sign` uses: message on stdin, algorithm in EVSEAL_SIGN_ALG, raw signature on stdout.

    python -m evseal.signer_stub path/to/private.key.json

A real deployment replaces this with a program that talks to the device (e.g. a PKCS#11 / vendor
PQ-capable module). This stub keeps the key in a file, so it demonstrates the interface, not the protection.
"""

from __future__ import annotations

import contextlib
import sys

with contextlib.redirect_stdout(sys.stderr):  # libraries may print banners; stdout carries only the signature
    from evseal.longterm import keys


def main(argv: list[str]) -> int:
    msg = sys.stdin.buffer.read()
    with contextlib.redirect_stdout(sys.stderr):  # first use of a backend may print too
        sig = keys.load_private(argv[1]).sign(msg)
    sys.stdout.buffer.write(sig)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
