"""Verify-to-open key derivation (SPEC §2 step 4): (K_i, n_i) = HKDF(ikm=C_i, salt=rid, info="evseal-unit" || i)."""

from __future__ import annotations

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from evseal.core.crypto import AEAD_KEY_LEN, AEAD_NONCE_LEN, KDFS


def derive_key_nonce(c_i: bytes, rid: bytes, index: int, alg: str) -> tuple[bytes, bytes]:
    okm = HKDF(
        algorithm=KDFS[alg](),
        length=AEAD_KEY_LEN + AEAD_NONCE_LEN,
        salt=rid,
        info=b"evseal-unit" + index.to_bytes(8, "big"),
    ).derive(c_i)
    return okm[:AEAD_KEY_LEN], okm[AEAD_KEY_LEN:]
