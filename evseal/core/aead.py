"""AEAD seal/open for verify-to-open sealing (SPEC §2 step 4), per AEAD chunk.

A unit is sealed as one or more chunks (`aead.chunk` = segment | frame, `image.aead_chunk_kb`).
Chunk c uses nonce n_i XOR c (big-endian, low bytes) and aad = rid || i — so a single-chunk
unit is exactly the SPEC formula E_i = AEAD(K_i, n_i, S_i, aad = rid || i).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

from evseal.core.crypto import AEAD_TAG_LEN, AEADS


class TagMismatch(Exception):
    """AEAD authentication failed — maps to CORRUPT/SEQUENCE_ERROR in verify.py, never silently ignored."""


def chunk_nonce(nonce: bytes, c: int) -> bytes:
    return (int.from_bytes(nonce, "big") ^ c).to_bytes(len(nonce), "big")


def aad(rid: bytes, index: int) -> bytes:
    return rid + index.to_bytes(8, "big")


def seal_chunk(alg: str, key: bytes, nonce: bytes, c: int, plaintext: bytes, ad: bytes) -> bytes:
    return AEADS[alg](key).encrypt(chunk_nonce(nonce, c), plaintext, ad)


def open_chunk(alg: str, key: bytes, nonce: bytes, c: int, ciphertext: bytes, ad: bytes) -> bytes:
    try:
        return AEADS[alg](key).decrypt(chunk_nonce(nonce, c), ciphertext, ad)
    except InvalidTag as exc:
        raise TagMismatch(f"chunk {c}") from exc


def ct_len(plain_len: int) -> int:
    return plain_len + AEAD_TAG_LEN
