"""Dual content hashing (SPEC §2: R_i = H1(S_i) || H2(S_i)) and the chain hash Hc.

Algorithm names come from the profile; the name->implementation map lives in core/crypto.py.
"""

from __future__ import annotations

import hashlib

from evseal.core.crypto import CHAIN_HASHES, CONTENT_HASHES


def digest_size(alg: str) -> int:
    return hashlib.new(CONTENT_HASHES.get(alg) or CHAIN_HASHES[alg]).digest_size


def dual_hash(data: bytes, algs: list[str] | tuple[str, ...]) -> bytes:
    """R_i = H1(S_i) || H2(S_i) — concatenated digests, in profile order."""
    return b"".join(hashlib.new(CONTENT_HASHES[a], data).digest() for a in algs)


def chain_hash(data: bytes, alg: str) -> bytes:
    return hashlib.new(CHAIN_HASHES[alg], data).digest()
