"""The signed hash chain (SPEC §2): C_0 = Hc("evseal-v1" || rid || profile_hash); C_i = Hc(i || R_i || C_{i-1})."""

from __future__ import annotations

from evseal.core.hashing import chain_hash

MAGIC = b"evseal-v1"


def chain_init(rid: bytes, profile_hash: bytes, alg: str) -> bytes:
    return chain_hash(MAGIC + rid + profile_hash, alg)


def chain_step(index: int, r_i: bytes, c_prev: bytes, alg: str) -> bytes:
    return chain_hash(index.to_bytes(8, "big") + r_i + c_prev, alg)
