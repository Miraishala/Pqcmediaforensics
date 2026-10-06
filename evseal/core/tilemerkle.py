"""Generic tile-Merkle (SPEC §2.5): a tiled unit's R_i = dual_hash(S_i) || MerkleRoot(leaves).

Format-agnostic: a leaf is {"k": key, "h": hex} or, for advisory leaves that need their raw
value at verify time (perceptual thumbnails), {"k": key, "v": hex} whose hash is computed here.
Key prefixes: "t:" content tile, "m:" metadata (EXIF/XMP/ICC), "g:" global (dims, quant
tables), "p:" perceptual (advisory only, never a cryptographic verdict). Images use it now;
video-frame localization reuses it unchanged (SPEC §8 "Later").
"""

from __future__ import annotations

from evseal.core.hashing import chain_hash


def leaf_digest(alg: str, key: str, content: bytes) -> bytes:
    return chain_hash(b"\x00" + key.encode() + b"\x00" + content, alg)


def leaf_hash(alg: str, leaf: dict) -> bytes:
    if "v" in leaf:
        return leaf_digest(alg, leaf["k"], bytes.fromhex(leaf["v"]))
    return bytes.fromhex(leaf["h"])


def merkle_root(alg: str, leaves: list[dict]) -> bytes:
    """RFC 6962-style: interior nodes Hc(0x01 || left || right); odd node promoted."""
    level = [leaf_hash(alg, lf) for lf in leaves] or [chain_hash(b"\x00empty", alg)]
    while len(level) > 1:
        nxt = [chain_hash(b"\x01" + level[j] + level[j + 1], alg) for j in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def compare(alg: str, signed: list[dict], fresh: list[dict]) -> dict[str, str]:
    """Per-key cryptographic status for content/metadata/global leaves (not perceptual)."""
    fresh_map = {lf["k"]: leaf_hash(alg, lf) for lf in fresh if not lf["k"].startswith("p:")}
    out = {}
    for lf in signed:
        if lf["k"].startswith("p:"):
            continue
        got = fresh_map.get(lf["k"])
        out[lf["k"]] = "VERIFIED" if got == leaf_hash(alg, lf) else ("CORRUPT" if got is None else "TAMPERED")
    return out
