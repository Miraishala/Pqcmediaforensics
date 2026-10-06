"""Erasure coding (SPEC §3.1): zfec Reed–Solomon stripes over sealed AEAD chunks, interleaved.

- Shards are sealed (ciphertext) chunks in global order: unit 1 chunk 0, unit 1 chunk 1, ...
- Interleave depth D: chunks are grouped in runs of k*D; within a run, stripe t takes
  members t, t+D, t+2D, ... so a burst of up to D consecutive bad chunks hits each stripe once.
- A short final run yields stripes with fewer than k members (k_eff); parity is still m.
- Members are padded to the stripe's longest; true lengths come from the manifest.
- Bad shards are *located* by AEAD tag failure (data) or the manifest's parity hashes, so every
  fault is an erasure and RS corrects up to m per stripe, not m/2.
- A rebuilt chunk is accepted only if it then passes AEAD and its unit matches the signed R_i
  (enforced by core/verify.py, not here).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import zfec

from evseal.core.crypto import FINGERPRINT_HASH


def stripes(n_chunks: int, k: int, depth: int) -> list[list[int]]:
    out = []
    run = k * depth
    for base in range(0, n_chunks, run):
        for t in range(depth):
            members = [base + t + j * depth for j in range(k) if base + t + j * depth < n_chunks]
            if members:
                out.append(members)
    return out


def _pad(blocks: list[bytes]) -> list[bytes]:
    width = max(len(b) for b in blocks)
    return [b + b"\x00" * (width - len(b)) for b in blocks]


def encode(members: list[bytes], m: int) -> list[bytes]:
    k = len(members)
    padded = _pad(members)
    return zfec.Encoder(k, k + m).encode(padded, tuple(range(k, k + m)))


def decode(k: int, m: int, have: dict[int, bytes], lens: list[int]) -> list[bytes] | None:
    """have: shard number (0..k-1 data, k..k+m-1 parity) -> padded bytes. Returns k data members."""
    if len(have) < k:
        return None
    nums = sorted(have)[:k]
    width = max(len(have[n]) for n in nums)
    blocks = [have[n] + b"\x00" * (width - len(have[n])) for n in nums]
    out = zfec.Decoder(k, k + m).decode(blocks, nums)
    return [bytes(b)[:lens[j]] for j, b in enumerate(out)]


def shard_hash(b: bytes) -> str:
    return hashlib.new(FINGERPRINT_HASH, b).hexdigest()


def par_name(s: int, p: int) -> str:
    return f"parity/{s:06d}_{p}.par"


def chunk_table(units_meta: list[dict]) -> list[tuple[int, int, int, int]]:
    """Global shard order: (unit i, chunk c, byte offset in segment file, ciphertext length)."""
    from evseal.core.crypto import AEAD_TAG_LEN

    out = []
    for u in sorted(units_meta, key=lambda u: u["i"]):
        if u.get("role") == "gap":
            continue
        off = 0
        for c, ln in enumerate(u["chunks"]):
            out.append((u["i"], c, off, ln + AEAD_TAG_LEN))
            off += ln + AEAD_TAG_LEN
    return out


def build_parity(bundle_dir: Path, units_meta: list[dict], ec: dict) -> dict | None:
    from evseal.core.manifest import seg_name

    k, m, depth = ec["k"], ec["m"], ec["interleave"]
    if m == 0:
        return None
    table = chunk_table(units_meta)
    cache: dict[int, bytes] = {}

    def chunk(g: int) -> bytes:
        i, _, off, ln = table[g]
        if i not in cache:
            cache.clear()  # members are spread out; keep memory flat rather than clever
            cache[i] = (Path(bundle_dir) / seg_name(i)).read_bytes()
        return cache[i][off : off + ln]

    hashes = []
    for s, members in enumerate(stripes(len(table), k, depth)):
        par = encode([chunk(g) for g in members], m)
        for p, sh in enumerate(par):
            (Path(bundle_dir) / par_name(s, p)).write_bytes(sh)
        hashes.append([shard_hash(sh) for sh in par])
    return {"k": k, "m": m, "interleave": depth, "n_chunks": len(table), "parity": hashes}


# ---- manifest RS copy (SPEC §3.2) ----

_RS_DIR = "manifest_rs/"


def write_manifest_rs(bundle_dir: Path, data: bytes, k: int, m: int) -> None:
    d = Path(bundle_dir) / _RS_DIR
    d.mkdir(exist_ok=True)
    size = -(-len(data) // k)
    parts = [data[j * size : (j + 1) * size] for j in range(k)]
    parts = [p + b"\x00" * (size - len(p)) for p in parts]
    shards = parts + list(zfec.Encoder(k, k + m).encode(parts, tuple(range(k, k + m))))
    h = hashlib.new(FINGERPRINT_HASH, data).hexdigest()
    for idx, sh in enumerate(shards):
        hdr = json.dumps({"sha3": h, "len": len(data), "k": k, "m": m, "idx": idx, "sh": shard_hash(sh)}).encode()
        (d / f"{idx:02d}.shard").write_bytes(hdr + b"\n" + sh)


def read_manifest_rs(bundle) -> tuple[bytes | None, str | None]:
    """Return (decoded manifest bytes or None, majority manifest hash or None)."""
    good: dict[str, list[tuple[dict, bytes]]] = {}
    for name in bundle.list(_RS_DIR):
        raw = bundle.read(name)
        if raw is None or b"\n" not in raw:
            continue
        hdr_raw, sh = raw.split(b"\n", 1)
        try:
            hdr = json.loads(hdr_raw)
            if shard_hash(sh) != hdr["sh"]:
                continue
        except (ValueError, KeyError, TypeError):
            continue
        good.setdefault(hdr["sha3"], []).append((hdr, sh))
    if not good:
        return None, None
    h, shards = max(good.items(), key=lambda kv: len(kv[1]))
    k, m, n = shards[0][0]["k"], shards[0][0]["m"], shards[0][0]["len"]
    have = {hdr["idx"]: sh for hdr, sh in shards}
    if len(have) < k:
        return None, h
    nums = sorted(have)[:k]
    parts = zfec.Decoder(k, k + m).decode([have[x] for x in nums], nums)
    data = b"".join(bytes(p) for p in parts)[:n]
    return (data if hashlib.new(FINGERPRINT_HASH, data).hexdigest() == h else None), h
