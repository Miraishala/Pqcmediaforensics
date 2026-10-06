"""Disaster-Recovery Geo-Split (SPEC §3.3 items 2–4).

Splits a bundle (or outer-encrypted container) into n fragments using zfec,
where any k fragments are sufficient to recover the original bit-exactly.
Untrusted sites cannot alter fragments without detection.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from pathlib import Path

from zfec import easyfec

from evseal.core.manifest import jcs, pack, unpack
from evseal.dr import custody

MAGIC_SHARD = b"EVSEAL-DR-SHARD1"  # 16 bytes


def split_bundle(
    input_path: Path,
    k: int,
    n: int,
    out_dir: Path,
    actor=None,
) -> list[Path]:
    """Split bundle directory or file into n self-contained shards, threshold k.

    Returns list of written shard file paths.
    """
    input_path = Path(input_path)
    out_dir = Path(out_dir)

    if not (1 <= k <= n <= 256):
        raise ValueError(f"Invalid parameters: require 1 <= k <= n <= 256, got k={k}, n={n}")

    # Read input payload
    with tempfile.TemporaryDirectory() as td:
        if input_path.is_dir():
            packed_path = Path(td) / "bundle.evseal"
            pack(input_path, packed_path)
            payload = packed_path.read_bytes()
        else:
            payload = input_path.read_bytes()

    data_len = len(payload)
    data_sha256 = hashlib.sha256(payload).hexdigest()

    # Encode into n shares via easyfec
    encoder = easyfec.Encoder(k, n)
    shares = encoder.encode(payload)
    padlen = (len(shares[0]) * k) - data_len
    shard_hashes = [hashlib.sha256(s).hexdigest() for s in shares]

    out_dir.mkdir(parents=True, exist_ok=True)
    out_paths = []

    for idx, share_bytes in enumerate(shares):
        hdr = {
            "format": "evseal-dr-shard-v1",
            "k": k,
            "n": n,
            "index": idx,
            "padlen": padlen,
            "data_len": data_len,
            "data_sha256": data_sha256,
            "shard_sha256": shard_hashes[idx],
            "shard_hashes": shard_hashes,
            "created_at": round(time.time(), 3),
        }
        hdr_bytes = jcs(hdr)

        shard_path = out_dir / f"shard_{idx:02d}.dr"
        with open(shard_path, "wb") as f:
            f.write(MAGIC_SHARD)
            f.write(len(hdr_bytes).to_bytes(4, "big"))
            f.write(hdr_bytes)
            f.write(share_bytes)
        out_paths.append(shard_path)

    # Custody log if actor provided and source is directory bundle
    if actor is not None and input_path.is_dir():
        custody.append(input_path, actor, "dr-split", {"k": k, "n": n, "shards": [p.name for p in out_paths]})

    return out_paths


def inspect_shard(shard_path: Path) -> dict:
    """Read and verify integrity of a single shard file."""
    p = Path(shard_path)
    data = p.read_bytes()
    if len(data) < len(MAGIC_SHARD) + 4:
        return {"ok": False, "reason": "file too small for shard container", "path": str(p)}
    if data[:len(MAGIC_SHARD)] != MAGIC_SHARD:
        return {"ok": False, "reason": "invalid shard magic", "path": str(p)}

    hdr_len = int.from_bytes(data[len(MAGIC_SHARD):len(MAGIC_SHARD) + 4], "big")
    offset = len(MAGIC_SHARD) + 4
    hdr_bytes = data[offset:offset + hdr_len]
    share_bytes = data[offset + hdr_len:]

    try:
        hdr = json.loads(hdr_bytes)
    except Exception as exc:
        return {"ok": False, "reason": f"malformed header JSON: {exc}", "path": str(p)}

    if hdr.get("format") != "evseal-dr-shard-v1":
        return {"ok": False, "reason": f"unsupported shard format: {hdr.get('format')}", "path": str(p)}

    idx = hdr.get("index")
    expected_hash = hdr.get("shard_sha256")
    actual_hash = hashlib.sha256(share_bytes).hexdigest()

    if actual_hash != expected_hash:
        return {
            "ok": False,
            "reason": f"shard {idx} data hash mismatch (expected {expected_hash}, got {actual_hash})",
            "path": str(p),
        }

    hashes_list = hdr.get("shard_hashes", [])
    if idx < 0 or idx >= len(hashes_list) or hashes_list[idx] != expected_hash:
        return {"ok": False, "reason": f"shard {idx} not consistent with shard_hashes list", "path": str(p)}

    return {
        "ok": True,
        "path": str(p),
        "header": hdr,
        "share_bytes": share_bytes,
    }


def recover_bundle(
    shards: list[Path] | Path,
    out_path: Path,
    actor=None,
) -> Path:
    """Recover bundle from at least k valid shards out of n.

    `shards` can be a list of shard file paths or a directory containing shard files.
    """
    out_path = Path(out_path)

    if isinstance(shards, Path) and shards.is_dir():
        shard_paths = sorted(shards.glob("*.dr"))
    elif isinstance(shards, (list, tuple)):
        shard_paths = [Path(p) for p in shards]
    else:
        shard_paths = [Path(shards)]

    # Inspect all candidate shards
    inspected = [inspect_shard(p) for p in shard_paths]
    valid = [s for s in inspected if s["ok"]]

    if not valid:
        reasons = [s["reason"] for s in inspected]
        raise ValueError(f"No valid shards available for recovery: {reasons}")

    # Check consistency across valid shards
    first_hdr = valid[0]["header"]
    k = first_hdr["k"]
    n = first_hdr["n"]
    data_sha256 = first_hdr["data_sha256"]
    padlen = first_hdr["padlen"]
    shard_hashes = first_hdr["shard_hashes"]

    # Deduplicate by index and ensure consensus
    by_index: dict[int, dict] = {}
    for s in valid:
        hdr = s["header"]
        if (hdr["k"], hdr["n"], hdr["data_sha256"], hdr["shard_hashes"]) != (k, n, data_sha256, shard_hashes):
            continue  # Shard from a different set or inconsistent
        if hdr["index"] not in by_index:
            by_index[hdr["index"]] = s

    if len(by_index) < k:
        raise ValueError(f"Insufficient valid shards for recovery: need {k}, have {len(by_index)}")

    # Pick first k unique shards
    selected = [by_index[idx] for idx in sorted(by_index.keys())[:k]]
    blocks = [s["share_bytes"] for s in selected]
    blocknums = [s["header"]["index"] for s in selected]

    decoder = easyfec.Decoder(k, n)
    recovered_data = decoder.decode(blocks, blocknums, padlen)

    # Verify recovered data SHA-256
    recovered_hash = hashlib.sha256(recovered_data).hexdigest()
    if recovered_hash != data_sha256:
        raise ValueError(f"Recovery failed: checksum mismatch (expected {data_sha256}, got {recovered_hash})")

    # Write output
    if out_path.suffix.lower() in (".zip", ".evseal", ".enc"):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(recovered_data)
    else:
        # Directory destination: unpack bundle
        out_path.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as td:
            temp_zip = Path(td) / "bundle.zip"
            temp_zip.write_bytes(recovered_data)
            unpack(temp_zip, out_path)

        if actor is not None:
            custody.append(out_path, actor, "dr-recover", {"k": k, "n": n, "used_shards": blocknums})

    return out_path
