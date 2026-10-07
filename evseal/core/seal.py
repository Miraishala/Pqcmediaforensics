"""Seal pipeline (SPEC §2): hash ∥ -> chain fold (sequential) -> sign + encrypt ∥ -> parity.

Units stream through in blocks, so the same loop serves Mode A (file export) and, later,
Mode B (live ingest). Each block's segments and records are fsync'd to the journal before the
next block starts, so a seal killed at any point leaves a bundle that verifies up to its last
durable record and reports UNSEALED_TAIL after the last checkpoint (SPEC §7C).

# ponytail: ThreadPoolExecutor, not ProcessPool — hashlib/AES/liboqs release the GIL so threads
# parallelise the heavy stages without pickling units; the pure-Python signer stays serial.
# Upgrade path: ProcessPoolExecutor for the signing stage if benchmarks on liboqs say so.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from evseal.core import crypto
from evseal.core.aead import aad, seal_chunk
from evseal.core.chain import chain_init, chain_step
from evseal.core.hashing import dual_hash
from evseal.core.kdf import derive_key_nonce
from evseal.core.manifest import (FORMAT, JOURNAL, Journal, block_msg, checkpoint_msg, compile_manifest, final_msg,
                                  gap_msg, jcs, seg_name, write_manifest)
from evseal.core.profile import check, profile_hash
from evseal.core.tilemerkle import merkle_root
from evseal.core.unit import SourceUnits, Unit
from evseal.longterm import keys
from evseal.longterm.anchorlog import AnchorLog
from evseal.longterm.timestamps import LocalTSA, stamp

GAP_PREFIX = b"evseal-gap:"
OPEN_END = 1e15  # "no upper bound" for a checkpoint key's footage window (JSON has no inf)

CONTAINER_MAP = {
    **{e: "video" for e in (".mp4", ".mov", ".m4v", ".mkv", ".avi", ".ts", ".mts", ".m2ts", ".h264", ".264", ".h265", ".265", ".hevc", ".dav")},
    **{e: "audio" for e in (".wav", ".mp3", ".m4a", ".aac", ".opus", ".ogg", ".flac", ".amr")},
    **{e: "image" for e in (".jpg", ".jpeg", ".png", ".tif", ".tiff", ".heic", ".heif", ".bmp", ".webp")},
}


def detect_kind(path: Path, profile: dict) -> str:
    path = Path(path)
    if path.is_dir():
        return "image"
    cmap = {**CONTAINER_MAP, **{k if k.startswith(".") else "." + k: v for k, v in profile["unit"]["container_map"].items()}}
    kind = cmap.get(path.suffix.lower())
    if kind is None:
        raise ValueError(f"unknown container {path.suffix!r} — add it to unit.container_map")
    return kind


def load_source(path: Path, profile: dict) -> SourceUnits:
    kind = detect_kind(path, profile)
    if kind == "image":
        from evseal.media.image import segment_images

        return segment_images(Path(path) if Path(path).is_dir() else [Path(path)], profile)
    if kind == "audio":
        from evseal.media.audio import segment_audio

        return segment_audio(path, profile)
    from evseal.media.video import segment_video

    return segment_video(path, profile)


def chunk_lengths(u: Unit, profile: dict, kind: str) -> list[int]:
    n = len(u.data)
    if u.role == "gap":
        return []
    if kind == "image":
        size = profile["image"]["aead_chunk_kb"] * 1024
        return [min(size, n - j) for j in range(0, n, size)] or [0]
    if profile["aead"]["chunk"] == "frame" and len(u.frame_offsets) > 1:
        cuts = sorted({0, *[f for f in u.frame_offsets if 0 < f < n], n})
        return [b - a for a, b in zip(cuts, cuts[1:])]
    return [n]


def unit_r(u: Unit, profile: dict) -> bytes:
    algs = profile["hash"]["content"]
    if u.role == "gap":
        return dual_hash(GAP_PREFIX + u.gap_reason.encode(), algs)
    r = dual_hash(u.data, algs)
    if "tiles" in u.meta:
        r += merkle_root(profile["hash"]["chain"], u.meta["tiles"]["leaves"])
    return r


def source_file_hash(src: Path, su: SourceUnits, algs: list[str]) -> bytes:
    """H(original input) for the final seal: the file's dual hash, or for an image set the dual
    hash of the canonical (name, dual hash) list."""
    if su.kind == "image":
        return dual_hash(jcs([[u.name, dual_hash(u.data, algs).hex()] for u in su.units if u.role == "data"]), algs)
    return dual_hash(Path(src).read_bytes(), algs)


def legacy_check(src: Path, claimed: dict[str, str]) -> dict:
    """SPEC §10: record and check an MD5/SHA-1 acquisition hash, flagged as classically broken."""
    out = {}
    if not claimed:
        return out
    data = Path(src).read_bytes() if Path(src).is_file() else b""
    for alg, value in claimed.items():
        alg = alg.lower()
        computed = hashlib.new(alg, data).hexdigest() if data else None
        out[alg] = {"claimed": value.lower(), "computed": computed, "match": computed == value.lower(),
                    "broken": alg in crypto.LEGACY_BROKEN_HASHES}
    return out


def _encrypt(u: Unit, i: int, c_i: bytes, rid: bytes, chunks: list[int], profile: dict) -> bytes:
    key, nonce = derive_key_nonce(c_i, rid, i, profile["kdf"]["alg"])
    ad, out, pos = aad(rid, i), [], 0
    for c, ln in enumerate(chunks):
        out.append(seal_chunk(profile["aead"]["alg"], key, nonce, c, u.data[pos : pos + ln], ad))
        pos += ln
    return b"".join(out)


def _write_seg(path: Path, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def seal(source: SourceUnits, profile: dict, root: keys.KeyPair, out_dir: Path, *, source_name: str = "",
         file_hash: bytes = b"", legacy: dict | None = None, tsa: LocalTSA | None = None,
         anchor_log: AnchorLog | None = None, progress=None) -> Path:
    profile = check(profile)
    progress = progress or (lambda *a: None)
    if tsa is None and not profile["timestamps"]["tsa_urls"]:
        # the verifier requires a token on every checkpoint and the final seal: fail now, not at verify time
        raise ValueError("no timestamp source: pass a TSA or set timestamps.tsa_urls (the bundle would never verify)")
    dev = [a for a in {profile["sign"]["alg"], profile["checkpoint"]["alg"], root.alg} if crypto.is_dev_only(a)]
    if dev and os.environ.get("EVSEAL_ALLOW_DEV_CRYPTO") != "1":
        raise RuntimeError(f"{', '.join(sorted(dev))} would run on the {crypto.DEV_ONLY_NOTE}. Build liboqs natively, "
                           "or set EVSEAL_ALLOW_DEV_CRYPTO=1 for throwaway UI/dev data")
    out = Path(out_dir)
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} is not empty")
    for d in ("segments", "parity", "certs", "anchors"):
        (out / d).mkdir(parents=True, exist_ok=True)
    (out / "certs" / "root.pub.json").write_text(json.dumps(root.public(), indent=1))

    rid, ph = os.urandom(32), profile_hash(profile)
    units, kind = source.units, source.kind
    data_units = [u for u in units if u.role == "data"]
    end_t = max((u.t + u.dur for u in data_units), default=0.0)
    for u in units:
        if u.role == "trailer":
            u.t = end_t  # framing after the last sample belongs to the last period
    n = len(units)
    rot = profile["keys"]["rotation_s"]
    top = None
    for i, u in enumerate(units, start=1):  # after the trailer fix-up above: framing units carry the end time
        p = int(u.t // rot)
        if top is not None and p < top:
            raise ValueError(f"unit {i} starts at t={u.t}s, in an earlier key period than a previous unit "
                             "(timestamps went backwards, e.g. PTS wrap or concatenated input): "
                             "the bundle would fail verification")
        top = p if top is None else max(top, p)
    w = profile["parallel"]["workers"]
    workers = (os.cpu_count() or 1) if w == "auto" else w
    chunks = [chunk_lengths(u, profile, kind) for u in units]

    with ThreadPoolExecutor(workers) as ex:
        progress("hash", 0, n)
        rs = list(ex.map(lambda u: unit_r(u, profile), units))  # stage 1 ∥
        progress("chain", 0, n)
        alg_c = profile["hash"]["chain"]
        cs = [chain_init(rid, ph, alg_c)]
        for i, r in enumerate(rs, start=1):  # stage 2: sequential fold, ~64 B of hashing per unit
            cs.append(chain_step(i, r, cs[-1], alg_c))

        genesis = {
            "format": FORMAT, "rid": rid.hex(), "profile": profile, "profile_hash": ph.hex(),
            "media": {"kind": kind, "source_name": source_name, "info": source.info, "units": n, "legacy_hashes": legacy or {}},
            "root": root.public(), "created": round(time.time(), 3), "tool": "evseal 0.1",
        }
        journal = Journal(out / JOURNAL, genesis)
        lines: list[dict] = []

        def emit(batch):
            journal.append(batch)
            lines.extend(batch)

        def anchor(kind_, i, c):
            if anchor_log is not None and profile["anchors"]["backend"] == "local-log":
                return anchor_log.append(kind=kind_, rid=rid.hex(), i=i, C=c.hex())
            return None

        anchors: list[dict] = []
        now = time.time()
        ck_key = keys.generate(profile["checkpoint"]["alg"], "checkpoint")
        ck_cert = keys.issue_cert(root, cert_id="checkpoint-0", role="checkpoint", subject=ck_key, rid=rid, profile_hash=ph,
                                  period=0, t_from=0.0, t_to=OPEN_END, not_before=now, not_after=now + profile["keys"]["rotation_s"] + 86400)
        emit([ck_cert])

        rot, blk_max = profile["keys"]["rotation_s"], profile["sign"]["block_segments"]
        blocks: list[list[int]] = []
        for i, u in enumerate(units, start=1):
            p = int(u.t // rot)
            if blocks and len(blocks[-1]) < blk_max and int(units[blocks[-1][0] - 1].t // rot) == p:
                blocks[-1].append(i)
            else:
                blocks.append([i])

        eph: keys.KeyPair | None = None
        eph_cert: dict | None = None
        interval, last_bucket = profile["checkpoint"]["interval_s"], 0
        crash_after = int(os.environ.get("EVSEAL_TEST_CRASH_AFTER_BLOCKS", "0")) if os.environ.get("EVSEAL_TEST_MODE") == "1" else 0  # test hook: simulated kill -9
        for b_no, blk in enumerate(blocks, start=1):
            p = int(units[blk[0] - 1].t // rot)
            if eph_cert is None or eph_cert["period"] != p:
                if eph is not None:
                    eph.wipe()  # period over: forward security
                eph = keys.generate(profile["sign"]["alg"], f"eph-{p}")
                t0 = time.time()
                eph_cert = keys.issue_cert(root, cert_id=f"eph-{p}", role="ephemeral", subject=eph, rid=rid, profile_hash=ph,
                                           period=p, t_from=float(p * rot), t_to=float((p + 1) * rot), not_before=t0, not_after=t0 + rot + 86400)  # a slow seal may outlive the period
                emit([eph_cert])
            cts = list(ex.map(lambda i: _encrypt(units[i - 1], i, cs[i], rid, chunks[i - 1], profile), blk))  # stage 3 ∥
            batch = []
            for i, ct in zip(blk, cts):
                u = units[i - 1]
                if u.role != "gap":
                    _write_seg(out / seg_name(i), ct)
                meta = {"i": i, "role": u.role, "off": u.offset, "len": len(u.data), "t": u.t, "dur": u.dur, "chunks": chunks[i - 1]}
                if u.name:
                    meta["name"] = u.name
                if u.role == "gap":
                    meta["gap"] = u.gap_reason
                meta.update(u.meta)
                batch.append({"type": "unit", "unit": meta})
                if u.role == "gap":
                    batch.append({"type": "gap", "i_start": i, "i_end": i, "reason": u.gap_reason, "cert": eph_cert["id"],
                                  "sig": eph.sign(gap_msg(rid, i, i, u.gap_reason)).hex()})
            tt = [[units[i - 1].t, units[i - 1].dur] for i in blk]  # unit times are signed (format v2, D6)
            sig = eph.sign(block_msg(rid, blk[0], blk[-1], [rs[i - 1] for i in blk], [cs[i] for i in blk], tt))
            batch.append({"type": "block", "i_start": blk[0], "i_end": blk[-1], "R": [rs[i - 1].hex() for i in blk],
                          "C": [cs[i].hex() for i in blk], "T": tt, "cert": eph_cert["id"], "sig": sig.hex()})
            last = units[blk[-1] - 1]
            bucket = int((last.t + last.dur) // interval)
            if bucket > last_bucket and blk[-1] < n:
                last_bucket = bucket
                i = blk[-1]
                msg = checkpoint_msg(rid, i, cs[i], i)
                batch.append({"type": "checkpoint", "i": i, "C": cs[i].hex(), "count": i, "t": last.t + last.dur,
                              "cert": ck_cert["id"], "sig": ck_key.sign(msg).hex(), "tst": stamp(profile, msg, tsa)})
                a = anchor("checkpoint", i, cs[i])
                anchors += [a] if a else []
            emit(batch)
            progress("seal", blk[-1], n)
            if crash_after and b_no >= crash_after:
                os._exit(137)

        msg = final_msg(rid, n, cs[n], file_hash)
        emit([{"type": "final", "n": n, "C_n": cs[n].hex(), "file_hash": file_hash.hex(), "cert": eph_cert["id"],
               "sig": eph.sign(msg).hex(), "tst": stamp(profile, msg, tsa)}])
        a = anchor("final", n, cs[n])
        anchors += [a] if a else []
        eph.wipe()
        ck_key.wipe()
        journal.close()

    progress("parity", 0, 1)
    manifest = compile_manifest(genesis, lines)
    from evseal.resilience.ec import build_parity

    manifest["ec"] = build_parity(out, manifest["units"], profile["ec"])
    (out / "anchors" / "anchors.jsonl").write_text("".join(json.dumps(a) + "\n" for a in anchors))
    progress("finalize", 0, 1)
    write_manifest(out, manifest)
    (out / JOURNAL).unlink()
    progress("done", n, n)
    return out


def seal_path(src: Path, profile: dict, root: keys.KeyPair, out_dir: Path, *, tsa: LocalTSA | None = None,
              anchor_log: AnchorLog | None = None, legacy_claims: dict | None = None, progress=None) -> Path:
    progress = progress or (lambda *a: None)
    progress("segment", 0, 1)
    su = load_source(Path(src), profile)
    fh = source_file_hash(src, su, profile["hash"]["content"])
    return seal(su, profile, root, out_dir, source_name=Path(src).name, file_hash=fh,
                legacy=legacy_check(src, legacy_claims or {}), tsa=tsa, anchor_log=anchor_log, progress=progress)
