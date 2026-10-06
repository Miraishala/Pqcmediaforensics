"""Repair (SPEC §3.1, §6 Repair, §10 repair from replicas): plan, rebuild, write back, re-verify.

AEAD is deterministic for a given (K_i, n_i, aad), so a unit whose plaintext was rebuilt and
matched its signed R_i is re-encrypted to exactly its original ciphertext. Parity shards whose
hash no longer matches are recomputed from the (now good) stripe members. Every repair appends
a signed custody record.
"""

from __future__ import annotations

from pathlib import Path

from evseal.core.aead import aad, seal_chunk
from evseal.core.kdf import derive_key_nonce
from evseal.core.manifest import Bundle, hexb, seg_name, write_manifest
from evseal.core.verify import Report, verify
from evseal.longterm.keys import KeyPair, Trust
from evseal.resilience import ec


def plan(bundle: Path, trust: Trust, replicas: tuple = ()) -> dict:
    """What is damaged, which stripes it sits in, and whether repair will succeed (dry run)."""
    rep = verify(bundle, trust, repair=True, replicas=replicas)
    m, src = Bundle(Path(bundle)).load_manifest()
    info = (m or {}).get("ec") or {}
    table = ec.chunk_table(m["units"]) if m and info else []
    where = {(i, c): g for g, (i, c, _, _) in enumerate(table)}
    stripe_of = {}
    if info:
        for s, members in enumerate(ec.stripes(len(table), info["k"], info["interleave"])):
            for g in members:
                stripe_of[g] = s
    damaged = []
    for u in rep.units:
        if u.status in ("REPAIRED", "CORRUPT"):
            meta = next((x for x in m["units"] if x["i"] == u.i), {})
            chunks = list(range(len(meta.get("chunks", []))))
            damaged.append({"i": u.i, "status": u.status, "detail": u.detail, "repairable": u.status == "REPAIRED",
                            "stripes": sorted({stripe_of.get(where.get((u.i, c))) for c in chunks if (u.i, c) in where} - {None})})
    return {"overall": rep.overall, "manifest_source": src, "damaged": damaged,
            "ec": {k: info.get(k) for k in ("k", "m", "interleave")} if info else None,
            "repairable": all(d["repairable"] for d in damaged) and src in ("manifest.json", "manifest.copy.json", "manifest_rs")}


def run(bundle: Path, trust: Trust, actor: KeyPair | None = None, replicas: tuple = ()) -> tuple[Report, Report, list[int]]:
    """Repair in place. Returns (before, after, repaired unit indices)."""
    bdir = Path(bundle)
    if not bdir.is_dir():
        raise ValueError("repair needs a bundle directory (unpack a .evseal first)")
    rebuilt: dict[int, bytes] = {}

    def sink(i, pt, res):
        if res.status == "REPAIRED":
            rebuilt[i] = pt

    before = verify(bdir, trust, repair=True, replicas=replicas, sink=sink)
    b = Bundle(bdir)
    m, src = b.load_manifest()
    if m is None:
        raise ValueError("no recoverable manifest")
    profile, rid = m["profile"], hexb(m["rid"])
    signed_c = {u.i: hexb(u.C) for u in before.units if u.C}
    metas = {u["i"]: u for u in m["units"]}
    for i, pt in rebuilt.items():
        key, nonce = derive_key_nonce(signed_c[i], rid, i, profile["kdf"]["alg"])
        parts, pos = [], 0
        for c, ln in enumerate(metas[i]["chunks"]):
            parts.append(seal_chunk(profile["aead"]["alg"], key, nonce, c, pt[pos : pos + ln], aad(rid, i)))
            pos += ln
        (bdir / seg_name(i)).write_bytes(b"".join(parts))
    info = m.get("ec")
    if info:
        table = ec.chunk_table(m["units"])
        for s, members in enumerate(ec.stripes(len(table), info["k"], info["interleave"])):
            bad = [p for p in range(info["m"]) if (b.read(ec.par_name(s, p)) is None
                   or ec.shard_hash(b.read(ec.par_name(s, p))) != info["parity"][s][p])]
            if bad:
                blocks = []
                for g in members:
                    i, _, off, ln = table[g]
                    blocks.append(((bdir / seg_name(i)).read_bytes())[off : off + ln])
                for p, sh in enumerate(ec.encode(blocks, info["m"])):
                    if p in bad and ec.shard_hash(sh) == info["parity"][s][p]:
                        (bdir / ec.par_name(s, p)).write_bytes(sh)
    if src != "manifest.json" or b.read("manifest.copy.json") is None:
        write_manifest(bdir, m)  # restore every manifest copy from the recovered one
    if actor is not None and (rebuilt or src != "manifest.json"):
        from evseal.dr.custody import append

        append(bdir, actor, "repair", {"units": sorted(rebuilt), "manifest_source": src})
    after = verify(bdir, trust, repair=False)
    return before, after, sorted(rebuilt)
