"""Attack and fault injections (SPEC §7 B, C, G). Each takes (bundle_dir, rng, ctx, **params)
and mutates a *copy* of a sealed bundle the way an attacker or a failing disk would.

An attacker can do anything to the bundle bytes, including deriving K_i from the manifest's
C_i (verify-to-open is not confidentiality) and rewriting every manifest copy; what they
cannot do is produce signatures under the collector's keys. All randomness is seeded.
"""

from __future__ import annotations

import io
import os
import random
import shutil
from pathlib import Path

from evseal.core.aead import aad, open_chunk, seal_chunk
from evseal.core.crypto import AEAD_TAG_LEN
from evseal.core.manifest import Bundle, hexb, seg_name, write_manifest
from evseal.core.kdf import derive_key_nonce
from evseal.resilience import ec


def _m(bdir: Path) -> dict:
    m, _ = Bundle(bdir).load_manifest()
    return m


def _save(bdir: Path, m: dict) -> None:
    write_manifest(bdir, m)  # attacker rewrites every copy, incl. the RS copy


def _signed_c(m: dict, i: int) -> bytes:
    for r in m["records"]:
        if r.get("type") == "block" and r["i_start"] <= i <= r["i_end"]:
            return hexb(r["C"][i - r["i_start"]])
    raise KeyError(i)


def data_units(m: dict) -> list[int]:
    return [u["i"] for u in m["units"] if u["role"] == "data"]


def pick(m: dict, rng: random.Random, which) -> int:
    d = data_units(m)
    if which == "random":
        return rng.choice(d)
    if which == "last":
        return d[-1]
    return d[int(which) - 1] if int(which) <= len(d) else d[-1]  # 1-based among data units


def decrypt_unit(bdir: Path, m: dict, i: int) -> bytes:
    p, rid = m["profile"], hexb(m["rid"])
    key, nonce = derive_key_nonce(_signed_c(m, i), rid, i, p["kdf"]["alg"])
    meta = next(u for u in m["units"] if u["i"] == i)
    raw, out, pos = (Path(bdir) / seg_name(i)).read_bytes(), [], 0
    for c, ln in enumerate(meta["chunks"]):
        out.append(open_chunk(p["aead"]["alg"], key, nonce, c, raw[pos : pos + ln + AEAD_TAG_LEN], aad(rid, i)))
        pos += ln + AEAD_TAG_LEN
    return b"".join(out)


def reencrypt_unit(bdir: Path, m: dict, i: int, pt: bytes) -> None:
    """Attack 2: encrypt edited plaintext with the derived key; fix up manifest lengths."""
    p, rid = m["profile"], hexb(m["rid"])
    key, nonce = derive_key_nonce(_signed_c(m, i), rid, i, p["kdf"]["alg"])
    meta = next(u for u in m["units"] if u["i"] == i)
    size = max(meta["chunks"]) if meta["chunks"] else len(pt)
    lens = [min(size, len(pt) - j) for j in range(0, len(pt), size)] if len(meta["chunks"]) > 1 else [len(pt)]
    parts, pos = [], 0
    for c, ln in enumerate(lens):
        parts.append(seal_chunk(p["aead"]["alg"], key, nonce, c, pt[pos : pos + ln], aad(rid, i)))
        pos += ln
    (Path(bdir) / seg_name(i)).write_bytes(b"".join(parts))
    meta["chunks"], meta["len"] = lens, len(pt)
    _save(bdir, m)


def _flip(data: bytes, rng: random.Random, n: int = 1) -> bytes:
    b = bytearray(data)
    for _ in range(n):
        j = rng.randrange(len(b))
        b[j] ^= 1 << rng.randrange(8)
    return bytes(b)


# ---- SPEC §7B attacks ----


def bitflip(bdir, rng, ctx, unit="random", flips=1):
    m = _m(bdir)
    i = pick(m, rng, unit)
    f = Path(bdir) / seg_name(i)
    f.write_bytes(_flip(f.read_bytes(), rng, flips))
    return {"units": [i]}


def reencrypt_edit(bdir, rng, ctx, unit="random"):
    m = _m(bdir)
    i = pick(m, rng, unit)
    pt = decrypt_unit(bdir, m, i)
    reencrypt_unit(bdir, m, i, _flip(pt, rng, 4))
    return {"units": [i]}


def swap_foreign(bdir, rng, ctx, unit="random"):
    """Attack 3: splice in a unit's plaintext from another recording, re-encrypted with our K_i."""
    m = _m(bdir)
    i = pick(m, rng, unit)
    other = ctx["foreign"]
    om = _m(other)
    pt = decrypt_unit(other, om, pick(om, rng, "random"))
    reencrypt_unit(bdir, m, i, pt)
    return {"units": [i]}


def delete_units(bdir, rng, ctx, unit="random", count=1):
    """Attack 4: cut `count` units out and renumber the rest down (footage silently shortened)."""
    m = _m(bdir)
    i = pick(m, rng, unit)
    n = max(u["i"] for u in m["units"])
    for j in range(i, i + count):
        (Path(bdir) / seg_name(j)).unlink(missing_ok=True)
    for j in range(i + count, n + 1):
        src = Path(bdir) / seg_name(j)
        if src.exists():
            os.replace(src, Path(bdir) / seg_name(j - count))
    return {"units": list(range(i, n + 1))}


def insert_unit(bdir, rng, ctx, unit="random"):
    """Attack 5: insert a copy of an earlier unit at i, shift the rest up, extend the manifest."""
    m = _m(bdir)
    i = pick(m, rng, unit)
    n = max(u["i"] for u in m["units"])
    for j in range(n, i - 1, -1):
        src = Path(bdir) / seg_name(j)
        if src.exists():
            os.replace(src, Path(bdir) / seg_name(j + 1))
    shutil.copy(Path(bdir) / seg_name(i - 1 if i > 1 else i + 1), Path(bdir) / seg_name(i))
    last = dict(next(u for u in m["units"] if u["i"] == n))
    last["i"] = n + 1
    m["units"].append(last)
    _save(bdir, m)
    return {"units": list(range(i, n + 2))}


def reorder(bdir, rng, ctx, a="random", b=None):
    m = _m(bdir)
    i = pick(m, rng, a)
    d = data_units(m)
    j = d[(d.index(i) + 1) % len(d)] if b is None else pick(m, rng, b)
    fi, fj = Path(bdir) / seg_name(i), Path(bdir) / seg_name(j)
    tmp = fi.with_suffix(".tmp")
    os.replace(fi, tmp)
    os.replace(fj, fi)
    os.replace(tmp, fj)
    mi = next(u for u in m["units"] if u["i"] == i)
    mj = next(u for u in m["units"] if u["i"] == j)
    mi["chunks"], mj["chunks"], mi["len"], mj["len"] = mj["chunks"], mi["chunks"], mj["len"], mi["len"]
    _save(bdir, m)
    return {"units": [i, j]}


def truncate_tail(bdir, rng, ctx, count=1):
    """Attack 7: drop the last units, their records and the final seal."""
    m = _m(bdir)
    n = max(u["i"] for u in m["units"])
    cut = n - count + 1
    m["units"] = [u for u in m["units"] if u["i"] < cut]
    m["records"] = [r for r in m["records"] if r.get("type") != "final" and not (r.get("type") == "block" and r["i_end"] >= cut)]
    for j in range(cut, n + 1):
        (Path(bdir) / seg_name(j)).unlink(missing_ok=True)
    _save(bdir, m)
    return {"units": []}


def strip_manifest(bdir, rng, ctx):
    for name in ("manifest.json", "manifest.copy.json"):
        (Path(bdir) / name).unlink(missing_ok=True)
    shutil.rmtree(Path(bdir) / "manifest_rs", ignore_errors=True)
    return {}


def strip_signatures(bdir, rng, ctx):
    m = _m(bdir)
    m["records"] = [r for r in m["records"] if r.get("type") not in ("block", "final", "checkpoint")]
    _save(bdir, m)
    return {}


def profile_downgrade(bdir, rng, ctx, field="sign.alg", value="Ed25519", fix_hash=True):
    """Attack 9: edit the embedded profile (e.g. to a classical algorithm), optionally re-hash it."""
    from evseal.core.profile import profile_hash

    m = _m(bdir)
    g, k = field.split(".")
    m["profile"][g][k] = value
    if fix_hash:
        m["profile_hash"] = profile_hash(m["profile"]).hex()
    _save(bdir, m)
    return {}


def attacker_reseal(bdir, rng, ctx):
    """Attack 10: re-seal the same footage with an attacker-controlled root key."""
    from evseal.core.seal import seal_path
    from evseal.longterm import keys

    shutil.rmtree(bdir)
    evil = keys.generate(ctx["profile"]["keys"]["root_alg"], "attacker")
    seal_path(ctx["media"], ctx["profile"], evil, bdir, tsa=ctx["ws"].tsa(), anchor_log=None)
    return {}


def forge_with_leaked_key(bdir, rng, ctx, unit=None):
    """Attack 11: edit a unit of period q and sign a replacement block with period p's leaked key."""
    from evseal.core.chain import chain_step
    from evseal.core.hashing import dual_hash
    from evseal.core.manifest import block_msg

    m = _m(bdir)
    leaked = ctx["leaked"][0]  # earliest period's ephemeral key, captured at seal time
    rot = m["profile"]["keys"]["rotation_s"]
    later = [u for u in m["units"] if u["role"] == "data" and u["t"] >= rot]
    i = later[len(later) // 2]["i"] if unit is None else int(unit)
    pt = _flip(decrypt_unit(bdir, m, i), rng, 4)
    rid, p = hexb(m["rid"]), m["profile"]
    c_prev = _signed_c(m, i - 1)
    r_new = dual_hash(pt, p["hash"]["content"])
    c_new = chain_step(i, r_new, c_prev, p["hash"]["chain"])
    m["records"] = [r for r in m["records"] if not (r.get("type") == "block" and r["i_start"] <= i <= r["i_end"])]
    sig = leaked.sign(block_msg(rid, i, i, [r_new], [c_new]))
    m["records"].append({"type": "block", "i_start": i, "i_end": i, "R": [r_new.hex()], "C": [c_new.hex()],
                         "cert": "eph-0", "sig": sig.hex()})
    key, nonce = derive_key_nonce(c_new, rid, i, p["kdf"]["alg"])
    (Path(bdir) / seg_name(i)).write_bytes(seal_chunk(p["aead"]["alg"], key, nonce, 0, pt, aad(rid, i)))
    meta = next(u for u in m["units"] if u["i"] == i)
    meta["chunks"], meta["len"] = [len(pt)], len(pt)
    _save(bdir, m)
    return {"units": [i]}


def replay_block(bdir, rng, ctx, src="1", dst="3"):
    """Attack 12: move a valid block signature to another index."""
    m = _m(bdir)
    a, b = pick(m, rng, src), pick(m, rng, dst)
    blocks = [r for r in m["records"] if r.get("type") == "block"]
    rec = dict(next(r for r in blocks if r["i_start"] <= a <= r["i_end"]))
    rec["i_start"] = rec["i_end"] = b
    m["records"] = [r for r in m["records"] if not (r.get("type") == "block" and r["i_start"] <= b <= r["i_end"])] + [rec]
    _save(bdir, m)
    return {"units": [b]}


def forge_clip_boundary(bdir, rng, ctx):
    """Attack 14: export a clip, then forge its boundary C_{i-1}."""
    from evseal.core.clip import make_clip

    m = _m(bdir)
    d = data_units(m)
    i, j = d[len(d) // 2], d[len(d) // 2]
    tmp = Path(str(bdir) + ".clip")
    make_clip(bdir, i, j, tmp)
    shutil.rmtree(bdir)
    os.replace(tmp, bdir)
    cm = _m(bdir)
    for r in cm["records"]:
        if r.get("type") == "block" and r["i_start"] <= i - 1 <= r["i_end"]:
            k = i - 1 - r["i_start"]
            r["C"][k] = bytes(rng.randrange(256) for _ in range(len(hexb(r["C"][k])))).hex()
    _save(bdir, cm)
    return {"units": [i]}


# ---- SPEC §7C faults ----


def bitrot(bdir, rng, ctx, rate=1e-6):
    """Flip each bit of every segment/parity file independently with probability `rate`."""
    hit = []
    for f in sorted((Path(bdir) / "segments").glob("*.seg")) + sorted((Path(bdir) / "parity").glob("*.par")):
        data = bytearray(f.read_bytes())
        nbits = len(data) * 8
        flips = _binomial(rng, nbits, rate)
        for _ in range(flips):
            j = rng.randrange(nbits)
            data[j // 8] ^= 1 << (j % 8)
        if flips:
            f.write_bytes(bytes(data))
            if f.suffix == ".seg":
                hit.append(int(f.stem))
    return {"units": hit}


def _binomial(rng: random.Random, n: int, p: float) -> int:
    if n * p < 30:  # Poisson approximation, exact enough for fault injection
        k, t, lim = 0, rng.random(), pow(2.718281828459045, -n * p)
        while t > lim:
            t *= rng.random()
            k += 1
        return k
    return max(0, round(rng.gauss(n * p, (n * p * (1 - p)) ** 0.5)))


def burst(bdir, rng, ctx, length=2, start="random"):
    """Damage `length` consecutive sealed chunks (a bad disk region)."""
    m = _m(bdir)
    table = ec.chunk_table(m["units"])
    s = rng.randrange(len(table) - length + 1) if start == "random" else int(start)
    hit = set()
    for g in range(s, s + length):
        i, _, off, ln = table[g]
        f = Path(bdir) / seg_name(i)
        b = bytearray(f.read_bytes())
        b[off + ln // 2] ^= 0xFF
        f.write_bytes(bytes(b))
        hit.add(i)
    return {"units": sorted(hit)}


def lose_stripe_shards(bdir, rng, ctx, count=1, stripe=0):
    """Delete `count` data members of one stripe (whole segment files of single-chunk units)."""
    m = _m(bdir)
    info = m["ec"]
    table = ec.chunk_table(m["units"])
    members = ec.stripes(len(table), info["k"], info["interleave"])[stripe]
    lost = sorted({table[g][0] for g in rng.sample(members, min(count, len(members)))})
    for i in lost:
        (Path(bdir) / seg_name(i)).unlink()
    return {"units": lost}


def lose_manifest_copies(bdir, rng, ctx, which=("manifest.json",)):
    for name in which:
        p = Path(bdir) / name
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink(missing_ok=True)
    return {}


# ---- SPEC §7G image-set attacks (in-bundle) ----


def edit_image_region(bdir, rng, ctx, unit="random", box=(70, 70, 40, 30)):
    """Inpaint/paste a region of one photo, re-encrypted with the derived key."""
    from PIL import Image

    m = _m(bdir)
    i = pick(m, rng, unit)
    pt = decrypt_unit(bdir, m, i)
    src = Image.open(io.BytesIO(pt))
    fmt, exif = src.format, src.info.get("exif")
    x, y, w, h = box
    im = src.convert("RGB")
    im.paste((rng.randrange(256), 0, 255), (x, y, x + w, y + h))
    buf = io.BytesIO()
    im.save(buf, fmt, **({"quality": 90} if fmt == "JPEG" else {}), **({"exif": exif} if exif else {}))
    reencrypt_unit(bdir, m, i, buf.getvalue())
    return {"units": [i]}


def remove_photo(bdir, rng, ctx, unit="2"):
    return delete_units(bdir, rng, ctx, unit=unit, count=1)


ATTACKS = {f.__name__: f for f in (
    bitflip, reencrypt_edit, swap_foreign, delete_units, insert_unit, reorder, truncate_tail, strip_manifest,
    strip_signatures, profile_downgrade, attacker_reseal, forge_with_leaked_key, replay_block, forge_clip_boundary,
    bitrot, burst, lose_stripe_shards, lose_manifest_copies, edit_image_region, remove_photo,
)}


def describe() -> list[dict]:
    return [{"name": n, "doc": (f.__doc__ or "").strip().splitlines()[0] if f.__doc__ else n} for n, f in ATTACKS.items()]

