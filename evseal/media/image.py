"""Image sets (SPEC §2 "Unit types", §2.5): ordering, gap detection, tile leaves, perceptual
advisory layer, copy comparison (LIKELY_EDITED / METADATA_CHANGED / DERIVED_COPY), heatmap.

Tile content basis (SPEC §2.5):
- JPEG: quantized DCT coefficients per tile, read losslessly with libjpeg (jpeglib) — the
  lossy IDCT never runs for a cryptographic leaf. Quant tables are a global leaf.
- PNG/TIFF/other Pillow formats, HEIC (pillow-heif; HEVC decode is bit-exact): raw pixels.
- EXIF/XMP/ICC: separate metadata leaves, so a metadata-only edit never looks like a content edit.
- Perceptual: per-tile 8x8 RGB thumbnail ("thumb8"; colour, so a same-luma edit still shows), signed but advisory only.
"""

from __future__ import annotations

import io
import re
import tempfile
from datetime import datetime
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

from evseal.core.tilemerkle import compare, leaf_digest
from evseal.core.unit import SourceUnits, Unit

try:  # HEIC/HEIF support is optional at runtime
    import pillow_heif

    pillow_heif.register_heif_opener()
except ImportError:  # pragma: no cover
    pass

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".heic", ".heif", ".bmp", ".webp"}
_JPEG = {".jpg", ".jpeg"}
_SEQ = re.compile(r"^(.*?)(\d+)(\.[^.]+)$")


def capture_time(data: bytes) -> float | None:
    try:
        exif = Image.open(io.BytesIO(data)).getexif()
        s = exif.get_ifd(0x8769).get(0x9003) or exif.get(0x0132)  # DateTimeOriginal, DateTime
        return datetime.strptime(str(s).strip("\x00 "), "%Y:%m:%d %H:%M:%S").timestamp() if s else None
    except Exception:
        return None


def _is_jpeg(data: bytes) -> bool:
    return data[:3] == b"\xff\xd8\xff"


def _dct(data: bytes):
    import jpeglib

    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        f.write(data)
        name = f.name
    try:
        im = jpeglib.read_dct(name)
        comps = [np.array(im.Y)] + ([np.array(im.Cb), np.array(im.Cr)] if im.has_chrominance else [])
        return comps, np.array(im.qt)
    finally:
        Path(name).unlink(missing_ok=True)


def _grid(w: int, h: int, tile: int) -> tuple[int, int]:
    return -(-w // tile), -(-h // tile)


def leaves(data: bytes, tile_px: int, alg: str, perceptual: str = "thumb8") -> dict:
    """Return {"w","h","tile","basis","leaves":[...]} for one image's bytes."""
    im = Image.open(io.BytesIO(data))
    w, h = im.size
    out: list[dict] = []

    def add(key: str, content: bytes):
        out.append({"k": key, "h": leaf_digest(alg, key, content).hex()})

    add("g:dims", f"{w}x{h}:{im.mode}".encode())
    for mk in ("exif", "xmp", "icc_profile"):
        v = im.info.get(mk)
        if v:
            add(f"m:{mk}", v if isinstance(v, bytes) else str(v).encode())
    nx, ny = _grid(w, h, tile_px)
    if _is_jpeg(data):
        basis = "jpeg-dct"
        tile = max(8, tile_px - tile_px % 8)
        nx, ny = _grid(w, h, tile)
        comps, qt = _dct(data)
        add("g:qt", qt.astype("<i2").tobytes())
        yb = tile // 8
        yh, yw = comps[0].shape[:2]
        for ty in range(ny):
            for tx in range(nx):
                parts = []
                for c in comps:
                    ch, cw = c.shape[:2]
                    r0, r1 = ty * yb * ch // yh, -(-(ty + 1) * yb * ch // yh)
                    c0, c1 = tx * yb * cw // yw, -(-(tx + 1) * yb * cw // yw)
                    parts.append(np.ascontiguousarray(c[r0:r1, c0:c1]).astype("<i2").tobytes())
                add(f"t:{tx},{ty}", b"|".join(parts))
    else:
        basis = "pixels"
        tile = tile_px
        arr = np.asarray(im)
        for ty in range(ny):
            for tx in range(nx):
                add(f"t:{tx},{ty}", np.ascontiguousarray(arr[ty * tile : (ty + 1) * tile, tx * tile : (tx + 1) * tile]).tobytes())
    if perceptual != "off":
        g = np.asarray(im.convert("RGB"))
        for ty in range(ny):
            for tx in range(nx):
                out.append({"k": f"p:{tx},{ty}", "v": _thumb(g[ty * tile : (ty + 1) * tile, tx * tile : (tx + 1) * tile]).hex()})
    return {"w": w, "h": h, "tile": tile, "basis": basis, "leaves": out}


def _thumb(region: np.ndarray) -> bytes:
    return Image.fromarray(region).resize((8, 8), Image.BOX).tobytes()


def segment_images(src: Path | list[Path], profile: dict) -> SourceUnits:
    """Order an image set (capture time then filename, or filename) and declare filename-sequence gaps."""
    paths = sorted(p for p in Path(src).iterdir() if p.suffix.lower() in IMAGE_EXTS) if not isinstance(src, list) else list(src)
    if not paths:
        raise ValueError(f"no images in {src}")
    cfg = profile["image"]
    items = []
    for p in paths:
        data = p.read_bytes()
        ct = capture_time(data) if cfg["set_order"] == "capture_time" else None
        items.append((ct if ct is not None else float("inf"), p.name, data))
    items.sort(key=lambda x: (x[0], x[1]))
    units: list[Unit] = []
    prev_seq = None
    for ct, name, data in items:
        m = _SEQ.match(name)
        seq = (m.group(1), int(m.group(2)), len(m.group(2)), m.group(3)) if m else None
        if seq and prev_seq and seq[0] == prev_seq[0] and seq[1] > prev_seq[1] + 1:
            for missing in range(prev_seq[1] + 1, seq[1]):
                units.append(Unit(data=b"", role="gap", gap_reason=f"expected {seq[0]}{missing:0{seq[2]}d}{seq[3]} never ingested"))
        prev_seq = seq if seq else prev_seq
        tiles = leaves(data, cfg["tile_px"], profile["hash"]["chain"], cfg["perceptual_hash"])
        units.append(Unit(data=data, name=name, meta={"tiles": tiles, "capture_time": None if ct == float("inf") else ct}))
    for n, u in enumerate(units):
        u.t, u.dur = float(n), 1.0
    return SourceUnits(kind="image", units=units, info={"count": sum(1 for u in units if u.role == "data"), "set_order": cfg["set_order"]})


# ---- comparison / localization ----


def _tile_xy(key: str) -> tuple[int, int]:
    x, y = key[2:].split(",")
    return int(x), int(y)


def tile_map(signed_tiles: dict, candidate: bytes, alg: str, threshold: float, original: bytes | None = None,
             in_bundle: bool = False) -> dict:
    """Localize differences between a sealed image (its signed leaves) and candidate bytes.

    verdict: VERIFIED | METADATA_CHANGED | TAMPERED | RECOMPRESSED | DERIVED_COPY | UNRELATED.
    Inside a bundle (in_bundle=True), cryptographic tile statuses always win (TAMPERED per tile),
    with perceptual distances attached as an advisory overlay.
    For external copies (in_bundle=False), LIKELY_EDITED appears when recompressed.
    """
    signed = signed_tiles["leaves"]
    try:
        fresh = leaves(candidate, signed_tiles["tile"], alg, "thumb8")
    except Exception as exc:
        tiles = []
        for lf in signed:
            if lf["k"].startswith("t:"):
                x, y = _tile_xy(lf["k"])
                tiles.append({"x": x, "y": y, "status": "CORRUPT"})
        return {"verdict": "CORRUPT", "detail": f"candidate does not decode: {exc}", "tile": signed_tiles.get("tile", 64),
                "w": signed_tiles.get("w", 0), "h": signed_tiles.get("h", 0), "metadata_changed": [], "tiles": tiles}
    if (fresh["w"], fresh["h"]) != (signed_tiles["w"], signed_tiles["h"]):
        return _derived(signed_tiles, candidate, original)
    st = compare(alg, signed, fresh["leaves"] if fresh["basis"] == signed_tiles["basis"] else [])
    content = {k: v for k, v in st.items() if k.startswith("t:")}
    meta_bad = [k for k, v in st.items() if k.startswith("m:") and v != "VERIFIED"]
    meta_bad += [lf["k"] for lf in fresh["leaves"] if lf["k"].startswith("m:") and lf["k"] not in st]
    bad = [k for k, v in content.items() if v != "VERIFIED"]
    tiles = []
    if content and len(bad) > len(content) / 2 and not in_bundle:
        # Recompressed (or re-encoded) copy: crypto can't say anything per tile; use the signed
        # perceptual thumbnails, advisory only.
        sp = {lf["k"]: bytes.fromhex(lf["v"]) for lf in signed if lf["k"].startswith("p:")}
        fp = {lf["k"]: bytes.fromhex(lf["v"]) for lf in fresh["leaves"] if lf["k"].startswith("p:")}
        for k in content:
            pk = "p:" + k[2:]
            d = float(np.abs(np.frombuffer(sp.get(pk, b""), np.uint8).astype(int) - np.frombuffer(fp.get(pk, b""), np.uint8).astype(int)).mean()) if pk in sp and pk in fp and len(sp[pk]) == len(fp[pk]) else 0.0
            x, y = _tile_xy(k)
            flagged = d > threshold
            tiles.append({"x": x, "y": y, "status": "LIKELY_EDITED" if flagged else "UNVERIFIED",
                          "confidence": round(min(1.0, d / (4 * threshold)), 3) if flagged else 0.0, "distance": round(d, 2)})
        verdict = "RECOMPRESSED"
    else:
        sp = {lf["k"]: bytes.fromhex(lf["v"]) for lf in signed if lf["k"].startswith("p:")}
        fp = {lf["k"]: bytes.fromhex(lf["v"]) for lf in fresh["leaves"] if lf["k"].startswith("p:")}
        for k, v in content.items():
            x, y = _tile_xy(k)
            tile_rec = {"x": x, "y": y, "status": "METADATA_CHANGED" if v == "VERIFIED" and meta_bad and not bad else v}
            pk = "p:" + k[2:]
            if pk in sp and pk in fp and len(sp[pk]) == len(fp[pk]):
                d = float(np.abs(np.frombuffer(sp[pk], np.uint8).astype(int) - np.frombuffer(fp[pk], np.uint8).astype(int)).mean())
                tile_rec["perceptual_distance"] = round(d, 2)
                tile_rec["perceptual_likely_edited"] = d > threshold
            tiles.append(tile_rec)
        verdict = "TAMPERED" if bad else ("METADATA_CHANGED" if meta_bad else "VERIFIED")
    return {"verdict": verdict, "tile": signed_tiles["tile"], "w": signed_tiles["w"], "h": signed_tiles["h"],
            "metadata_changed": sorted(set(meta_bad)), "tiles": tiles}


def _derived(signed_tiles: dict, candidate: bytes, original: bytes | None) -> dict:
    """DERIVED_COPY heuristic (SPEC §9.2): resize (same aspect) or crop (template match)."""
    base = {"tile": signed_tiles["tile"], "w": signed_tiles["w"], "h": signed_tiles["h"], "tiles": [], "metadata_changed": []}
    if original is None:
        return {**base, "verdict": "UNRELATED", "detail": "dimensions differ and no original available"}
    o = Image.open(io.BytesIO(original)).convert("L")
    c = Image.open(io.BytesIO(candidate)).convert("L")
    (ow, oh), (cw, ch) = o.size, c.size
    if abs(ow / oh - cw / ch) < 0.01:
        a = np.asarray(o.resize((64, 64), Image.BOX), float)
        b = np.asarray(c.resize((64, 64), Image.BOX), float)
        if np.abs(a - b).mean() < 6:
            return {**base, "verdict": "DERIVED_COPY", "relation": "resize", "detail": f"{ow}x{oh} -> {cw}x{ch}"}
    if cw <= ow and ch <= oh:
        s = 4  # search at 1/4 scale, then refine at full scale around the best offset
        os_ = np.asarray(o.resize((ow // s, oh // s), Image.BOX), float)
        cs = np.asarray(c.resize((max(1, cw // s), max(1, ch // s)), Image.BOX), float)
        best = (1e9, 0, 0)
        for y in range(os_.shape[0] - cs.shape[0] + 1):
            for x in range(os_.shape[1] - cs.shape[1] + 1):
                d = np.abs(os_[y : y + cs.shape[0], x : x + cs.shape[1]] - cs).mean()
                if d < best[0]:
                    best = (d, x, y)
        oa, ca = np.asarray(o, float), np.asarray(c, float)
        fine = min(
            ((np.abs(oa[y : y + ch, x : x + cw] - ca).mean(), x, y)
             for y in range(max(0, best[2] * s - s), min(oh - ch, best[2] * s + s) + 1)
             for x in range(max(0, best[1] * s - s), min(ow - cw, best[1] * s + s) + 1)),
            default=(1e9, 0, 0),
        )
        if fine[0] < 6:
            return {**base, "verdict": "DERIVED_COPY", "relation": "crop", "detail": f"crop {cw}x{ch} at ({fine[1]},{fine[2]})"}
    return {**base, "verdict": "UNRELATED", "detail": "dimensions differ; no crop/resize relationship found"}


_COLORS = {"VERIFIED": (22, 163, 74), "TAMPERED": (220, 38, 38), "CORRUPT": (124, 58, 237), "METADATA_CHANGED": (234, 179, 8),
           "LIKELY_EDITED": (249, 115, 22), "UNVERIFIED": (148, 163, 184)}


def heatmap(image: bytes, tmap: dict) -> bytes:
    """PNG overlay: each tile tinted by status (UI also shows icon + text, never colour alone)."""
    im = Image.open(io.BytesIO(image)).convert("RGBA")
    over = Image.new("RGBA", im.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(over)
    t = tmap.get("tile", 64)
    for tile in tmap.get("tiles", []):
        r, g, b = _COLORS.get(tile["status"], (0, 0, 0))
        x0, y0 = tile["x"] * t, tile["y"] * t
        draw.rectangle([x0, y0, x0 + t - 1, y0 + t - 1], fill=(r, g, b, 40 if tile["status"] == "VERIFIED" else 130), outline=(r, g, b, 200))
    buf = io.BytesIO()
    Image.alpha_composite(im, over).convert("RGB").save(buf, "PNG")
    return buf.getvalue()
