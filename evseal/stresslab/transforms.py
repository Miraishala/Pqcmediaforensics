"""Copy transforms for SPEC §7G comparisons: what happens to a photo outside the bundle
(EXIF edit, recompression, crop, a pasted region, a single changed pixel/coefficient)."""

from __future__ import annotations

import io
import random
import tempfile
from pathlib import Path

from PIL import Image


def _save(im: Image.Image, fmt: str, **kw) -> bytes:
    buf = io.BytesIO()
    im.save(buf, fmt, **kw)
    return buf.getvalue()


def identical(data: bytes, rng: random.Random) -> bytes:
    return data


def exif_edit(data: bytes, rng: random.Random) -> bytes:
    """Change only EXIF DateTimeOriginal; JPEG coefficients and quant tables stay untouched."""
    im = Image.open(io.BytesIO(data))
    exif = im.getexif()
    exif.get_ifd(0x8769)[0x9003] = "1999:01:01 00:00:00"
    payload = exif.tobytes()
    payload = payload if payload.startswith(b"Exif\x00\x00") else b"Exif\x00\x00" + payload
    if data[:2] != b"\xff\xd8":
        return _save(im, im.format, exif=payload)
    out, j = bytearray(data[:2]), 2  # splice a new APP1 in place of the old one (lossless)
    while j + 4 <= len(data) and data[j] == 0xFF and data[j + 1] != 0xDA:
        seglen = int.from_bytes(data[j + 2 : j + 4], "big")
        if data[j + 1] == 0xE1 and data[j + 4 : j + 8] == b"Exif":
            out += b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload
        else:
            out += data[j : j + 2 + seglen]
        j += 2 + seglen
    return bytes(out + data[j:])


def one_pixel(data: bytes, rng: random.Random, x: int = 100, y: int = 100) -> bytes:
    src = Image.open(io.BytesIO(data))
    im = src.convert("RGB")
    r, g, b = im.getpixel((x, y))
    im.putpixel((x, y), ((r + 1) % 256, g, b))
    return _save(im, "PNG", **({"exif": src.info["exif"]} if "exif" in src.info else {}))


def one_coefficient(data: bytes, rng: random.Random, bx: int = 12, by: int = 12) -> bytes:
    """Change a single quantized luma DCT coefficient (lossless DCT rewrite)."""
    import jpeglib

    with tempfile.TemporaryDirectory() as td:
        src, dst = Path(td) / "a.jpg", Path(td) / "b.jpg"
        src.write_bytes(data)
        im = jpeglib.read_dct(str(src))
        im.Y[by, bx, 0, 1] += 1
        im.write_dct(str(dst))
        return dst.read_bytes()


def recompress(data: bytes, rng: random.Random, quality: int = 75) -> bytes:
    im = Image.open(io.BytesIO(data))
    return _save(im.convert("RGB"), "JPEG", quality=quality)


def recompress_edit(data: bytes, rng: random.Random, box=(130, 64, 60, 60), quality: int = 75) -> bytes:
    im = Image.open(io.BytesIO(data)).convert("RGB")
    x, y, w, h = box
    im.paste((255, 0, 255), (x, y, x + w, y + h))
    return _save(im, "JPEG", quality=quality)


def crop(data: bytes, rng: random.Random, box=(40, 30, 200, 150)) -> bytes:
    im = Image.open(io.BytesIO(data))
    return _save(im.crop(box), "PNG")


def resize(data: bytes, rng: random.Random, scale: float = 0.5) -> bytes:
    im = Image.open(io.BytesIO(data))
    return _save(im.resize((int(im.width * scale), int(im.height * scale)), Image.LANCZOS), "PNG")


TRANSFORMS = {f.__name__: f for f in (identical, exif_edit, one_pixel, one_coefficient, recompress, recompress_edit, crop, resize)}
