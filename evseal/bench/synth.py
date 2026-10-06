"""Synthetic footage/audio/image generator (SPEC §7F) — ffmpeg testsrc2 + noise, sine audio.

Used by tests (spike formats, SPEC §9.1) and by benchmarks. Deterministic inputs; ffmpeg
version may still change exact bytes, which is fine — tests only compare a file to itself.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_V = ["-f", "lavfi", "-i", "testsrc2=size=320x240:rate={fps}:duration={d}"]
_A = ["-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration={d}"]
_H264 = ["-c:v", "libx264", "-preset", "ultrafast", "-g", "{g}", "-pix_fmt", "yuv420p", "-threads", "1"]

# name -> (inputs, codec args, extension). {d}=duration s, {fps}, {g}=GOP frames
FORMATS: dict[str, tuple[list[str], list[str], str]] = {
    "mp4_moovend": (_V + _A, _H264 + ["-c:a", "aac", "-b:a", "64k"], "mp4"),
    "mp4_faststart": (_V + _A, _H264 + ["-c:a", "aac", "-b:a", "64k", "-movflags", "+faststart"], "mp4"),
    "mp4_fragmented": (_V + _A, _H264 + ["-c:a", "aac", "-b:a", "64k", "-movflags", "frag_keyframe+empty_moov"], "mp4"),
    "ts": (_V + _A, _H264 + ["-c:a", "aac", "-b:a", "64k", "-f", "mpegts"], "ts"),
    "h264": (_V, _H264 + ["-f", "h264"], "h264"),
    "h265": (_V, ["-c:v", "libx265", "-preset", "ultrafast", "-x265-params", "keyint={g}:log-level=none", "-f", "hevc"], "h265"),
    "wav": (_A, ["-c:a", "pcm_s16le"], "wav"),
    "mp3": (_A, ["-c:a", "libmp3lame", "-b:a", "64k"], "mp3"),
    "m4a": (_A, ["-c:a", "aac", "-b:a", "64k"], "m4a"),
    "opus": (_A, ["-c:a", "opus", "-strict", "-2", "-b:a", "64k"], "opus"),
}


def make_media(fmt: str, out_dir: Path, duration_s: float = 4, fps: int = 10, gop: int = 10) -> Path:
    """Generate one synthetic file. GOP == fps by default, so keyframes land every 1 s."""
    inputs, codec, ext = FORMATS[fmt]
    out = Path(out_dir) / f"{fmt}.{ext}"
    if out.exists():
        return out
    fill = {"d": duration_s, "fps": fps, "g": gop}
    args = [a.format(**fill) for a in inputs + codec]
    if shutil.which("ffmpeg") is None:
        raise RuntimeError("ffmpeg not on PATH")
    subprocess.run(["ffmpeg", "-y", "-v", "error", *args, "-map_metadata", "-1", str(out)], check=True)
    return out


def make_image(path: Path, size: tuple[int, int] = (256, 192), seed: int = 0, fmt: str | None = None, exif_time: str | None = None) -> Path:
    """A deterministic photo-like image (gradient + seeded noise + shapes)."""
    import numpy as np
    from PIL import Image

    rng = np.random.default_rng(seed)
    w, h = size
    y, x = np.mgrid[0:h, 0:w]
    base = np.stack([(x * 255 // max(w - 1, 1)), (y * 255 // max(h - 1, 1)), ((x + y) * 127 // max(w + h - 2, 1))], -1)
    img = (base + rng.integers(-20, 20, (h, w, 3))).clip(0, 255).astype("uint8")
    for _ in range(4):
        cx, cy, r = rng.integers(0, w), rng.integers(0, h), rng.integers(8, 40)
        img[(x - cx) ** 2 + (y - cy) ** 2 < r * r] = rng.integers(0, 255, 3)
    im = Image.fromarray(img)
    path = Path(path)
    kwargs = {}
    if exif_time:
        exif = Image.Exif()
        exif.get_ifd(0x8769)[0x9003] = exif_time  # DateTimeOriginal
        kwargs["exif"] = exif.tobytes()
    if (fmt or path.suffix.lower().lstrip(".")) in ("jpg", "jpeg"):
        kwargs["quality"] = 90
    im.save(path, format=fmt, **kwargs)
    return path
