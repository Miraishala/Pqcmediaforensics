"""Shared byte-range segmentation (SPEC §9.1): cut at packet boundaries, sorted by byte
position, so concatenating every unit reproduces the input bit-exactly — by construction,
because units are a partition of the file's bytes.

Spike findings (tests/test_media.py, ffmpeg-muxed fixtures):
- MP4 (moov-at-end / faststart), raw H.264/H.265, WAV, MP3, M4A: packets are contiguous.
- Fragmented MP4: `moof` boxes sit between fragments -> a cut moves back to the `moof`
  start so each fragment's framing travels with its samples.
- MPEG-TS: many packets have no `pos`, and PES sizes don't match on-disk spans -> no
  contiguity at all; positioned keyframe packets still start on 188-byte TS packets.
- Ogg/Opus: packets share pages (pos = page start), so positions overlap -> cut points are
  de-duplicated page starts.
None of this affects bit-exactness — only how cleanly a clip remuxes for playback.

Cuts land on keyframes of the primary stream (video if any, else audio — where every
packet is a keyframe), targeting the requested duration. Bytes before the first packet
(e.g. ftyp/moov) become a `header` unit, bytes after the last a `trailer` unit (moov-at-end).
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from evseal.core.unit import SourceUnits, Unit


@dataclass(frozen=True)
class _Packet:
    stream_index: int
    pos: int
    size: int
    pts_time: float | None  # None when the demuxer exposes no timing (raw Annex B)
    key: bool


def _ffprobe_json(args: list[str]) -> dict:
    out = subprocess.run(["ffprobe", "-v", "quiet", "-print_format", "json", *args], capture_output=True, check=True)
    return json.loads(out.stdout)


def probe(path: Path) -> tuple[list[_Packet], list[dict], dict]:
    d = _ffprobe_json(
        ["-show_packets", "-show_streams", "-show_format", "-show_entries",
         "packet=pos,size,pts_time,dts_time,stream_index,flags", str(path)]
    )
    packets = []
    for p in d.get("packets", []):
        if p.get("pos") in (None, "N/A"):
            continue  # e.g. MPEG-TS: payload of a PES already positioned elsewhere
        t = p.get("pts_time", p.get("dts_time"))
        packets.append(
            _Packet(int(p["stream_index"]), int(p["pos"]), int(p["size"]),
                    float(t) if t not in (None, "N/A") else None, "K" in p.get("flags", ""))
        )
    if not packets:
        raise ValueError(f"no positioned packets in {path} — use segment.mode = remux")
    return sorted(packets, key=lambda pk: pk.pos), d.get("streams", []), d.get("format", {})


def _primary_stream(streams: list[dict], packets: list[_Packet]) -> int:
    for kind in ("video", "audio"):
        for s in streams:
            if s.get("codec_type") == kind:
                return int(s["index"])
    return packets[0].stream_index


def _fps(streams: list[dict], idx: int) -> float | None:
    for s in streams:
        if int(s.get("index", -1)) == idx:
            num, _, den = (s.get("avg_frame_rate") or s.get("r_frame_rate") or "0/0").partition("/")
            if float(den or 1) and float(num):
                return float(num) / float(den or 1)
    return None


def _cut_times(packets, streams, duration_s, assumed_fps) -> tuple[list[tuple[int, float]], float]:
    """Return ([(pos, t)] for each unit start among primary-stream keyframes, total duration)."""
    idx = _primary_stream(streams, packets)
    prim = [p for p in packets if p.stream_index == idx]
    if any(p.pts_time is not None for p in prim):
        t0 = min(p.pts_time for p in prim if p.pts_time is not None)
        timed = sorted(((p.pts_time - t0, p) for p in prim if p.pts_time is not None), key=lambda tp: tp[0])
        step = (timed[-1][0] / (len(timed) - 1)) if len(timed) > 1 else duration_s
    else:
        # ponytail: raw elementary streams carry no timing and ffprobe's frame-rate guess is
        # wrong for them (a 10 fps source reports 25/1). Times are frame_index / fps, with fps
        # from segment.assumed_fps when set. Never affects bit-exactness, only unit durations.
        # Upgrade path: take fps from DVR export metadata once a real sample exists (SPEC §9.1).
        fps = assumed_fps or _fps(streams, idx) or 25.0
        timed = [(n / fps, p) for n, p in enumerate(prim)]
        step = 1 / fps
    cuts, next_t = [], 0.0
    for t, p in timed:
        if p.key and t >= next_t - 1e-6:
            cuts.append((p.pos, t))
            next_t = t + duration_s
    return cuts, timed[-1][0] + step


def segment_bytes(path: Path, duration_s: float, assumed_fps: float = 0.0) -> SourceUnits:
    path = Path(path)
    data = path.read_bytes()
    packets, streams, fmt = probe(path)
    first, last_end = packets[0].pos, min(len(data), max(p.pos + p.size for p in packets))
    prev_end: dict[int, int] = {}
    for a, b in zip(packets, packets[1:]):
        prev_end[b.pos] = max(prev_end.get(b.pos, 0), a.pos + a.size)

    cuts, total_t = _cut_times(packets, streams, duration_s, assumed_fps)
    starts: list[tuple[int, float]] = []
    for pos, t in cuts:
        pe = prev_end.get(pos)
        if pe is not None and pe < pos and data[pe + 4 : pe + 8] == b"moof":
            pos = pe  # fragmented MP4: keep the fragment's moof with its samples
        if (not starts or pos > starts[-1][0]) and pos < last_end:
            starts.append((pos, t))
    if not starts:
        starts = [(first, 0.0)]
    starts[0] = (first, 0.0)  # packets before the first keyframe (e.g. leading audio) join unit 1

    units: list[Unit] = []
    if first > 0:
        units.append(Unit(data=data[:first], role="header", offset=0))
    pkt_pos = sorted({p.pos for p in packets})
    for n, (pos, t) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else last_end
        nxt_t = starts[n + 1][1] if n + 1 < len(starts) else total_t
        frames = [p - pos for p in pkt_pos if pos <= p < end]
        units.append(Unit(data=data[pos:end], offset=pos, t=round(t, 6), dur=round(max(nxt_t - t, 0.0), 6), frame_offsets=frames))
    if last_end < len(data):
        units.append(Unit(data=data[last_end:], role="trailer", offset=last_end))
    info = {
        "container": fmt.get("format_name"),
        "duration_s": float(fmt["duration"]) if fmt.get("duration") not in (None, "N/A") else round(total_t, 6),
        "streams": [{"index": s.get("index"), "type": s.get("codec_type"), "codec": s.get("codec_name")} for s in streams],
        "segment_mode": "byte-range",
    }
    return SourceUnits(kind="", units=units, info=info)


def segment_remux(path: Path, duration_s: float) -> SourceUnits:
    """Fallback (SPEC §9.1): stream-copy into independent TS segments. Frames stay
    bit-identical but the container is new; the original file's hash is still in the final seal."""
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(
            ["ffmpeg", "-v", "error", "-i", str(path), "-map", "0", "-c", "copy", "-f", "segment",
             "-segment_time", str(duration_s), "-segment_format", "mpegts", "-reset_timestamps", "0",
             str(Path(td) / "%06d.ts")],
            check=True,
        )
        units, t = [], 0.0
        for f in sorted(Path(td).glob("*.ts")):
            fmt = _ffprobe_json(["-show_format", str(f)]).get("format", {})
            dur = float(fmt.get("duration") or duration_s)
            units.append(Unit(data=f.read_bytes(), t=round(t, 6), dur=round(dur, 6)))
            t += dur
    return SourceUnits(kind="", units=units, info={"container": "mpegts", "segment_mode": "remux", "duration_s": round(t, 6)})


def segment_file(path: Path, duration_s: float, mode: str = "byte-range", assumed_fps: float = 0.0) -> SourceUnits:
    if mode == "remux":
        return segment_remux(path, duration_s)
    return segment_bytes(path, duration_s, assumed_fps)


def make_preview(restored: Path, units: list[dict], report, out_dir: Path) -> Path:
    """Playable preview (SPEC §6 Clip & Open) next to the bit-exact restored file.

    A clip of an MP4/MOV keeps the original moov, whose sample offsets point into the full
    file, so its bytes are laid back at their original offsets (zero-filled elsewhere) before
    ffmpeg stream-copies the clip's time range. TS / fMP4 / raw / audio clips play as-is.

    # ponytail: the sparse layout is as large as the original file. Upgrade path: rewrite
    # stco/co64 offsets in the clip's moov instead.
    """
    kind = report.media.get("kind")
    container = (report.media.get("info") or {}).get("container") or ""
    src = Path(restored)
    pre_in: list[str] = []
    if report.clip:
        if any(x in container for x in ("mp4", "mov")) and any(u.get("role") == "header" for u in units):
            sparse = Path(out_dir) / ".sparse.bin"
            data = src.read_bytes()
            with open(sparse, "wb") as f:
                f.truncate(max(u["off"] + u["len"] for u in units))
                pos = 0
                for u in sorted(units, key=lambda u: u["i"]):
                    f.seek(u["off"])
                    f.write(data[pos : pos + u["len"]])
                    pos += u["len"]
            src = sparse
        pre_in = ["-ss", str(report.clip["t_from"]), "-to", str(report.clip["t_to"])]
    out = Path(out_dir) / ("preview.mp4" if kind == "video" else "preview.m4a")
    base = ["ffmpeg", "-y", "-v", "error", "-fflags", "+genpts+discardcorrupt", *pre_in, "-i", str(src)]
    maps = ["-map", "0:v:0?", "-map", "0:a:0?"] if kind == "video" else ["-map", "0:a:0"]
    tries = [["-c", "copy"], ["-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p", "-c:a", "aac"]]
    err = ""
    for codec in tries:
        r = subprocess.run([*base, *maps, *codec, "-movflags", "+faststart", str(out)], capture_output=True, text=True)
        if r.returncode == 0 and out.exists() and out.stat().st_size > 0:
            break
        err = r.stderr[-500:]
    else:
        raise RuntimeError(f"preview failed: {err}")
    if src.name == ".sparse.bin":
        src.unlink(missing_ok=True)
    return out
