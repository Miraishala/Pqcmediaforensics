"""Video/AV unit extraction (SPEC §9.1) — selects segment.duration_s. Audio inside an AV file
is covered by the same byte-range units (SPEC §2 "Unit types")."""

from __future__ import annotations

from pathlib import Path

from evseal.core.unit import SourceUnits
from evseal.media.common import segment_file


def segment_video(path: Path, profile: dict) -> SourceUnits:
    s = profile["segment"]
    su = segment_file(path, s["duration_s"], s["mode"], s["assumed_fps"])
    su.kind = "video"
    return su
