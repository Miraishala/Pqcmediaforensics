"""Standalone-audio unit extraction (SPEC §9.1) — same packet-based segmentation as video,
with audio.segment_duration_s (call recordings, sting audio, voice notes)."""

from __future__ import annotations

from pathlib import Path

from evseal.core.unit import SourceUnits
from evseal.media.common import segment_file


def segment_audio(path: Path, profile: dict) -> SourceUnits:
    su = segment_file(path, profile["audio"]["segment_duration_s"], profile["segment"]["mode"],
                      max_unit_mb=profile["segment"].get("max_unit_mb", 0))
    su.kind = "audio"
    return su
