"""The generic unit abstraction (SPEC §2 "Unit types"). A unit is indexed bytes plus a little
locating metadata — format-specific extraction (byte-range video/audio segments, ordered image
sets) lives in evseal/media/*.py, never here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ROLES = ("header", "data", "trailer", "gap")


@dataclass
class Unit:
    data: bytes
    role: str = "data"  # header/trailer = container framing (e.g. MP4 ftyp/moov), always in every clip
    offset: int = 0  # byte offset in the original file (timed media)
    t: float = 0.0  # start time, seconds from recording start (images: position in set)
    dur: float = 0.0
    name: str = ""  # images: original filename
    frame_offsets: list[int] = field(default_factory=list)  # packet starts within data (aead.chunk = frame)
    meta: dict = field(default_factory=dict)  # media-specific, e.g. tile leaves for tiled units
    gap_reason: str = ""  # role == "gap": why this index has no data (SPEC §2 step 8)


@dataclass
class SourceUnits:
    """Output of a media/*.py segmenter: ordered units, 1-based index = list position + 1."""

    kind: str  # video | audio | image
    units: list[Unit]
    info: dict = field(default_factory=dict)  # container / ffprobe summary, recorded in the manifest

    def reconstruct(self) -> bytes:
        """Timed media: header + data units + trailer in order equals the original input, bit-exact."""
        return b"".join(u.data for u in self.units)
