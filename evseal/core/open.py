"""Verify-to-open (SPEC §2 step 4): restore a bundle or clip only after it verifies.

Output is written to a temporary file and only renamed into place once the overall verdict
is VERIFIED — fail closed. `partial=True` (examiner override) writes just the VERIFIED and
REPAIRED units, clearly named `.partial`, with the report beside it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from evseal.core.verify import OK, Report, verify
from evseal.longterm.keys import Trust


class NotVerified(Exception):
    def __init__(self, report: Report):
        super().__init__(f"refusing to open: overall {report.overall}; " + "; ".join(report.reasons[:5]))
        self.report = report


def open_bundle(path: Path, trust: Trust, out_dir: Path, *, partial: bool = False, preview: bool = True,
                replicas: tuple = ()) -> tuple[Report, dict]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    from evseal.core.manifest import Bundle

    manifest, _ = Bundle(Path(path)).load_manifest()
    is_image = (manifest or {}).get("media", {}).get("kind") == "image"
    tmp = out / ".opening.part"
    fh = open(tmp, "wb")
    image_out: dict[int, bytes] = {}

    def sink(i, pt, _res):
        if is_image:
            image_out[i] = pt
        else:
            fh.write(pt)  # timed media streams straight to disk, in index order

    try:
        rep = verify(path, trust, sink=sink, replicas=replicas)
    finally:
        fh.close()
    if rep.overall != "VERIFIED" and not partial:
        tmp.unlink(missing_ok=True)
        raise NotVerified(rep)
    suffix = "" if rep.overall == "VERIFIED" else ".partial"
    outputs: dict = {"report": str(out / "report.json")}
    (out / "report.json").write_text(json.dumps(rep.to_dict(), indent=1))
    kind = rep.media.get("kind")
    name = rep.media.get("source_name") or "restored"
    ok_units = [u for u in rep.units if u.status in OK]
    if kind == "image":
        tmp.unlink(missing_ok=True)
        files = []
        for u in ok_units:
            if u.role == "data":
                p = out / (Path(u.name).name + suffix)
                p.write_bytes(image_out[u.i])
                files.append(str(p))
        outputs["files"] = files
        return rep, outputs
    stem, ext = os.path.splitext(name)
    if rep.clip:
        stem = f"{stem}.clip_{rep.clip['i']}-{rep.clip['j']}"
    target = out / f"{stem}{ext}{suffix}"
    os.replace(tmp, target)
    outputs["restored"] = str(target)
    if preview and ok_units:
        from evseal.media.common import make_preview

        ok_idx = {u.i for u in ok_units}
        try:
            outputs["preview"] = str(make_preview(target, [u for u in manifest["units"] if u["i"] in ok_idx], rep, out))
        except Exception as exc:  # preview is a convenience; the restored file is the evidence
            outputs["preview_error"] = str(exc)
    return rep, outputs
