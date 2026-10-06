"""Clip package (SPEC §2): units i..j (sealed, never re-encrypted), the signed C_{i-1}, the signed
records covering i..j, the certificates, the nearest checkpoints and the final seal — verifies
and opens with no access to the source. Container header/trailer units ride along (SPEC §9.1).
"""

from __future__ import annotations

import shutil
from pathlib import Path

from evseal.core.manifest import Bundle, seg_name, write_manifest


def range_for_time(manifest: dict, t0: float, t1: float) -> tuple[int, int]:
    data = [u for u in manifest["units"] if u.get("role") in ("data", "gap")]
    hit = [u["i"] for u in data if u["t"] < t1 and u["t"] + max(u["dur"], 1e-9) > t0]
    if not hit:
        raise ValueError(f"no units between {t0}s and {t1}s")
    return min(hit), max(hit)


def make_clip(bundle_path: Path, i: int, j: int, out_dir: Path) -> Path:
    b = Bundle(Path(bundle_path))
    m, _ = b.load_manifest()
    if m is None:
        raise ValueError("bundle has no readable manifest")
    if "clip" in m:
        lo, hi = int(m["clip"]["i"]), int(m["clip"]["j"])
        if not (lo <= i <= j <= hi):
            raise ValueError(f"clip of a clip must stay within {lo}..{hi}")
    units = [u for u in m["units"] if i <= u["i"] <= j or u.get("role") in ("header", "trailer")]
    if not any(i <= u["i"] <= j for u in units):
        raise ValueError(f"no units in range {i}..{j}")
    recs = m["records"]
    cks = sorted((r for r in recs if r.get("type") == "checkpoint"), key=lambda r: r["i"])
    before = [r for r in cks if r["i"] < i][-1:]
    after = [r for r in cks if r["i"] > j][:1]
    chosen_ck = before + [r for r in cks if i <= r["i"] <= j] + after
    finals = [r for r in recs if r.get("type") == "final"]
    need = {u["i"] for u in units} | {u["i"] - 1 for u in units} | {r["i"] for r in chosen_ck} | {int(r["n"]) for r in finals}
    keep = []
    for r in recs:
        t = r.get("type")
        if t == "cert" or t == "final":
            keep.append(r)
        elif t == "block" and any(r["i_start"] <= x <= r["i_end"] for x in need):
            keep.append(r)
        elif t == "gap" and r["i_start"] <= j and r["i_end"] >= i:
            keep.append(r)
        elif t == "checkpoint" and r in chosen_ck:
            keep.append(r)
    clip = {k: v for k, v in m.items() if k not in ("units", "records", "ec", "reseals")}
    data_units = [u for u in units if i <= u["i"] <= j]
    clip.update(units=units, records=keep, ec=None, reseals=[],
                clip={"i": i, "j": j, "t_from": data_units[0]["t"], "t_to": data_units[-1]["t"] + data_units[-1]["dur"]})
    out = Path(out_dir)
    (out / "segments").mkdir(parents=True, exist_ok=False)
    (out / "certs").mkdir()
    for u in units:
        raw = b.read(seg_name(u["i"]))
        if raw is not None:
            (out / seg_name(u["i"])).write_bytes(raw)
    root = b.read("certs/root.pub.json")
    if root is not None:
        (out / "certs" / "root.pub.json").write_bytes(root)
    write_manifest(out, clip)
    return out


def copy_bundle(src: Path, dst: Path) -> Path:
    return Path(shutil.copytree(src, dst))
