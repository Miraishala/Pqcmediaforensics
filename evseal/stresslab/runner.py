"""Stress Lab runner (SPEC §7): seal synthetic media, apply a scenario from expected.toml,
verify, and compare actual against expected. A mismatch is a bug, not a flaky test. Every
result records its seed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

from evseal.bench.synth import make_image, make_media
from evseal.core import profile as prof
from evseal.core.manifest import Bundle
from evseal.core.seal import seal_path
from evseal.core.verify import compare_copy, verify
from evseal.longterm import keys
from evseal.longterm.timestamps import LocalTSA
from evseal.stresslab.attacks import ATTACKS
from evseal.workspace import Workspace

EXPECTED = Path(__file__).with_name("expected.toml")

# Lab base profile: defaults, but small stripes so 6-second fixtures exercise RS, and ML-DSA-65
# checkpoints because the DEV-ONLY pure-Python SLH-DSA takes seconds per signature.
LAB_PROFILE = {"ec": {"k": 4, "m": 2, "interleave": 2}, "checkpoint": {"alg": "ML-DSA-65"}}


def load_expected(path: Path = EXPECTED) -> list[dict]:
    return tomllib.loads(Path(path).read_text(encoding="utf-8"))["scenario"]


@contextlib.contextmanager
def _capture_ephemeral(store: list):
    """Simulate a leaked ephemeral key (attack 11): keep a copy before the seal wipes it."""
    real = keys.KeyPair.wipe

    def wipe(self):
        if self.name.startswith("eph-") and self.sk:
            store.append(keys.KeyPair(self.alg, self.pk, bytearray(self.sk), self.name))
        real(self)

    keys.KeyPair.wipe = wipe
    try:
        yield
    finally:
        keys.KeyPair.wipe = real


class Lab:
    def __init__(self, workdir: Path, ws: Workspace | None = None):
        self.dir = Path(workdir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ws = ws or Workspace(self.dir / "ws")
        if not (self.ws.keys_dir / "lab-root.key.json").exists():
            self.ws.keygen("lab-root")
        self.root = self.ws.root("lab-root")
        self.media_dir = self.dir / "media"
        self.media_dir.mkdir(exist_ok=True)
        self._bases: dict[str, tuple[Path, dict]] = {}

    def media(self, name: str) -> Path:
        if name.startswith("images_"):
            d = self.media_dir / name
            if not d.exists():
                d.mkdir()
                ext = "png" if "png" in name else "jpg"
                nums = [1, 2, 4, 5] if "gap" in name else [1, 2, 3, 4]
                for k, n in enumerate(nums):
                    make_image(d / f"IMG_{n:04d}.{ext}", seed=n, exif_time=f"2024:05:0{k + 1} 10:00:00")
            return d
        if name == "long":  # 125 s: three rotation periods and two checkpoints at 60 s
            out = self.media_dir / "long"
            out.mkdir(exist_ok=True)
            return make_media("ts", out, duration_s=125, fps=5, gop=5)
        return make_media(name, self.media_dir, duration_s=6)

    def base(self, sc: dict) -> tuple[Path, dict]:
        """Seal (cached) the scenario's media with its profile; return (bundle, ctx)."""
        p = prof.resolve(prof._merge(prof._merge(prof.DEFAULTS, LAB_PROFILE), sc.get("profile", {})))
        leak = sc.get("attack") == "forge_with_leaked_key"
        offset = float(sc.get("tsa_offset_s", 0))
        key = hashlib.sha256(json.dumps([sc["media"], p, leak, offset], sort_keys=True).encode()).hexdigest()[:16]
        if key not in self._bases:
            out = self.dir / "bases" / key
            leaked: list = []
            if out.exists():
                shutil.rmtree(out)
            tsa = LocalTSA(self.ws.home / "tsa", clock=(lambda: time.time() + offset))
            with _capture_ephemeral(leaked) if leak else contextlib.nullcontext():
                seal_path(self.media(sc["media"]), p, self.root, out, tsa=tsa, anchor_log=self.ws.anchor_log())
            self._bases[key] = (out, {"profile": p, "leaked": leaked})
        return self._bases[key]

    def foreign(self, sc: dict) -> Path:
        other = dict(sc, media=sc.get("foreign_media", "mp4_fragmented" if sc["media"] != "mp4_fragmented" else "ts"))
        other.pop("attack", None)
        return self.base(other)[0]

    def run(self, sc: dict, seed: int = 1) -> dict:
        t0 = time.time()
        rng = random.Random(f"{seed}:{sc['id']}")
        res = {"id": sc["id"], "title": sc.get("title", ""), "seed": seed, "expected": _expected_view(sc)}
        try:
            if sc.get("kind") == "compare":
                actual = self._run_compare(sc, rng)
            elif sc.get("kind") == "crash":
                actual = self._run_crash(sc)
            else:
                actual = self._run_bundle(sc, rng)
            res["actual"] = actual
            res["mismatches"] = _mismatches(sc, actual)
        except Exception as exc:  # a crash is a mismatch too, with the reason kept
            res["actual"] = {"error": f"{type(exc).__name__}: {exc}"}
            res["mismatches"] = [f"scenario raised {type(exc).__name__}: {exc}"]
        res["pass"] = not res["mismatches"]
        res["seconds"] = round(time.time() - t0, 2)
        return res

    def _run_bundle(self, sc: dict, rng: random.Random) -> dict:
        base, ctx = self.base(sc)
        work = self.dir / "runs" / sc["id"]
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(base, work)
        ctx = dict(ctx, ws=self.ws, media=self.media(sc["media"]))
        if sc.get("attack") == "swap_foreign":
            ctx["foreign"] = self.foreign(sc)
        info = ATTACKS[sc["attack"]](work, rng, ctx, **sc.get("params", {})) if sc.get("attack") else {}
        rep = verify(work, self.ws.trust())
        return {"overall": rep.overall, "units": {u.i: u.status for u in rep.units}, "affected": info.get("units", []),
                "roles": {u.i: u.role for u in rep.units}, "reasons": rep.reasons[:6],
                "tiles": {u.i: _tile_counts(u.tiles) for u in rep.units if u.tiles}}

    def _run_compare(self, sc: dict, rng: random.Random) -> dict:
        from evseal.stresslab.transforms import TRANSFORMS

        base, ctx = self.base(sc)
        m, _ = Bundle(base).load_manifest()
        i = [u["i"] for u in m["units"] if u["role"] == "data"][int(sc.get("unit", 1)) - 1]
        src = self.media(sc["media"])
        name = next(u["name"] for u in m["units"] if u["i"] == i)
        cand = TRANSFORMS[sc["transform"]]((src / name).read_bytes(), rng, **sc.get("params", {}))
        out = compare_copy(base, self.ws.trust(), i, cand)
        return {"verdict": out["verdict"], "tiles": _tile_counts(out), "detail": out.get("detail", "")}

    def _run_crash(self, sc: dict) -> dict:
        """kill -9 mid-seal (deterministic: the seal process exits hard after N fsync'd blocks)."""
        p = prof.resolve(prof._merge(prof._merge(prof.DEFAULTS, LAB_PROFILE), sc.get("profile", {})))
        work = self.dir / "runs" / sc["id"]
        if work.exists():
            shutil.rmtree(work)
        prof_path = self.dir / f"{sc['id']}.toml"
        prof_path.write_text(prof.dumps(p))
        env = dict(os.environ, EVSEAL_TEST_CRASH_AFTER_BLOCKS=str(sc["params"]["after_blocks"]), EVSEAL_HOME=str(self.ws.home))
        code = (
            "import sys; from evseal.workspace import Workspace; from evseal.core import profile as P;"
            "from evseal.core.seal import seal_path; ws=Workspace();"
            f"seal_path(sys.argv[1], P.load(sys.argv[2]), ws.root('lab-root'), sys.argv[3], tsa=ws.tsa(), anchor_log=ws.anchor_log())"
        )
        r = subprocess.run([sys.executable, "-c", code, str(self.media(sc["media"])), str(prof_path), str(work)], env=env)
        rep = verify(work, self.ws.trust())
        return {"overall": rep.overall, "units": {u.i: u.status for u in rep.units}, "affected": [], "exit_code": r.returncode,
                "roles": {u.i: u.role for u in rep.units}, "reasons": rep.reasons[:6], "tiles": {}}


def _tile_counts(tmap: dict | None) -> dict:
    out: dict[str, int] = {}
    for t in (tmap or {}).get("tiles", []):
        out[t["status"]] = out.get(t["status"], 0) + 1
    return out


def _expected_view(sc: dict) -> dict:
    return {k: sc[k] for k in ("overall", "affected", "others", "any", "none", "verdict", "tiles", "tiles_min", "tiles_max",
                               "tail", "head") if k in sc}


def _mismatches(sc: dict, a: dict) -> list[str]:
    out = []
    if "verdict" in sc and a.get("verdict") != sc["verdict"]:
        out.append(f"verdict {a.get('verdict')} != expected {sc['verdict']}")
    for key, op in (("tiles", "=="), ("tiles_min", ">="), ("tiles_max", "<=")):
        for status, n in sc.get(key, {}).items():
            got = a.get("tiles", {}).get(status, 0) if "verdict" in sc else sum(t.get(status, 0) for t in a.get("tiles", {}).values())
            if not {"==": got == n, ">=": got >= n, "<=": got <= n}[op]:
                out.append(f"tiles[{status}] = {got}, expected {op} {n}")
    if "verdict" in sc:
        return out
    if "overall" in sc and a["overall"] != sc["overall"]:
        out.append(f"overall {a['overall']} != expected {sc['overall']}")
    units, affected = a["units"], set(a["affected"])
    data = [i for i, r in a["roles"].items() if r in ("data", "gap")]
    allowed = sc.get("affected")
    allowed = [allowed] if isinstance(allowed, str) else allowed
    if allowed:
        for i in affected:
            if units.get(i) not in allowed:
                out.append(f"affected unit {i}: {units.get(i)} not in {allowed}")
    if sc.get("others"):
        for i, st in units.items():
            if i not in affected and st != sc["others"] and a["roles"].get(i) != "gap":
                out.append(f"untouched unit {i}: {st} != {sc['others']}")
    for st in sc.get("any", []):
        if st not in units.values():
            out.append(f"no unit has status {st}")
    for st in sc.get("none", []):
        bad = [i for i in (affected or data) if units.get(i) == st]
        if bad:
            out.append(f"units {bad} unexpectedly {st}")
    if "tail" in sc:  # status of the last data units, e.g. UNSEALED_TAIL after a crash
        if not data or units.get(max(data)) != sc["tail"]:
            out.append(f"last unit {units.get(max(data)) if data else None} != {sc['tail']}")
    if "head" in sc and (not data or units.get(min(data)) != sc["head"]):
        out.append(f"first unit {units.get(min(data)) if data else None} != {sc['head']}")
    return out


def run_matrix(workdir: Path, ids: list[str] | None = None, seed: int = 1, full: bool = True, progress=None) -> list[dict]:
    lab = Lab(workdir)
    scs = [s for s in load_expected() if (ids is None or s["id"] in ids) and (full or not s.get("slow"))]
    out = []
    for n, sc in enumerate(scs):
        if progress:
            progress(sc["id"], n, len(scs))
        out.append(lab.run(sc, seed))
    return out

