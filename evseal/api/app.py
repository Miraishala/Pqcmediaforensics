"""FastAPI backend for the UI (SPEC §6). Thin: every operation calls into core/ — the verifier
never imports this module. Long jobs (seal) report per-stage progress over SSE.

Run: `evseal serve` (or `uvicorn evseal.api.app:app`). Workspace = $EVSEAL_HOME or ~/.evseal.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import random
import re
import shutil
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from evseal import access
from evseal.api import auth
from evseal.core import crypto
from evseal.core import profile as prof
from evseal.core.clip import make_clip
from evseal.core.manifest import Bundle
from evseal.core.open import NotVerified, open_bundle
from evseal.core.seal import CONTAINER_MAP, seal_path
from evseal.core.verify import compare_copy, verify
from evseal.resilience import repair as rep_mod
from evseal.workspace import Workspace

app = FastAPI(title="EviSeal")
WS = Workspace()
COOKIE = "evseal_session"


def _auth_off() -> bool:
    return os.environ.get("EVSEAL_AUTH") == "off"  # dev/test only: no login, no per-user signing


def _session(request: Request):
    return getattr(request.state, "session", None)


def _actor(request: Request):
    """The signing key for custody records written on this request: the logged-in user's own key.
    With authentication off (dev) fall back to the first workspace root key."""
    s = _session(request)
    if s is not None:
        return s.kp
    keys = [k for k in WS.list_keys() if k["has_private"]]
    return WS.root(keys[0]["name"]) if keys else None


@app.middleware("http")
async def access_guard(request: Request, call_next):
    path = request.url.path
    request.state.session = None
    if not path.startswith("/api/") or path.startswith("/api/auth/") or _auth_off():
        return await call_next(request)
    try:
        d = auth.SESSIONS.directory(WS)
    except access.AccessError as exc:
        return JSONResponse({"detail": f"access log invalid: {exc}"}, status_code=503)
    if d is None:
        return JSONResponse({"detail": "no users yet: run `evseal user-init ADMIN` (or set EVSEAL_AUTH=off for dev)"}, status_code=503)
    sess = auth.SESSIONS.get(request.cookies.get(COOKIE))
    if sess is None:
        return JSONResponse({"detail": "authentication required"}, status_code=401)
    perm = auth.perm_for(request.method, path)
    try:
        user = access.authorize(d, sess.user.id, perm)  # live directory: a revocation or role change bites immediately
    except access.Denied as exc:
        access.record(WS.home, sess.user, sess.kp, "denied", {"perm": perm, "method": request.method, "path": path})
        auth.SESSIONS.own_append(WS)
        return JSONResponse({"detail": str(exc)}, status_code=403)
    if perm in access.LOGGED:  # signed intent is on record before the action runs
        access.record(WS.home, user, sess.kp, "act", {"perm": perm, "method": request.method, "path": path})
        auth.SESSIONS.own_append(WS)
    request.state.session = sess
    return await call_next(request)


@app.post("/api/auth/login")
def login(body: dict, request: Request):
    try:
        tok = auth.SESSIONS.login(WS, str(body.get("user", "")), body.get("passphrase") or None)
    except auth.Throttled as exc:
        raise HTTPException(429, str(exc))
    except (access.Denied, access.AccessError):
        raise HTTPException(401, "login failed")
    except FileNotFoundError:
        raise HTTPException(401, "login failed")
    r = JSONResponse({"ok": True})
    r.set_cookie(COOKIE, tok, httponly=True, samesite="strict", max_age=auth.TTL_S)
    return r


@app.post("/api/auth/logout")
def logout(request: Request):
    auth.SESSIONS.logout(WS, request.cookies.get(COOKIE))
    r = JSONResponse({"ok": True})
    r.delete_cookie(COOKIE)
    return r


@app.get("/api/auth/session")
def session(request: Request):
    if _auth_off():
        return {"auth": "off", "user": None}
    s = auth.SESSIONS.get(request.cookies.get(COOKIE))
    try:
        d = auth.SESSIONS.directory(WS)
    except access.AccessError:
        d = None
    if s is None:
        return {"auth": "on", "user": None, "setup_needed": d is None}
    perms = sorted(p for p, roles in access.PERMS.items() if s.user.role in roles)
    return {"auth": "on", "user": s.user.id, "role": s.user.role, "permissions": perms}


@app.get("/api/audit/users")
def audit_users():
    d = auth.SESSIONS.directory(WS)
    return {"users": [u.public() for u in d.users.values()] if d else []}


@app.get("/api/audit/log")
def audit_log(limit: int = 100):
    from evseal.dr import custody

    d = auth.SESSIONS.directory(WS)  # replays the whole log: raises if it was tampered with
    recs = custody.entries(WS.home, access.LOG)
    return {"intact": d is not None, "entries": len(recs), "tail": recs[-max(1, min(limit, 1000)):]}


@app.get("/api/bundles/{name}/court-report")
def court_report(name: str, custodian: str = "", designation: str = "", organisation: str = "", device: str = "", place: str = ""):
    from evseal.report import build_report, render_markdown

    r = build_report(_bundle(name), WS.trust(), custodian=custodian, designation=designation,
                     organisation=organisation, device=device, place=place)
    return Response(render_markdown(r), media_type="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="{name}-report.md"'})


_NAME = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_jobs: dict[str, dict] = {}
_cache: dict[str, tuple[float, dict, dict]] = {}  # bundle -> (mtime, report, image plaintexts)


def _safe(name: str) -> str:
    if not _NAME.match(name) or name in (".", ".."):
        raise HTTPException(400, f"bad name {name!r}")
    return name


def _bundle(name: str) -> Path:
    p = WS.home / "bundles" / _safe(name)
    if not p.is_dir():
        raise HTTPException(404, f"no bundle {name}")
    return p


def _mtime(p: Path) -> float:
    return max((f.stat().st_mtime for f in p.rglob("*") if f.is_file()), default=0.0)


def _verify(name: str, force: bool = False) -> tuple[dict, dict]:
    p = _bundle(name)
    mt = _mtime(p)
    hit = _cache.get(name)
    if hit and hit[0] == mt and not force:
        return hit[1], hit[2]
    images: dict[int, bytes] = {}
    m, _ = Bundle(p).load_manifest()
    is_img = (m or {}).get("media", {}).get("kind") == "image"
    r = verify(p, WS.trust(), sink=(lambda i, pt, res: images.__setitem__(i, pt)) if is_img else None)
    d = r.to_dict()
    d["bundle"] = name
    d["verified_at"] = time.time()
    _cache[name] = (mt, d, images)
    return d, images


# ---- environment / profiles / keys ----


@app.get("/api/doctor")
def doctor():
    from evseal.cli import run_doctor

    return run_doctor()


@app.get("/api/schema")
def schema():
    fields = []
    for (g, k), rule in prof.SCHEMA.items():
        f = {"group": g, "key": k, "kind": rule[0], "default": prof.DEFAULTS[g][k]}
        if rule[0] in ("num", "int"):
            f["min"], f["max"] = rule[1], rule[2]
        if rule[0] in ("enum", "list", "map"):
            f["options"] = rule[1]
        fields.append(f)
    sig = {a: {"class": crypto.security_class(a), "backend": crypto.get_signature_backend(a)[1]} for a in crypto.SIG_ALGS}
    kem = {a: {"class": "pq", "backend": crypto.get_kem_backend(a)[1]} for a in crypto.KEM_ALGS}
    return {"fields": fields, "algorithms": {**sig, **kem}, "presets": list(prof.PRESETS), "container_map": CONTAINER_MAP}


@app.get("/api/profiles")
def list_profiles():
    saved = sorted(p.stem for p in (WS.home / "profiles").glob("*.toml"))
    return {"presets": list(prof.PRESETS), "saved": saved}


@app.get("/api/profiles/{name}")
def get_profile(name: str):
    try:
        return WS.profile(_safe(name))
    except (FileNotFoundError, OSError):
        raise HTTPException(404, "no such profile")


class ProfileBody(BaseModel):
    profile: dict
    bitrate_mbps: float = 2.0
    hours: float = 12.0
    cores: int = 8


@app.post("/api/profiles/validate")
def validate_profile(body: ProfileBody):
    p = prof.resolve(body.profile)
    errors, warnings = prof.validate(p)
    est = prof.estimates(p, body.bitrate_mbps, body.hours, body.cores) if not errors else None
    return {"errors": errors, "warnings": warnings, "estimates": est, "profile": p}


@app.put("/api/profiles/{name}")
def save_profile(name: str, body: ProfileBody):
    if name in prof.PRESETS:
        raise HTTPException(400, "presets are read-only; save under a new name")
    p = prof.resolve(body.profile)
    errors, _ = prof.validate(p)
    if errors:
        raise HTTPException(422, {"errors": errors})
    (WS.home / "profiles" / f"{_safe(name)}.toml").write_text(prof.dumps(p))
    return {"saved": name}


@app.delete("/api/profiles/{name}")
def delete_profile(name: str):
    (WS.home / "profiles" / f"{_safe(name)}.toml").unlink(missing_ok=True)
    return {"deleted": name}


class DiffBody(BaseModel):
    a: str
    b: str


@app.post("/api/profiles/diff")
def diff_profiles(body: DiffBody):
    return {"diff": prof.diff(WS.profile(body.a), WS.profile(body.b))}


@app.get("/api/keys")
def list_keys():
    return {"keys": WS.list_keys(), "tsa": WS.tsa().kp.public(), "dev_only_warning":
            "Private keys are stored as plain files in the workspace (DEV-ONLY). HSM/TPM support comes later."}


class KeyBody(BaseModel):
    name: str
    alg: str = prof.DEFAULTS["keys"]["root_alg"]


@app.post("/api/keys")
def make_key(body: KeyBody):
    if body.alg not in crypto.SIG_ALGS:
        raise HTTPException(400, "unknown algorithm")
    try:
        return WS.keygen(_safe(body.name), body.alg)
    except FileExistsError as e:
        raise HTTPException(409, str(e))


@app.get("/api/keys/rotation")
def rotation_log():
    """Certificates issued across all bundles (ephemeral rotation + checkpoint keys)."""
    out = []
    for b in sorted((WS.home / "bundles").iterdir()):
        m, _ = Bundle(b).load_manifest()
        for r in (m or {}).get("records", []):
            if r.get("type") == "cert":
                out.append({"bundle": b.name, "id": r["id"], "role": r["role"], "alg": r["alg"], "period": r["period"],
                            "not_before": r["not_before"], "not_after": r["not_after"], "root_fp": r["root_fp"],
                            "fp": crypto.fingerprint(bytes.fromhex(r["pk"]))})
    return {"certs": out}


# ---- uploads / seal jobs ----


@app.post("/api/uploads")
async def upload(files: list[UploadFile] = File(...)):
    uid = uuid.uuid4().hex[:12]
    d = WS.home / "uploads" / uid
    d.mkdir(parents=True)
    names = []
    for f in files:
        fname = Path(f.filename or "file").name
        _safe(fname)
        with open(d / fname, "wb") as out:
            shutil.copyfileobj(f.file, out)
        names.append(fname)
    return {"upload_id": uid, "files": names}


class SealBody(BaseModel):
    upload_id: str
    profile: str | dict = "court-grade"
    key: str
    name: str | None = None


def _run_seal(job: dict, src: Path, p: dict, key: str, out: Path, sess=None):
    def progress(stage, done, total):
        job["events"].put({"stage": stage, "done": done, "total": total, "t": time.time()})

    try:
        seal_path(src, p, WS.root(key), out, tsa=WS.tsa(), anchor_log=WS.anchor_log(), progress=progress)
        if sess is not None:
            access.attest_seal(out, sess.user, sess.kp)  # the operator signs what was sealed (non-repudiation)
        job["status"] = "done"
    except Exception as exc:
        job["status"] = "error"
        job["error"] = f"{type(exc).__name__}: {exc}"
        shutil.rmtree(out, ignore_errors=True)
    job["events"].put(None)


@app.post("/api/seal")
def seal(body: SealBody, request: Request):
    up = WS.home / "uploads" / _safe(body.upload_id)
    files = sorted(up.iterdir()) if up.is_dir() else []
    if not files:
        raise HTTPException(404, "upload not found")
    images = [f for f in files if CONTAINER_MAP.get(f.suffix.lower()) == "image"]
    src = up if len(files) > 1 or images else files[0]
    if len(files) > 1 and len(images) != len(files):
        raise HTTPException(400, "multiple files must all be images (one image set); seal videos one at a time")
    p = WS.profile(body.profile) if isinstance(body.profile, str) else prof.resolve(body.profile)
    errors, _ = prof.validate(p)
    if errors:
        raise HTTPException(422, {"errors": errors})
    if not (WS.keys_dir / f"{_safe(body.key)}.key.json").exists():
        raise HTTPException(404, "no such key")
    name = _safe(body.name or f"{Path(files[0]).stem if src.is_file() else 'imageset'}-{time.strftime('%Y%m%d-%H%M%S')}")
    out = WS.home / "bundles" / name
    if out.exists():
        raise HTTPException(409, "bundle name exists")
    jid = uuid.uuid4().hex[:12]
    job = {"id": jid, "bundle": name, "status": "running", "events": queue.Queue(), "error": None}
    _jobs[jid] = job
    threading.Thread(target=_run_seal, args=(job, src, p, body.key, out, _session(request)), daemon=True).start()
    return {"job": jid, "bundle": name}


@app.get("/api/jobs/{jid}/events")
def job_events(jid: str):
    job = _jobs.get(jid)
    if job is None:
        raise HTTPException(404, "no such job")

    def gen():
        while True:
            ev = job["events"].get()
            if ev is None:
                yield f"data: {json.dumps({'stage': 'end', 'status': job['status'], 'error': job['error'], 'bundle': job['bundle']})}\n\n"
                return
            yield f"data: {json.dumps(ev)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


# ---- bundles ----


@app.get("/api/bundles")
def bundles():
    out = []
    for b in sorted((WS.home / "bundles").iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        m, src = Bundle(b).load_manifest()
        if m is None:
            out.append({"name": b.name, "kind": "?", "manifest": src})
            continue
        cached = _cache.get(b.name)
        out.append({"name": b.name, "kind": m["media"]["kind"], "source": m["media"].get("source_name"),
                    "units": len(m["units"]), "created": m.get("created"), "clip": m.get("clip"), "manifest": src,
                    "sign_alg": m["profile"]["sign"]["alg"],
                    "overall": cached[1]["overall"] if cached and cached[0] == _mtime(b) else None})
    return {"bundles": out}


@app.post("/api/bundles/{name}/verify")
def verify_bundle(name: str):
    return _verify(name, force=True)[0]


@app.get("/api/bundles/{name}/report")
def report(name: str):
    return _verify(name)[0]


@app.get("/api/bundles/{name}/manifest")
def manifest(name: str):
    m, src = Bundle(_bundle(name)).load_manifest()
    return {"source": src, "manifest": m}


@app.get("/api/bundles/{name}/image/{i}")
def image(name: str, i: int, heat: bool = False):
    """Verify-to-open for one photo: served only if it verified; tampered photos are shown
    only as their heatmap overlay over the (decrypted) candidate bytes."""
    rep, imgs = _verify(name)
    u = next((x for x in rep["units"] if x["i"] == i), None)
    if u is None:
        raise HTTPException(404, "no such unit")
    data = imgs.get(i)
    if data is None and u["status"] == "TAMPERED" and heat:  # never served as evidence, only as an overlay
        data = _tampered_bytes(name, i)
    if data is None:
        raise HTTPException(403, f"unit {i} is {u['status']}: not opened")
    if heat:
        from evseal.media.image import heatmap

        m, _ = Bundle(_bundle(name)).load_manifest()
        meta = next(x for x in m["units"] if x["i"] == i)
        tmap = u.get("tiles") or {"tile": meta["tiles"]["tile"], "tiles": [
            {"x": int(k[2:].split(",")[0]), "y": int(k[2:].split(",")[1]), "status": "VERIFIED"}
            for k in (lf["k"] for lf in meta["tiles"]["leaves"]) if k.startswith("t:")]}
        return Response(heatmap(data, tmap), media_type="image/png")
    return Response(data, media_type="application/octet-stream")


def _tampered_bytes(name: str, i: int) -> bytes | None:
    from evseal.stresslab.attacks import decrypt_unit

    try:
        b = _bundle(name)
        m, _ = Bundle(b).load_manifest()
        return decrypt_unit(b, m, i)
    except Exception:
        return None


@app.get("/api/bundles/{name}/tiles/{i}")
def tiles(name: str, i: int):
    rep, _ = _verify(name)
    m, _ = Bundle(_bundle(name)).load_manifest()
    meta = next((x for x in m["units"] if x["i"] == i), None)
    if meta is None or "tiles" not in meta:
        raise HTTPException(404, "not a tiled unit")
    u = next(x for x in rep["units"] if x["i"] == i)
    status = {(t["x"], t["y"]): t for t in (u.get("tiles") or {}).get("tiles", [])}
    leaves = {lf["k"]: lf for lf in meta["tiles"]["leaves"]}
    out = []
    for k, lf in leaves.items():
        if not k.startswith("t:"):
            continue
        x, y = (int(v) for v in k[2:].split(","))
        st = status.get((x, y), {"status": "VERIFIED" if u["status"] in ("VERIFIED", "REPAIRED") else u["status"]})
        out.append({"x": x, "y": y, "leaf": lf["h"], "perceptual": leaves.get(f"p:{x},{y}", {}).get("v"), **st})
    return {"w": meta["tiles"]["w"], "h": meta["tiles"]["h"], "tile": meta["tiles"]["tile"], "basis": meta["tiles"]["basis"],
            "unit_status": u["status"], "metadata": [{"k": k, "h": lf.get("h")} for k, lf in leaves.items() if k[:2] in ("m:", "g:")],
            "tiles": out, "metadata_changed": (u.get("tiles") or {}).get("metadata_changed", [])}


@app.post("/api/bundles/{name}/compare")
async def compare(name: str, unit: int = Form(...), file: UploadFile = File(...)):
    data = await file.read()
    out = compare_copy(_bundle(name), WS.trust(), unit, data)
    if out.get("tiles"):
        from evseal.media.image import heatmap

        try:
            out["heatmap_png"] = base64.b64encode(heatmap(data, out)).decode()
        except Exception:
            pass
    return out


class ClipBody(BaseModel):
    i: int
    j: int
    name: str | None = None


@app.post("/api/bundles/{name}/clip")
def clip(name: str, body: ClipBody):
    cname = _safe(body.name or f"{name}.clip{body.i}-{body.j}")
    out = WS.home / "bundles" / cname
    if out.exists():
        shutil.rmtree(out)
    try:
        make_clip(_bundle(name), body.i, body.j, out)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"bundle": cname}


class OpenBody(BaseModel):
    partial: bool = False


@app.post("/api/bundles/{name}/open")
def open_(name: str, body: OpenBody):
    out = WS.home / "opened" / _safe(name)
    shutil.rmtree(out, ignore_errors=True)
    try:
        rep, outputs = open_bundle(_bundle(name), WS.trust(), out, partial=body.partial)
    except NotVerified as e:
        return JSONResponse({"refused": True, "overall": e.report.overall, "reasons": e.report.reasons}, status_code=409)
    rel = {}
    for k, v in outputs.items():
        if isinstance(v, str) and Path(v).exists():
            rel[k] = f"/api/opened/{name}/{Path(v).name}"
        elif isinstance(v, list):
            rel[k] = [f"/api/opened/{name}/{Path(x).name}" for x in v]
        else:
            rel[k] = v
    return {"overall": rep.overall, "outputs": rel}


@app.get("/api/opened/{name}/{fname}")
def opened_file(name: str, fname: str):
    p = WS.home / "opened" / _safe(name) / _safe(fname)
    if not p.is_file():
        raise HTTPException(404, "not found")
    return FileResponse(p, filename=fname)


@app.get("/api/bundles/{name}/repair/plan")
def repair_plan(name: str):
    return rep_mod.plan(_bundle(name), WS.trust())


@app.post("/api/bundles/{name}/repair/run")
def repair_run(name: str, request: Request):
    actor = _actor(request)
    before, after, units = rep_mod.run(_bundle(name), WS.trust(), actor=actor)
    _cache.pop(name, None)
    return {"before": before.overall, "after": after.overall, "repaired": units, "report": _verify(name, force=True)[0]}


@app.delete("/api/bundles/{name}")
def delete_bundle(name: str):
    shutil.rmtree(_bundle(name))
    _cache.pop(name, None)
    return {"deleted": name}


class TamperBody(BaseModel):
    attack: str
    params: dict = {}
    seed: int = 1


@app.post("/api/bundles/{name}/tamper")
def tamper(name: str, body: TamperBody):
    """Demo/Stress-Lab helper: apply one attack or fault to a COPY of the bundle (seeded)."""
    from evseal.stresslab.attacks import ATTACKS

    if body.attack not in ATTACKS or body.attack in ("attacker_reseal", "forge_with_leaked_key", "swap_foreign"):
        raise HTTPException(400, "attack not available from the UI")
    src = _bundle(name)
    dst = WS.home / "bundles" / _safe(f"{name}.{body.attack}.s{body.seed}")
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    try:
        info = ATTACKS[body.attack](dst, random.Random(f"{body.seed}:{body.attack}"), {"ws": WS}, **body.params)
    except Exception as e:
        shutil.rmtree(dst, ignore_errors=True)
        raise HTTPException(400, f"{type(e).__name__}: {e}")
    return {"bundle": dst.name, "seed": body.seed, "info": info}


@app.get("/api/attacks")
def attacks():
    from evseal.stresslab.attacks import describe

    return {"attacks": [a for a in describe() if a["name"] not in ("attacker_reseal", "forge_with_leaked_key", "swap_foreign")]}


# ---- Stress Lab, Benchmarks & DR ----


@app.get("/api/stress/scenarios")
def stress_scenarios():
    from evseal.stresslab.runner import load_expected

    scs = load_expected()
    return {"scenarios": [
        {
            "id": s["id"],
            "title": s.get("title", ""),
            "kind": s.get("kind", "bundle"),
            "slow": bool(s.get("slow", False)),
            "media": s.get("media", ""),
            "attack": s.get("attack", ""),
            "expected": {k: s[k] for k in ("overall", "affected", "others", "verdict", "tail", "head") if k in s},
        }
        for s in scs
    ]}


class StressRunBody(BaseModel):
    ids: list[str] | None = None
    seed: int = 1
    full: bool = False


@app.post("/api/stress/run")
def stress_run(body: StressRunBody):
    import tempfile
    from evseal.stresslab.runner import run_matrix

    with tempfile.TemporaryDirectory() as td:
        results = run_matrix(Path(td), ids=body.ids, seed=body.seed, full=body.full)
    passed = sum(1 for r in results if r["pass"])
    return {
        "results": results,
        "seed": body.seed,
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
    }


class BenchRunBody(BaseModel):
    quick: bool = True
    workers: int | None = None


_latest_bench: list[dict] = []


@app.post("/api/bench/run")
def bench_run(body: BenchRunBody):
    global _latest_bench
    from evseal.bench.sweep import run_sweep

    _latest_bench = run_sweep(quick=body.quick, workers=body.workers)
    return {"results": _latest_bench}


@app.get("/api/bench/results")
def bench_results():
    return {"results": _latest_bench}


class DrSplitBody(BaseModel):
    k: int = 2
    n: int = 3


@app.post("/api/bundles/{name}/dr/split")
def bundle_dr_split(name: str, body: DrSplitBody, request: Request):
    from evseal.dr.split import split_bundle

    b = _bundle(name)
    actor = _actor(request)
    out_dir = WS.home / "dr_shards" / _safe(name)
    shards = split_bundle(b, k=body.k, n=body.n, out_dir=out_dir, actor=actor)
    return {"bundle": name, "k": body.k, "n": body.n, "shards": [s.name for s in shards]}


class DrRecoverBody(BaseModel):
    shards_bundle: str
    out_name: str


@app.post("/api/dr/recover")
def bundle_dr_recover(body: DrRecoverBody, request: Request):
    from evseal.dr.split import recover_bundle

    shards_dir = WS.home / "dr_shards" / _safe(body.shards_bundle)
    if not shards_dir.is_dir():
        raise HTTPException(404, "no shards found for bundle")
    actor = _actor(request)
    out_bundle = WS.home / "bundles" / _safe(body.out_name)
    recover_bundle(shards_dir, out_bundle, actor=actor)
    _cache.pop(body.out_name, None)
    return {"bundle": body.out_name, "report": _verify(body.out_name, force=True)[0]}


_UI = Path(__file__).resolve().parent.parent / "ui" / "dist"
if _UI.is_dir():
    app.mount("/", StaticFiles(directory=_UI, html=True), name="ui")
