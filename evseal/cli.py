"""EviSeal CLI entry point."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys

from pathlib import Path

import typer

from evseal.core import crypto

app = typer.Typer(help="EviSeal — post-quantum sealed video evidence tool")


def _check_ffmpeg_tool(tool: str) -> tuple[bool, str]:
    path = shutil.which(tool)
    if path is None:
        return False, "not found on PATH"
    try:
        result = subprocess.run(
            [tool, "-version"], capture_output=True, text=True, timeout=10, check=False
        )
        first_line = result.stdout.splitlines()[0] if result.stdout else "(no version output)"
        return True, first_line
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"found at {path} but failed to run: {exc}"


def _check_zfec() -> tuple[bool, str]:
    try:
        import zfec  # noqa: F401

        return True, "importable"
    except ImportError as exc:
        return False, f"import failed: {exc}"


def run_doctor() -> dict:
    """Build the doctor report as plain data, so it's unit-testable without CLI parsing."""
    report: dict = {
        "python_version": sys.version.split()[0],
        "os": f"{platform.system()} {platform.release()}",
        "algorithms": [],
        "ffmpeg": {},
        "ffprobe": {},
        "zfec": {},
        "ok": True,
    }

    for status in crypto.available():
        entry = {
            "name": status.name,
            "family": status.family,
            "backend": status.backend,
            "note": status.note,
        }
        report["algorithms"].append(entry)

    ffmpeg_ok, ffmpeg_msg = _check_ffmpeg_tool("ffmpeg")
    ffprobe_ok, ffprobe_msg = _check_ffmpeg_tool("ffprobe")
    zfec_ok, zfec_msg = _check_zfec()

    report["ffmpeg"] = {"ok": ffmpeg_ok, "detail": ffmpeg_msg}
    report["ffprobe"] = {"ok": ffprobe_ok, "detail": ffprobe_msg}
    report["zfec"] = {"ok": zfec_ok, "detail": zfec_msg}

    # P0's done-when bar (SPEC §8): ML-DSA, SLH-DSA, ML-KEM must each be
    # LISTED (available() always lists them) and at least one ML-DSA
    # variant and one ML-KEM variant must have a working backend. SLH-DSA
    # is allowed to be unavailable pending P3 (no Windows/cp312 wheel
    # today) but doctor still reports it, never hides it.
    has_working_ml_dsa = any(
        a["family"] == "signature" and a["name"].startswith("ML-DSA") and a["backend"]
        for a in report["algorithms"]
    )
    has_working_ml_kem = any(
        a["family"] == "kem" and a["backend"] for a in report["algorithms"]
    )
    report["ok"] = bool(
        has_working_ml_dsa and has_working_ml_kem and ffmpeg_ok and ffprobe_ok and zfec_ok
    )
    return report


@app.command()
def doctor() -> None:
    """Check the environment: PQC algorithm availability, ffmpeg/ffprobe, zfec."""
    report = run_doctor()

    typer.echo(f"Python: {report['python_version']}  OS: {report['os']}")
    typer.echo("")
    typer.echo("Algorithms:")
    for a in report["algorithms"]:
        if a["backend"]:
            typer.echo(f"  [ok]      {a['name']:<20} ({a['family']}, backend={a['backend']})")
        else:
            typer.echo(f"  [missing] {a['name']:<20} ({a['family']}) — {a['note']}")

    typer.echo("")
    for label, key in [("ffmpeg", "ffmpeg"), ("ffprobe", "ffprobe"), ("zfec", "zfec")]:
        entry = report[key]
        mark = "ok" if entry["ok"] else "missing"
        typer.echo(f"{label}: [{mark}] {entry['detail']}")

    typer.echo("")
    if report["ok"]:
        typer.echo("Overall: READY for P1 (core ML-DSA + ML-KEM backends available).")
    else:
        typer.echo("Overall: NOT READY — see missing items above.", err=True)
        raise typer.Exit(code=1)


HomeOpt = typer.Option(None, "--home", help="workspace (default $EVSEAL_HOME or ~/.evseal)")


def _ws(home):
    from evseal.workspace import Workspace

    return Workspace(home)


AsOpt = typer.Option(None, "--as", envvar="EVSEAL_USER", help="acting user id (required once the workspace has an access log)")


def _actor(ws, user: str | None, perm: str):
    """Authorize `user` for `perm` and return (User, KeyPair) so the action is signed by that person.
    An unmanaged workspace (no access log yet) returns (None, None) with a warning."""
    from evseal import access

    try:
        d = ws.directory()
    except access.AccessError as exc:
        typer.echo(f"access log invalid: {exc}", err=True)
        raise typer.Exit(3)
    if d is None:
        typer.echo("warning: unmanaged workspace (no access log): this action is not attributable to a person", err=True)
        return None, None
    if not user:
        typer.echo("--as USER is required: this workspace has an access log", err=True)
        raise typer.Exit(3)
    try:
        u = access.authorize(d, user, perm)
        kp = ws.user_key(user)
        if kp.fp != u.fp:
            raise access.Denied("the key file does not match the registered key for this user")
    except (access.Denied, ValueError, FileNotFoundError) as exc:
        typer.echo(f"denied: {exc}", err=True)
        raise typer.Exit(3)
    if perm in access.LOGGED:
        access.record(ws.home, u, kp, "act", {"perm": perm, "via": "cli"})
    return u, kp


def _trust(ws, extra_roots: list[str] | None, allow_classical: bool):
    from evseal.longterm.keys import Trust

    t = ws.trust(allow_classical)
    if extra_roots:
        t.roots.update(Trust.from_paths(roots=extra_roots).roots)
    return t


def _pass_key(ws, user_id: str, alg: str):
    """Create a user's signing key under the workspace (encrypted when EVSEAL_KEY_PASSPHRASE is set)."""
    import os

    from evseal.longterm import keys

    kp = keys.generate(alg, user_id)
    keys.save(kp, ws.user_keys_dir, os.environ.get("EVSEAL_KEY_PASSPHRASE") or None)
    return kp


@app.command("user-init")
def user_init(user_id: str, alg: str = typer.Option("ML-DSA-65", help="user signing algorithm"), home: str = HomeOpt):
    """Create the access log with a self-signed first admin (generates that admin's key)."""
    from evseal import access

    ws = _ws(home)
    kp = _pass_key(ws, user_id, alg)
    access.init_admin(ws.home, user_id, kp)
    typer.echo(f"admin {user_id}: {kp.alg} fp={kp.fp}")


@app.command("user-add")
def user_add(user_id: str, role: str = typer.Option(..., help="admin | collector | examiner | custodian | auditor"),
             alg: str = typer.Option("ML-DSA-65"), pub: str = typer.Option(None, help="register this existing .pub.json instead of generating a key"),
             home: str = HomeOpt, user: str = AsOpt):
    """Add a user (admin only). The new user's key is generated here unless --pub is given."""
    from evseal import access
    from evseal.longterm import keys

    ws = _ws(home)
    who, kp = _actor(ws, user, "users")
    if who is None:
        typer.echo("run user-init first", err=True)
        raise typer.Exit(2)
    if pub:
        rec = keys.load_public(Path(pub))
    else:
        rec = _pass_key(ws, user_id, alg).public()
    access.add_user(ws.home, who.id, kp, user_id, role, rec)
    typer.echo(f"added {user_id} as {role} (fp {rec['fp'][:16]}…)")


@app.command("user-role")
def user_role(user_id: str, role: str, home: str = HomeOpt, user: str = AsOpt):
    """Change a user's role (admin only)."""
    from evseal import access

    ws = _ws(home)
    who, kp = _actor(ws, user, "users")
    access.set_role(ws.home, who.id, kp, user_id, role)
    typer.echo(f"{user_id} is now {role}")


@app.command("user-revoke")
def user_revoke(user_id: str, home: str = HomeOpt, user: str = AsOpt):
    """Revoke a user (admin only). Their past signatures stay verifiable."""
    from evseal import access

    ws = _ws(home)
    who, kp = _actor(ws, user, "users")
    access.revoke_user(ws.home, who.id, kp, user_id)
    typer.echo(f"revoked {user_id}")


@app.command("users")
def users_cmd(home: str = HomeOpt):
    """List users and roles from the verified access log."""
    d = _ws(home).directory()
    for u in (d.users.values() if d else []):
        typer.echo(f"{u.id:<20} {u.role:<10} {'active' if u.active else 'REVOKED':<8} {u.alg} {u.fp[:16]}…")


@app.command("access-log")
def access_log(tail: int = 20, home: str = HomeOpt, user: str = AsOpt):
    """Verify the access log end to end and print its last entries (admin or auditor)."""
    from evseal import access
    from evseal.dr import custody

    ws = _ws(home)
    _actor(ws, user, "audit")
    access.replay(ws.home)
    recs = custody.entries(ws.home, access.LOG)
    typer.echo(f"access log intact: {len(recs)} signed, chained entries")
    for r in recs[-tail:]:
        typer.echo(f"{r['seq']:>5} {r.get('actor_id', '?'):<14} {r['action']:<12} {json.dumps(r['detail'])[:80]}")


@app.command()
def keygen(name: str, alg: str = typer.Option("ML-DSA-87", help="root/collector key algorithm"), home: str = HomeOpt):
    """Generate a root (collector) key in the workspace. DEV-ONLY file-based private key."""
    pub = _ws(home).keygen(name, alg)
    typer.echo(f"{name}: {pub['alg']} fp={pub['fp']}")


@app.command()
def seal(src: str, out: str, key: str = typer.Option(..., help="root key name"), profile: str = typer.Option(None, help="preset or TOML"),
         acq_md5: str = typer.Option(None, help="legacy MD5 acquisition hash to record/check"),
         acq_sha1: str = typer.Option(None, help="legacy SHA-1 acquisition hash to record/check"), home: str = HomeOpt,
         user: str = AsOpt):
    """Seal a video/audio file or an image folder into a bundle directory."""
    from evseal import access
    from evseal.core.seal import seal_path

    ws = _ws(home)
    who, kp = _actor(ws, user, "seal")
    claims = {k: v for k, v in (("md5", acq_md5), ("sha1", acq_sha1)) if v}

    def progress(stage, done, total):
        typer.echo(f"\r{stage:<9} {done}/{total}", nl=stage == "done")

    seal_path(Path(src), ws.profile(profile), ws.root(key), Path(out), tsa=ws.tsa(), anchor_log=ws.anchor_log(),
              legacy_claims=claims, progress=progress)
    if who is not None:
        access.attest_seal(Path(out), who, kp)  # the operator signs what was sealed (non-repudiation)
    typer.echo(f"sealed -> {out}" + (f" (attested by {who.id}, {who.role})" if who else ""))


@app.command()
def verify(bundle: str, trust_root: list[str] = typer.Option(None, help="extra trusted root .pub.json"),
           allow_classical: bool = False, json_out: str = typer.Option(None, "--json", help="write report JSON"),
           require_operator: bool = typer.Option(False, help="policy: require a valid operator seal attestation"),
           home: str = HomeOpt):
    """Verify a bundle or clip (reference verifier). Exit 0 only when VERIFIED."""
    import json

    from evseal.core.verify import verify as _verify

    trust = _trust(_ws(home), trust_root, allow_classical)
    trust.require_operator = require_operator
    r = _verify(Path(bundle), trust)
    typer.echo(f"overall: {r.overall}   {r.counts()}")
    for reason in r.reasons:
        typer.echo(f"  ! {reason}")
    for u in r.units:
        if u.status != "VERIFIED":
            typer.echo(f"  unit {u.i:>6} {u.status:<15} {u.detail}")
    if json_out:
        Path(json_out).write_text(json.dumps(r.to_dict(), indent=1))
    raise typer.Exit(0 if r.overall == "VERIFIED" else 1)


@app.command()
def clip(bundle: str, out: str, start: int = typer.Option(None, help="first unit"), end: int = typer.Option(None, help="last unit"),
         t0: float = typer.Option(None, help="start time s"), t1: float = typer.Option(None, help="end time s"),
         home: str = HomeOpt, user: str = AsOpt):
    """Export a standalone clip (units start..end or a time range)."""
    from evseal.core.clip import make_clip, range_for_time
    from evseal.core.manifest import Bundle

    _actor(_ws(home), user, "clip")
    if start is None:
        start, end = range_for_time(Bundle(Path(bundle)).load_manifest()[0], t0, t1)
    make_clip(Path(bundle), start, end, Path(out))
    typer.echo(f"clip {start}..{end} -> {out}")


@app.command("open")
def open_cmd(bundle: str, out: str, partial: bool = typer.Option(False, help="write only VERIFIED/REPAIRED units"), home: str = HomeOpt,
             user: str = AsOpt):
    """Verify-to-open: restore the original (or clip) only if it verifies."""
    from evseal.core.open import NotVerified, open_bundle

    _actor(_ws(home), user, "open")
    try:
        rep, outputs = open_bundle(Path(bundle), _ws(home).trust(), Path(out), partial=partial)
    except NotVerified as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    typer.echo(f"{rep.overall}: {outputs}")


@app.command()
def repair(bundle: str, replica: list[str] = typer.Option(None), dry_run: bool = False, key: str = typer.Option(None), home: str = HomeOpt,
           user: str = AsOpt):
    """Rebuild damaged units from parity/replicas, write back, re-verify."""
    from evseal.resilience import repair as r

    ws = _ws(home)
    if dry_run:
        typer.echo(r.plan(Path(bundle), ws.trust(), tuple(replica or ())))
        return
    who, ukp = _actor(ws, user, "repair")
    before, after, units = r.run(Path(bundle), ws.trust(), ukp or (ws.root(key) if key else None), tuple(replica or ()))
    typer.echo(f"{before.overall} -> {after.overall}; repaired units {units}")


@app.command()
def reseal(bundle: str, key: str = typer.Option(...), hash_alg: str = typer.Option(None), home: str = HomeOpt, user: str = AsOpt):
    """Append an evidence-record reseal signed by a (current) trusted root key."""
    from evseal.longterm.reseal import reseal as _reseal

    ws = _ws(home)
    _actor(ws, user, "reseal")
    rec = _reseal(Path(bundle), ws.root(key), ws.tsa(), hash_alg)
    typer.echo(f"resealed: {rec['alg']} over {rec['hash_alg']} {rec['manifest_hash'][:16]}…")


@app.command()
def report(bundle: str, out: str = typer.Option("evseal-report.md", help="markdown output (a .json twin is written too)"),
           custodian: str = "", designation: str = "", organisation: str = "", device: str = "", place: str = "",
           allow_classical: bool = False, home: str = HomeOpt, user: str = AsOpt):
    """Draft a court report / s.63-style certificate from a verification. A human must complete and sign it."""
    from evseal.report import write_report

    _actor(_ws(home), user, "report")
    r = write_report(Path(bundle), _trust(_ws(home), None, allow_classical), Path(out), custodian=custodian,
                     designation=designation, organisation=organisation, device=device, place=place)
    typer.echo(f"{r['facts']['verdict']}: draft written to {out}")


@app.command(name="stamp-queue")
def stamp_queue(bundle: str):
    """Submit timestamp requests that were queued because the TSA was unreachable at seal time."""
    from evseal.longterm.timestamps import flush_queue

    typer.echo(f"stamped {flush_queue(Path(bundle))} queued token(s)")


@app.command()
def compare(bundle: str, unit: int, copy: str, home: str = HomeOpt):
    """Compare an external copy of a sealed photo against the bundle (tile map)."""
    from evseal.core.verify import compare_copy

    out = compare_copy(Path(bundle), _ws(home).trust(), unit, Path(copy).read_bytes())
    counts: dict = {}
    for t in out.get("tiles", []):
        counts[t["status"]] = counts.get(t["status"], 0) + 1
    typer.echo(f"{out['verdict']} {counts} {out.get('detail', '')}")


@app.command()
def pack(bundle: str, out: str):
    """Directory bundle -> single .evseal file (zip, stored)."""
    from evseal.core.manifest import pack as _pack

    typer.echo(_pack(Path(bundle), Path(out)))


@app.command("dr-split")
def dr_split(bundle: str, out_dir: str, k: int = typer.Option(2, help="threshold fragments"), n: int = typer.Option(3, help="total fragments"),
             key: str = typer.Option(None, help="signing key for custody log"), home: str = HomeOpt, user: str = AsOpt):
    """Split a bundle directory or archive into n geo-redundant shards (threshold k)."""
    from evseal.dr.split import split_bundle

    ws = _ws(home)
    who, ukp = _actor(ws, user, "dr")
    actor = ukp or (ws.root(key) if key else None)
    shards = split_bundle(Path(bundle), k=k, n=n, out_dir=Path(out_dir), actor=actor)
    typer.echo(f"split {bundle} into {len(shards)} shards (k={k}, n={n}) -> {out_dir}")


@app.command("dr-recover")
def dr_recover(out: str, shards: list[str] = typer.Argument(..., help="shard files or shard directory"),
               key: str = typer.Option(None, help="signing key for custody log"), home: str = HomeOpt, user: str = AsOpt):
    """Recover bundle from at least k geo-redundant shards."""
    from evseal.dr.split import recover_bundle

    ws = _ws(home)
    who, ukp = _actor(ws, user, "dr")
    actor = ukp or (ws.root(key) if key else None)
    input_shards = Path(shards[0]) if len(shards) == 1 and Path(shards[0]).is_dir() else [Path(s) for s in shards]
    recovered = recover_bundle(input_shards, Path(out), actor=actor)
    typer.echo(f"recovered bundle -> {recovered}")


@app.command("dr-wrap")
def dr_wrap(bundle: str, out: str, custodian_pk: list[str] = typer.Option(..., help="custodian key file or id:hex"),
            kem_alg: str = "ML-KEM-768"):
    """Encrypt bundle with outer ML-KEM layer for custodian confidentiality."""
    import json
    from evseal.dr.outer import encrypt_outer

    custodians = []
    for c in custodian_pk:
        if Path(c).is_file():
            custodians.append(json.loads(Path(c).read_text()))
        elif ":" in c:
            cid, pk_hex = c.split(":", 1)
            custodians.append({"id": cid, "pk": pk_hex, "alg": kem_alg})
        else:
            raise ValueError(f"invalid custodian specification: {c}")
    encrypt_outer(Path(bundle), custodians, Path(out), kem_alg=kem_alg)
    typer.echo(f"outer encrypted -> {out}")


@app.command("dr-unwrap")
def dr_unwrap(outer_file: str, out: str, custodian_id: str = typer.Option(..., "--id"),
              key: str = typer.Option(..., "--key", help="custodian private key JSON file or hex")):
    """Decrypt outer ML-KEM encrypted bundle container."""
    import json
    from evseal.dr.outer import decrypt_outer

    sk = json.loads(Path(key).read_text())["sk"] if Path(key).is_file() else key
    decrypt_outer(Path(outer_file), custodian_id, sk, Path(out))
    typer.echo(f"outer decrypted -> {out}")


@app.command()
def stress(scenario: str = typer.Option(None, help="specific scenario ID to run"),
           full: bool = typer.Option(False, "--full", help="run full matrix including slow"), seed: int = 1):
    """Run Stress Lab scenario matrix against expected results."""
    import tempfile
    from evseal.stresslab.runner import run_matrix

    with tempfile.TemporaryDirectory() as td:
        ids = [scenario] if scenario else None
        results = run_matrix(Path(td), ids=ids, seed=seed, full=full)
        passed = sum(1 for r in results if r["pass"])
        failed = len(results) - passed
        for r in results:
            mark = "PASS" if r["pass"] else "FAIL"
            typer.echo(f"[{mark}] {r['id']:<35} ({r['seconds']}s)")
            for m in r.get("mismatches", []):
                typer.echo(f"       ! {m}")
        typer.echo(f"\nTotal: {passed} passed, {failed} failed out of {len(results)} scenarios (seed={seed})")
        if failed > 0:
            raise typer.Exit(1)


@app.command()
def bench(quick: bool = typer.Option(True, "--quick/--full", help="quick sweep vs full parameter grid"),
          workers: int = typer.Option(None, help="worker processes"),
          json_out: str = typer.Option(None, "--json", help="export JSON metrics")):
    """Run parameter sweep benchmarks measuring throughput, RAM, and overhead."""
    from evseal.bench.sweep import run_sweep

    results = run_sweep(quick=quick, workers=workers, out_file=Path(json_out) if json_out else None)
    header = f"{'Configuration':<44} {'Overhead':<10} {'Throughput':<12} {'RAM':<8} {'Status'}"
    typer.echo(header)
    typer.echo("-" * len(header))
    for r in results:
        status = "OK" if r["verified"] else "FAIL"
        typer.echo(f"{r['label']:<44} {r['overhead_pct']:>6.1f}%    {r['throughput_mb_s']:>6.1f} MB/s   {r['peak_ram_mb']:>5.1f}MB  [{status}]")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    """Run the API + UI (role-based login; refuses a non-loopback address when authentication is off)."""
    import os

    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1") and os.environ.get("EVSEAL_AUTH") == "off":
        typer.echo("refusing to serve an unauthenticated API on a non-loopback address", err=True)
        raise typer.Exit(2)
    uvicorn.run("evseal.api.app:app", host=host, port=port)


if __name__ == "__main__":
    app()
