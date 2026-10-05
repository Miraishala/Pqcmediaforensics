"""EviSeal CLI entry point."""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys

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


if __name__ == "__main__":
    app()
