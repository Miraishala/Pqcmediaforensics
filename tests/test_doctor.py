"""Tests for evseal.cli.run_doctor and the crypto registry it reports on."""

from __future__ import annotations

from evseal.cli import run_doctor
from evseal.core import crypto


def test_doctor_report_shape():
    report = run_doctor()
    assert set(report.keys()) == {
        "python_version",
        "os",
        "algorithms",
        "ffmpeg",
        "ffprobe",
        "zfec",
        "ok",
    }
    assert isinstance(report["algorithms"], list)
    names = {a["name"] for a in report["algorithms"]}
    # SPEC §8 P0 done-when: doctor must at least LIST all three families,
    # even if a given backend turns out unavailable in this environment.
    assert {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} <= names
    assert any(n.startswith("SLH-DSA") for n in names)
    assert {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} <= names


def test_doctor_algorithm_entries_have_required_fields():
    report = run_doctor()
    for entry in report["algorithms"]:
        assert set(entry.keys()) == {"name", "family", "backend", "note"}
        assert entry["family"] in {"signature", "kem"}
        if entry["backend"] is None:
            assert entry["note"], "an unavailable algorithm must explain why"


def test_doctor_handles_missing_ffmpeg(monkeypatch):
    monkeypatch.setattr("evseal.cli.shutil.which", lambda _tool: None)
    report = run_doctor()
    assert report["ffmpeg"]["ok"] is False
    assert report["ffprobe"]["ok"] is False
    assert report["ok"] is False


def test_doctor_handles_missing_zfec(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "zfec":
            raise ImportError("simulated missing zfec")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    report = run_doctor()
    assert report["zfec"]["ok"] is False
    assert report["ok"] is False


def test_doctor_ok_requires_ml_dsa_and_ml_kem_backends(monkeypatch):
    monkeypatch.setattr(
        "evseal.core.crypto.get_signature_backend", lambda _name: (None, None)
    )
    report = run_doctor()
    assert report["ok"] is False
    assert all(a["backend"] is None for a in report["algorithms"] if a["family"] == "signature")


def test_liboqs_buildable_check_does_not_raise():
    # Must never raise, and must be cheap (no subprocess spawn) when
    # no compiler is present — this is the guard that stops liboqs-python's
    # auto-build-on-import from retrying a doomed clone+cmake build on
    # every single call. See crypto._liboqs_buildable's docstring.
    result = crypto._liboqs_buildable()
    assert isinstance(result, bool)
