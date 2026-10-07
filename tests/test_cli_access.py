"""CLI role enforcement and operator attestation, end to end."""
from __future__ import annotations

from typer.testing import CliRunner

from evseal.bench.synth import make_media
from evseal.cli import app

R = CliRunner()


def _run(home, *args, ok=True):
    r = R.invoke(app, [*args, "--home", str(home)])
    assert (r.exit_code == 0) == ok, f"{args}: exit {r.exit_code}\n{r.output}"
    return r


def test_roles_gate_the_cli_and_seal_is_attested(tmp_path):
    home = tmp_path / "ws"
    (home / "profiles").mkdir(parents=True)
    (home / "profiles" / "fast.toml").write_text('[checkpoint]\nalg = "ML-DSA-44"\n[sign]\nalg = "ML-DSA-44"\n[keys]\nroot_alg = "ML-DSA-65"\n')
    _run(home, "keygen", "device", "--alg", "ML-DSA-65")
    _run(home, "user-init", "alice", "--alg", "ML-DSA-44")
    _run(home, "user-add", "bob", "--role", "collector", "--alg", "ML-DSA-44", "--as", "alice")
    _run(home, "user-add", "carol", "--role", "examiner", "--alg", "ML-DSA-44", "--as", "alice")
    media = make_media("ts", tmp_path, duration_s=3, fps=10, gop=10)
    out = tmp_path / "b"

    _run(home, "seal", str(media), str(out), "--key", "device", "--profile", "fast", "--as", "carol", ok=False)  # examiner may not seal
    assert not out.exists()
    _run(home, "seal", str(media), str(out), "--key", "device", "--profile", "fast", ok=False)                   # anonymous: refused
    r = _run(home, "seal", str(media), str(out), "--key", "device", "--profile", "fast", "--as", "bob")
    assert "attested by bob, collector" in r.output

    assert "VERIFIED" in _run(home, "verify", str(out), "--require-operator").output
    _run(home, "open", str(out), str(tmp_path / "o1"), "--as", "bob", ok=False)                                # collector may not release plaintext
    _run(home, "open", str(out), str(tmp_path / "o2"), "--as", "carol")
    _run(home, "user-add", "mallory", "--role", "admin", "--as", "carol", ok=False)                             # only admins manage users
    _run(home, "user-revoke", "carol", "--as", "alice")
    _run(home, "open", str(out), str(tmp_path / "o3"), "--as", "carol", ok=False)                              # revoked
    log = _run(home, "access-log", "--as", "alice").output
    assert "access log intact" in log and "user-revoke" in log and "act" in log
