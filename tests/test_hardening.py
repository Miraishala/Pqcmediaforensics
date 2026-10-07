"""Failure-mode audit regressions: hostile/odd input must be a clean verdict or a clear seal-time error."""
from __future__ import annotations

import json
import os
import random
import shutil

import pytest

from evseal.core import profile as prof
from evseal.core.hashing import dual_hash
from evseal.core.seal import seal
from evseal.core.unit import SourceUnits, Unit
from evseal.core.verify import verify
from evseal.workspace import Workspace

FAST = {"checkpoint": {"alg": "ML-DSA-44"}, "ec": {"k": 2, "m": 1, "interleave": 1}, "keys": {"rotation_s": 60}}


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    ws = Workspace(tmp_path_factory.mktemp("hard") / "ws")
    ws.keygen("r")
    return ws


def _seal(lab, out, ts, tsa=True):
    rng = random.Random(1234)  # seeded: deterministic payloads
    p = prof._merge(lab.profile(None), FAST)
    su = SourceUnits("video", [Unit(data=rng.randbytes(300), t=float(t), dur=1.0, offset=i * 300) for i, t in enumerate(ts)], {})
    seal(su, p, lab.root("r"), out, file_hash=dual_hash(su.reconstruct(), p["hash"]["content"]),
         tsa=lab.tsa() if tsa else None, anchor_log=lab.anchor_log())
    return out


def test_baseline_verifies(lab, tmp_path):
    assert verify(_seal(lab, tmp_path / "b", [0, 1, 2]), lab.trust()).overall == "VERIFIED"


def test_non_zip_bundle_is_rejected_not_crash(lab, tmp_path):
    junk = tmp_path / "junk.evseal"
    junk.write_bytes(b"not a zip")
    assert verify(junk, lab.trust()).overall == "REJECTED"


def test_huge_chunk_length_in_manifest_does_not_crash(lab, tmp_path):
    b = _seal(lab, tmp_path / "b", [0, 1, 2])
    m = json.loads((b / "manifest.json").read_text())
    m["units"][0]["chunks"] = [10**12]
    (b / "manifest.json").write_text(json.dumps(m))
    (b / "manifest.copy.json").unlink()
    shutil.rmtree(b / "manifest_rs")
    # was an uncaught MemoryError; parity may legitimately rebuild the unit (AEAD + signed R_i still authenticate it)
    assert verify(b, lab.trust()).overall in ("VERIFIED", "REJECTED", "NOT_VERIFIED")


def test_seal_refuses_time_going_backwards_across_periods(lab, tmp_path):
    with pytest.raises(ValueError, match="went backwards"):
        _seal(lab, tmp_path / "b", [0, 30, 70, 20, 40])


def test_seal_refuses_without_timestamp_source(lab, tmp_path):
    with pytest.raises(ValueError, match="no timestamp source"):
        _seal(lab, tmp_path / "b", [0, 1, 2], tsa=False)


def _final_token_time(b):
    m = json.loads((b / "manifest.json").read_text())
    return next(r for r in m["records"] if r["type"] == "final")["tst"][0]["time"], m["root"]["fp"]


def test_revocation_after_sealing_keeps_evidence_valid(lab, tmp_path):
    b = _seal(lab, tmp_path / "b", [0, 1, 2])
    t, fp = _final_token_time(b)
    tr = lab.trust()
    tr.revocations[fp] = t + 1000  # revoked long after the timestamped seal
    assert verify(b, tr).overall == "VERIFIED"


def test_revocation_before_timestamp_proof_fails(lab, tmp_path):
    b = _seal(lab, tmp_path / "b", [0, 1, 2])
    t, fp = _final_token_time(b)
    tr = lab.trust()
    tr.revocations[fp] = t  # cert was issued before this, but nothing proves signing predates revocation
    rep = verify(b, tr)
    assert rep.overall == "NOT_VERIFIED" and any("revocation" in r for r in rep.reasons)


def test_tsa_clock_offset_reported_and_policy_controlled(lab, tmp_path):
    import time

    from evseal.longterm.timestamps import LocalTSA

    tsa = LocalTSA(lab.home / "tsa", clock=lambda: time.time() + 3 * 86400)
    rng = random.Random(7)
    p = prof._merge(lab.profile(None), FAST)
    su = SourceUnits("video", [Unit(data=rng.randbytes(200), t=float(i), dur=1.0) for i in range(3)], {})
    b = tmp_path / "b"
    seal(su, p, lab.root("r"), b, file_hash=dual_hash(su.reconstruct(), p["hash"]["content"]), tsa=tsa, anchor_log=lab.anchor_log())
    rep = verify(b, lab.trust())
    assert rep.overall == "NOT_VERIFIED" and any("outside the signing key" in r for r in rep.reasons)
    wide = lab.trust()
    wide.slack_s = 4 * 86400
    assert verify(b, wide).overall == "VERIFIED"


def test_seal_blocks_dev_only_backend_unless_overridden(lab, tmp_path, monkeypatch):
    from evseal.core import crypto

    monkeypatch.setattr(crypto, "is_dev_only", lambda alg: True)
    monkeypatch.delenv("EVSEAL_ALLOW_DEV_CRYPTO", raising=False)
    with pytest.raises(RuntimeError, match="DEV-ONLY"):
        _seal(lab, tmp_path / "b", [0, 1])
    monkeypatch.setenv("EVSEAL_ALLOW_DEV_CRYPTO", "1")
    assert verify(_seal(lab, tmp_path / "c", [0, 1]), lab.trust()).overall == "VERIFIED"


def test_unit_size_cap_splits_big_units_and_stays_bit_exact(tmp_path):
    from evseal.bench.synth import make_media
    from evseal.core.seal import load_source

    ts = make_media("ts", tmp_path, duration_s=4, fps=10, gop=10)
    base = prof.resolve(prof._merge(prof.DEFAULTS, {"segment": {"max_unit_mb": 0}}))
    capped = prof.resolve(prof._merge(prof.DEFAULTS, {"segment": {"max_unit_mb": 0.02}}))
    a, b = load_source(ts, base), load_source(ts, capped)
    assert len(b.units) > len(a.units)
    assert b.reconstruct() == ts.read_bytes()


def test_old_profile_without_new_knob_still_validates():
    p = prof.resolve(None)
    del p["segment"]["max_unit_mb"]
    assert prof.validate(p)[0] == []


def test_mp4_clip_preview_is_compact_not_sparse(lab, tmp_path):
    from evseal.bench.synth import make_media
    from evseal.core.clip import make_clip
    from evseal.core.open import open_bundle
    from evseal.core.seal import seal_path

    src = make_media("mp4_moovend", tmp_path, duration_s=6, fps=10, gop=10)
    b = tmp_path / "b"
    seal_path(src, prof._merge(lab.profile(None), FAST), lab.root("r"), b, tsa=lab.tsa(), anchor_log=lab.anchor_log())
    clip = tmp_path / "clip"
    make_clip(b, 3, 4, clip)
    _, out = open_bundle(clip, lab.trust(), tmp_path / "o")
    assert "preview" in out and os.path.getsize(out["preview"]) < src.stat().st_size
    assert not list((tmp_path / "o").glob(".*.mp4")) and not list((tmp_path / "o").glob(".sparse*"))


def _ts_straddles(data: bytes, cut: int) -> bool:
    """Independent check: does any PES-carrying PID have a PES open across `cut`?"""
    pids, nxt = set(), {}
    for i in range(0, len(data) - 187, 188):
        pid, pusi = ((data[i + 1] & 0x1F) << 8) | data[i + 2], bool(data[i + 1] & 0x40)
        if pusi and pid not in (0, 0x1FFF):
            off = i + 4 + ((1 + data[i + 4]) if data[i + 3] & 0x20 else 0)
            if data[off : off + 3] == b"\x00\x00\x01":
                pids.add(pid)
    for i in range(cut, len(data) - 187, 188):
        pid, pusi = ((data[i + 1] & 0x1F) << 8) | data[i + 2], bool(data[i + 1] & 0x40)
        if pid in pids and pid not in nxt:
            nxt[pid] = pusi
        if len(nxt) == len(pids):
            break
    return not all(nxt.values())


def test_ts_cuts_do_not_split_audio_or_video_pes(tmp_path):
    from evseal.bench.synth import make_media
    from evseal.core.seal import load_source

    ts = make_media("ts", tmp_path, duration_s=8, fps=10, gop=10)
    su = load_source(ts, prof.resolve(None))
    assert su.reconstruct() == ts.read_bytes()
    data, bounds, pos = ts.read_bytes(), [], 0
    for u in su.units:
        pos += len(u.data)
        bounds.append(pos)
    inner = [b for b in bounds[:-2] if b % 188 == 0][1:]  # skip header/first and trailer edges
    assert inner and not any(_ts_straddles(data, b) for b in inner)


def _ts_pkt(pid: int, pusi: bool) -> bytes:
    hdr = bytes([0x47, (0x40 if pusi else 0) | (pid >> 8), pid & 0xFF, 0x10])
    body = (b"\x00\x00\x01" + bytes([0xE0 if pid == 0x100 else 0xC0]) if pusi else b"")
    return hdr + body + b"\xaa" * (184 - len(body))


def test_ts_clean_cut_moves_off_a_straddling_audio_pes():
    from evseal.media.common import _ts_clean_cut, _ts_pes_pids

    V, A = 0x100, 0x101
    seq = [(V, 1), (V, 0), (A, 1), (A, 0), (V, 1), (A, 0), (A, 1), (V, 0)]  # cut before index 4 splits an audio PES
    data = b"".join(_ts_pkt(p, bool(u)) for p, u in seq)
    pids = _ts_pes_pids(data)
    assert pids == {V, A} and _ts_straddles(data, 4 * 188)
    cut = _ts_clean_cut(data, 4 * 188, 0, pids)
    assert cut == 2 * 188 and not _ts_straddles(data, cut)
    # no clean point inside the allowed window: keep the keyframe cut rather than guessing
    assert _ts_clean_cut(data, 4 * 188, 3 * 188, pids) == 4 * 188


def test_unit_time_is_signed_edit_is_detected(lab, tmp_path):
    b = _seal(lab, tmp_path / "b", [0, 1, 2])
    m = json.loads((b / "manifest.json").read_text())
    m["units"][1]["t"] += 0.5  # attacker rewrites when unit 2 was captured
    (b / "manifest.json").write_text(json.dumps(m))
    (b / "manifest.copy.json").unlink()
    shutil.rmtree(b / "manifest_rs")
    rep = verify(b, lab.trust())
    assert rep.overall == "NOT_VERIFIED"
    assert [u.status for u in rep.units] == ["VERIFIED", "TAMPERED", "VERIFIED"]


def test_v1_bundle_without_signed_times_still_verifies(lab, tmp_path, monkeypatch):
    from evseal.core import manifest, seal as seal_mod

    # emulate a pre-D6 sealer: v1 format tag and v1 block message (no T)
    monkeypatch.setattr(seal_mod, "FORMAT", manifest.FORMAT_V1)
    orig = seal_mod.block_msg
    monkeypatch.setattr(seal_mod, "block_msg", lambda rid, a, z, rs, cs, tt=None: orig(rid, a, z, rs, cs))
    b = _seal(lab, tmp_path / "b", [0, 1, 2])
    m = json.loads((b / "manifest.json").read_text())
    assert m["format"] == manifest.FORMAT_V1
    for r in m["records"]:
        r.pop("T", None)
    (b / "manifest.json").write_text(json.dumps(m))
    (b / "manifest.copy.json").unlink()
    shutil.rmtree(b / "manifest_rs")
    assert verify(b, lab.trust()).overall == "VERIFIED"


def test_report_for_verified_and_tampered_bundles(lab, tmp_path):
    from evseal.report import write_report

    b = _seal(lab, tmp_path / "b", [0, 1, 2])
    r = write_report(b, lab.trust(), tmp_path / "r.md", custodian="A. Custodian", device="Cam-7")
    text = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert r["facts"]["verdict"] == "VERIFIED" and "A. Custodian" in text and r["facts"]["rid"] in text
    assert all(h in text for _, h in r["facts"]["original_file_hashes"]) and "Part A" in text
    seg = b / "segments" / "000002.seg"
    seg.write_bytes(bytes(x ^ 1 for x in seg.read_bytes()[:20]) + seg.read_bytes()[20:])
    (b / "parity").exists() and shutil.rmtree(b / "parity")
    write_report(b, lab.trust(), tmp_path / "t.md")
    bad = (tmp_path / "t.md").read_text(encoding="utf-8")
    assert "did **not** verify" in bad and "Part A" not in bad


def test_evseal_verify_cli_exit_codes_and_no_ui_imports(lab, tmp_path):
    import subprocess
    import sys

    b = _seal(lab, tmp_path / "b", [0, 1, 2])
    root = next((lab.keys_dir).glob("*.pub.json"))
    tsa = lab.home / "tsa" / "tsa.pub.json"
    code = ("import sys; from evseal.verify_cli import main; rc = main(sys.argv[1:]); "
            "bad = [m for m in ('typer','fastapi','uvicorn') if m in sys.modules]; print('UI_IMPORTS', bad); sys.exit(rc)")
    ok = subprocess.run([sys.executable, "-c", code, str(b), "--root", str(root), "--tsa", str(tsa)], capture_output=True, text=True)
    assert ok.returncode == 0 and "overall: VERIFIED" in ok.stdout and "UI_IMPORTS []" in ok.stdout
    (b / "segments" / "000001.seg").write_bytes(b"x" * 10)
    shutil.rmtree(b / "parity", ignore_errors=True)
    bad = subprocess.run([sys.executable, "-c", code, str(b), "--root", str(root), "--tsa", str(tsa)], capture_output=True, text=True)
    assert bad.returncode == 1


def test_framing_units_at_t0_do_not_trip_the_time_guard(lab, tmp_path):
    """moov-at-end MP4: header and trailer carry t=0 in the segmenter; the trailer is moved to the end time before the guard."""
    rng = random.Random(3)
    p = prof._merge(lab.profile(None), FAST)
    mk = lambda role, t: Unit(data=rng.randbytes(100), role=role, t=float(t), dur=1.0 if role == "data" else 0.0)
    su = SourceUnits("video", [mk("header", 0), mk("data", 0), mk("data", 30), mk("data", 70), mk("trailer", 0)], {})
    b = tmp_path / "b"
    seal(su, p, lab.root("r"), b, file_hash=dual_hash(su.reconstruct(), p["hash"]["content"]), tsa=lab.tsa(), anchor_log=lab.anchor_log())
    assert verify(b, lab.trust()).overall == "VERIFIED"


def test_root_key_encrypted_at_rest_when_passphrase_set(tmp_path, monkeypatch):
    monkeypatch.setenv("EVSEAL_KEY_PASSPHRASE", "correct horse")
    ws = Workspace(tmp_path / "ws")
    ws.keygen("enc-root", "ML-DSA-44")
    f = ws.keys_dir / "enc-root.key.json"
    d = json.loads(f.read_text())
    assert "enc" in d and "sk" not in d
    sk_hex = ws.root("enc-root").sk.hex()
    assert sk_hex not in f.read_text()
    monkeypatch.setenv("EVSEAL_KEY_PASSPHRASE", "wrong")
    with pytest.raises(ValueError, match="wrong passphrase"):
        ws.root("enc-root")
    monkeypatch.delenv("EVSEAL_KEY_PASSPHRASE")
    with pytest.raises(ValueError, match="passphrase-protected"):
        ws.root("enc-root")


def test_benchmark_refuses_dev_only_backend_and_records_environment(monkeypatch):
    from evseal.bench import sweep
    from evseal.core import crypto

    env = sweep.environment({"ML-DSA-44"})
    assert env["cpu_count"] and "backends" in env and "ML-DSA-44" in env["backends"]
    monkeypatch.setattr(crypto, "get_signature_backend", lambda alg: (None, "pure-python"))
    monkeypatch.delenv("EVSEAL_ALLOW_DEV_CRYPTO", raising=False)
    with pytest.raises(RuntimeError, match="DEV-ONLY"):
        sweep.run_sweep(quick=True)


def test_external_signer_keeps_private_key_out_of_the_workspace(lab, tmp_path):
    import sys

    from evseal.longterm import keys

    hsm = tmp_path / "hsm"  # stands in for the device's secure storage
    kp = keys.generate("ML-DSA-87", "hsm-root")
    keys.save(kp, hsm)
    ws = Workspace(tmp_path / "ws")
    keys.register_external("hsm-root", kp.public(), [sys.executable, "-m", "evseal.signer_stub", str(hsm / "hsm-root.key.json")], ws.keys_dir)
    assert "sk" not in json.loads((ws.keys_dir / "hsm-root.key.json").read_text())
    root = ws.root("hsm-root")
    assert root.signer and not root.sk
    p = prof._merge(ws.profile(None), FAST)
    su = SourceUnits("video", [Unit(data=os.urandom(200), t=float(i), dur=1.0) for i in range(3)], {})
    b = tmp_path / "b"
    seal(su, p, root, b, file_hash=dual_hash(su.reconstruct(), p["hash"]["content"]), tsa=ws.tsa(), anchor_log=ws.anchor_log())
    assert verify(b, ws.trust()).overall == "VERIFIED"


def test_pq_witness_is_added_next_to_rfc3161_and_checked(lab, tmp_path):
    from evseal.longterm.timestamps import stamp

    p = prof._merge(lab.profile(None), {"timestamps": {"tsa_urls": ["http://127.0.0.1:9"]}})
    kinds = [t["kind"] for t in stamp(p, b"msg", lab.tsa())]
    assert kinds == ["queued", "local"]


def test_external_signer_with_garbage_output_fails_at_seal_time(tmp_path):
    import sys

    from evseal.longterm import keys

    kp = keys.generate("ML-DSA-44", "bad")
    ws = Workspace(tmp_path / "ws")
    keys.register_external("bad", kp.public(), [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'junk')"], ws.keys_dir)
    with pytest.raises(RuntimeError, match="does not verify"):
        ws.root("bad").sign(b"msg")
