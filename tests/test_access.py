"""Roles, signed identities and non-repudiation (evseal/access.py)."""
from __future__ import annotations

import json
import random
import shutil

import pytest

from evseal import access
from evseal.core import profile as prof
from evseal.core.hashing import dual_hash
from evseal.core.seal import seal
from evseal.core.unit import SourceUnits, Unit
from evseal.core.verify import verify
from evseal.dr import custody
from evseal.longterm import keys
from evseal.workspace import Workspace

FAST = {"checkpoint": {"alg": "ML-DSA-44"}, "ec": {"k": 2, "m": 1, "interleave": 1}}


@pytest.fixture()
def org(tmp_path):
    """A workspace with an admin, a collector, an examiner and an auditor."""
    ws = Workspace(tmp_path / "ws")
    ws.keygen("device-root", "ML-DSA-87")
    kps = {u: keys.generate("ML-DSA-44", u) for u in ("alice", "bob", "carol", "dave")}
    access.init_admin(ws.home, "alice", kps["alice"])
    for uid, role in (("bob", "collector"), ("carol", "examiner"), ("dave", "auditor")):
        access.add_user(ws.home, "alice", kps["alice"], uid, role, kps[uid].public())
    return ws, kps


def _seal(ws, out, n=3):
    rng = random.Random(9)
    p = prof._merge(ws.profile(None), FAST)
    su = SourceUnits("video", [Unit(data=rng.randbytes(200), t=float(i), dur=1.0, offset=i * 200) for i in range(n)], {})
    seal(su, p, ws.root("device-root"), out, file_hash=dual_hash(su.reconstruct(), p["hash"]["content"]),
         tsa=ws.tsa(), anchor_log=ws.anchor_log())
    return out


def test_directory_replays_and_roles_are_enforced(org):
    ws, _ = org
    d = access.replay(ws.home)
    assert {u.id: u.role for u in d.users.values()} == {"alice": "admin", "bob": "collector", "carol": "examiner", "dave": "auditor"}
    assert access.authorize(d, "bob", "seal").id == "bob"
    for uid, perm in (("bob", "open"), ("carol", "seal"), ("dave", "open"), ("carol", "repair"), ("bob", "users"), ("dave", "delete")):
        with pytest.raises(access.Denied):
            access.authorize(d, uid, perm)
    assert access.authorize(d, "carol", "open") and access.authorize(d, "dave", "audit")
    with pytest.raises(access.Denied):
        access.authorize(d, "mallory", "read")


def test_only_an_admin_may_change_the_directory(org):
    ws, kps = org
    eve = keys.generate("ML-DSA-44", "eve")
    with pytest.raises(access.Denied):
        access.add_user(ws.home, "bob", kps["bob"], "eve", "admin", eve.public())
    with pytest.raises(access.Denied):  # right id, wrong key
        access.add_user(ws.home, "alice", kps["bob"], "eve", "admin", eve.public())


def test_tampering_with_the_access_log_invalidates_the_directory(org):
    ws, _ = org
    log = ws.home / access.LOG
    lines = log.read_text().splitlines()
    rec = json.loads(lines[2])  # carol's user-add
    rec["detail"]["role"] = "admin"  # privilege escalation by editing the file
    lines[2] = json.dumps(rec, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n")
    with pytest.raises(access.AccessError):
        access.replay(ws.home)
    assert ws.trust().actors == {}  # a damaged directory vouches for nobody


def test_dropping_a_middle_entry_is_detected(org):
    ws, _ = org
    log = ws.home / access.LOG
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    with pytest.raises(access.AccessError):
        access.replay(ws.home)


def test_revocation_and_last_admin_protection(org):
    ws, kps = org
    access.revoke_user(ws.home, "alice", kps["alice"], "carol")
    with pytest.raises(access.Denied):
        access.authorize(access.replay(ws.home), "carol", "verify")
    with pytest.raises(access.AccessError):  # alice is the only admin
        access.revoke_user(ws.home, "alice", kps["alice"], "alice")
    access.set_role(ws.home, "alice", kps["alice"], "bob", "admin")
    access.revoke_user(ws.home, "alice", kps["alice"], "alice")  # fine once bob is admin
    assert [u.id for u in access.replay(ws.home).admins()] == ["bob"]


def test_signed_entries_are_attributable_and_wrong_key_is_refused(org):
    ws, kps = org
    d = access.replay(ws.home)
    rec = access.record(ws.home, d.users["bob"], kps["bob"], "act", {"perm": "seal", "path": "/api/seal"})
    assert rec["actor_id"] == "bob" and rec["actor_fp"] == kps["bob"].fp and rec["sig"]
    with pytest.raises(access.Denied):
        access.record(ws.home, d.users["bob"], kps["carol"], "act", {})
    access.replay(ws.home)  # operational entries keep the log valid


def test_seal_attestation_binds_operator_to_the_bundle(org, tmp_path):
    ws, kps = org
    d = access.replay(ws.home)
    b = _seal(ws, tmp_path / "b")
    access.attest_seal(b, d.users["bob"], kps["bob"])
    tr = ws.trust()
    tr.require_operator = True
    rep = verify(b, tr)
    assert rep.overall == "VERIFIED"
    assert any("sealed by bob (collector)" in c["detail"] for c in rep.checks)


def test_policy_requires_an_attestation_and_rejects_unknown_signers(org, tmp_path):
    ws, kps = org
    d = access.replay(ws.home)
    plain = _seal(ws, tmp_path / "plain")
    tr = ws.trust()
    assert verify(plain, tr).overall == "VERIFIED"  # policy off: not required
    tr.require_operator = True
    rep = verify(plain, tr)
    assert rep.overall == "NOT_VERIFIED" and any("operator attestation" in r for r in rep.reasons)
    mallory = keys.generate("ML-DSA-44", "mallory")  # key the directory never registered
    ghost = access.User("bob", "collector", mallory.alg, mallory.pk.hex(), mallory.fp)
    access.attest_seal(plain, ghost, mallory)
    assert verify(plain, tr).overall == "NOT_VERIFIED"


def test_attestation_copied_to_another_bundle_does_not_verify(org, tmp_path):
    ws, kps = org
    d = access.replay(ws.home)
    a, b = _seal(ws, tmp_path / "a"), _seal(ws, tmp_path / "b")
    access.attest_seal(a, d.users["bob"], kps["bob"])
    shutil.copy(a / "custody.log", b / "custody.log")  # replay another bundle's attestation
    rep = verify(b, ws.trust())
    assert rep.overall == "NOT_VERIFIED" and any("does not match this bundle" in r for r in rep.reasons)


def test_concurrent_appends_keep_the_chain_intact(org):
    import threading

    ws, kps = org
    d = access.replay(ws.home)
    ts = [threading.Thread(target=lambda: [access.record(ws.home, d.users["bob"], kps["bob"], "act", {"i": i}) for i in range(5)]) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(custody.entries(ws.home, access.LOG)) == 4 + 20
    access.replay(ws.home)
