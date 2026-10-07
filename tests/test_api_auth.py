"""Live API with authentication ON: login with a signing key, role enforcement, signed access log."""
from __future__ import annotations

import http.cookiejar
import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest
import uvicorn

from evseal import access
from evseal.api import app as api_app
from evseal.api import auth as api_auth
from evseal.bench.synth import make_media
from evseal.dr import custody
from evseal.longterm import keys
from evseal.workspace import Workspace

PW = {u: f"pw-{u}" for u in ("alice", "bob", "carol", "dave")}
ROLE = {"alice": "admin", "bob": "collector", "carol": "examiner", "dave": "auditor"}


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    import os

    os.environ.pop("EVSEAL_AUTH", None)
    ws = Workspace(tmp_path_factory.mktemp("authapi"))
    ws.keygen("device", "ML-DSA-65")
    kps = {}
    for u in PW:
        kps[u] = keys.generate("ML-DSA-44", u)
        keys.save(kps[u], ws.user_keys_dir, PW[u])  # passphrase-encrypted at rest
    access.init_admin(ws.home, "alice", kps["alice"])
    for u in ("bob", "carol", "dave"):
        access.add_user(ws.home, "alice", kps["alice"], u, ROLE[u], kps[u].public())
    (ws.home / "profiles").mkdir(exist_ok=True)
    (ws.home / "profiles" / "fast.toml").write_text('[checkpoint]\nalg = "ML-DSA-44"\n[sign]\nalg = "ML-DSA-44"\n')
    api_app.WS = ws
    api_auth.SESSIONS = api_auth.Sessions()
    api_app.auth.SESSIONS = api_auth.SESSIONS
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = uvicorn.Server(uvicorn.Config(api_app.app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            urllib.request.urlopen(f"{url}/api/auth/session", timeout=2)
            break
        except Exception:
            time.sleep(0.1)
    yield {"url": url, "ws": ws}
    server.should_exit = True
    t.join(timeout=3)


class Client:
    def __init__(self, url):
        self.url = url
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method, path, body=None, raw=None, headers=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        h = dict(headers or {})
        if body is not None:
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=data, headers=h, method=method)
        try:
            with self.op.open(req, timeout=30) as r:
                txt = r.read().decode()
                return r.status, (json.loads(txt) if "json" in r.headers.get("content-type", "") else txt)
        except urllib.error.HTTPError as e:
            txt = e.read().decode()
            try:
                return e.code, json.loads(txt)
            except ValueError:
                return e.code, txt

    def login(self, user, pw=None):
        return self.call("POST", "/api/auth/login", {"user": user, "passphrase": PW[user] if pw is None else pw})


def _seal_via_api(c, srv, tmp_path, name):
    media = make_media("ts", tmp_path, duration_s=3, fps=10, gop=10).read_bytes()
    b = "----x1"
    raw = b"\r\n".join([f"--{b}".encode(), b'Content-Disposition: form-data; name="files"; filename="t.ts"', b"Content-Type: video/mp2t", b"",
                        media, f"--{b}--".encode(), b""])
    st, up = c.call("POST", "/api/uploads", raw=raw, headers={"Content-Type": f"multipart/form-data; boundary={b}"})
    assert st == 200, up
    st, job = c.call("POST", "/api/seal", {"upload_id": up["upload_id"], "profile": "fast", "key": "device", "name": name})
    return st, job


def _wait_sealed(c, jid):
    req = urllib.request.Request(c.url + f"/api/jobs/{jid}/events")
    with c.op.open(req, timeout=60) as stream:
        while True:
            raw = stream.readline()
            if not raw:  # EOF; blank SSE separator lines are not empty reads
                return None
            line = raw.decode().strip()
            if line.startswith("data: "):
                ev = json.loads(line[6:])
                if ev.get("stage") == "end":
                    return ev


def test_unauthenticated_requests_are_refused(srv):
    c = Client(srv["url"])
    assert c.call("GET", "/api/bundles")[0] == 401
    assert c.call("DELETE", "/api/bundles/x")[0] == 401
    st, s = c.call("GET", "/api/auth/session")
    assert st == 200 and s["user"] is None and s["auth"] == "on"


def test_wrong_passphrase_fails_and_repeated_failures_are_throttled(srv):
    c = Client(srv["url"])
    for _ in range(api_auth.MAX_FAILS):
        assert c.login("dave", "nope")[0] == 401
    assert c.login("dave", "nope")[0] == 429
    assert c.login("dave")[0] == 429  # even the right passphrase waits out the window
    api_auth.SESSIONS._fails.clear()
    assert c.login("dave")[0] == 200


def test_roles_are_enforced_and_denials_are_signed_and_attributable(srv, tmp_path):
    ws = srv["ws"]
    bob = Client(srv["url"])
    assert bob.login("bob")[0] == 200
    st, s = bob.call("GET", "/api/auth/session")
    assert s["user"] == "bob" and s["role"] == "collector" and "seal" in s["permissions"] and "open" not in s["permissions"]
    assert bob.call("GET", "/api/bundles")[0] == 200
    assert bob.call("DELETE", "/api/bundles/nothing")[0] == 403              # collector may not delete
    assert bob.call("GET", "/api/audit/log")[0] == 403
    assert bob.call("POST", "/api/bundles/nothing/open", {"partial": False})[0] == 403  # collector may not release plaintext
    assert bob.call("POST", "/api/keys", {"name": "x", "alg": "ML-DSA-44"})[0] == 403   # only admins manage keys
    recs = custody.entries(ws.home, access.LOG)
    denied = [r for r in recs if r["action"] == "denied" and r.get("actor_id") == "bob"]
    assert len(denied) >= 4 and all(r["actor_fp"] for r in denied)
    access.replay(ws.home)  # the log with all these entries still verifies


def test_collector_seals_and_the_bundle_carries_the_operator_signature(srv, tmp_path):
    bob, carol, dave = Client(srv["url"]), Client(srv["url"]), Client(srv["url"])
    bob.login("bob"), carol.login("carol"), dave.login("dave")
    st, job = _seal_via_api(bob, srv, tmp_path, "att-bundle")
    assert st == 200, job
    ev = _wait_sealed(bob, job["job"])
    assert ev and ev["status"] == "done", ev
    assert carol.call("POST", "/api/bundles/att-bundle/verify")[1]["overall"] == "VERIFIED"
    rep = carol.call("GET", "/api/bundles/att-bundle/report")[1]
    assert any("sealed by bob (collector)" in c["detail"] for c in rep["checks"])
    st, md = carol.call("GET", "/api/bundles/att-bundle/court-report?custodian=C.+Carol")
    assert st == 200 and "C. Carol" in md and "VERIFIED" in md
    assert carol.call("POST", "/api/bundles/att-bundle/open", {"partial": False})[0] == 200   # examiner releases plaintext
    assert dave.call("POST", "/api/bundles/att-bundle/open", {"partial": False})[0] == 403    # auditor may not
    assert carol.call("POST", "/api/bundles/att-bundle/repair/run")[0] == 403                 # examiner may not repair
    assert dave.call("GET", "/api/audit/log")[1]["intact"] is True


def test_revocation_takes_effect_immediately_for_open_sessions(srv):
    ws = srv["ws"]
    carol = Client(srv["url"])
    assert carol.login("carol")[0] == 200
    assert carol.call("GET", "/api/bundles")[0] == 200
    alice_kp = keys.load_private(ws.user_keys_dir / "alice.key.json", PW["alice"])
    access.revoke_user(ws.home, "alice", alice_kp, "carol")
    assert carol.call("GET", "/api/bundles")[0] == 403
    assert Client(srv["url"]).login("carol")[0] == 401


def test_tampered_access_log_locks_the_api(srv):
    ws = srv["ws"]
    log = ws.home / access.LOG
    saved = log.read_text()
    try:
        lines = saved.splitlines()
        rec = json.loads(lines[1])
        rec["detail"]["role"] = "admin"
        lines[1] = json.dumps(rec, separators=(",", ":"))
        log.write_text("\n".join(lines) + "\n")
        c = Client(srv["url"])
        assert c.call("GET", "/api/bundles")[0] == 503
    finally:
        log.write_text(saved)
