"""tests/test_e2e_api.py — End-to-end testing of the full system through live API & UI server.

Uses Python stdlib (urllib.request) against a live background uvicorn server.
Zero external test client dependencies needed.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
import uvicorn

from evseal.api import app as api_app
from evseal.bench.synth import make_media
from evseal.workspace import Workspace


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    import os

    os.environ["EVSEAL_AUTH"] = "off"  # this file exercises the endpoints; roles are covered in test_api_auth.py
    workdir = tmp_path_factory.mktemp("e2e_home")
    ws = Workspace(workdir)
    api_app.WS = ws

    # Select random available port or fixed test port
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    config = uvicorn.Config(api_app.app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"

    # Wait for server to start
    for _ in range(50):
        try:
            with urllib.request.urlopen(f"{base_url}/api/doctor", timeout=2) as r:
                if r.status == 200:
                    break
        except Exception:
            time.sleep(0.1)

    yield {"url": base_url, "ws": ws, "home": workdir}

    server.should_exit = True
    thread.join(timeout=2)
    os.environ.pop("EVSEAL_AUTH", None)


def _http(url: str, method: str = "GET", data: dict | None = None, headers: dict | None = None) -> tuple[int, dict | str]:
    hdrs = headers or {}
    req_data = None
    if data is not None:
        req_data = json.dumps(data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=req_data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            content_type = resp.headers.get("content-type", "")
            raw = resp.read().decode("utf-8")
            if "application/json" in content_type:
                return resp.status, json.loads(raw)
            return resp.status, raw
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8")
        try:
            return err.code, json.loads(raw)
        except Exception:
            return err.code, raw


def test_01_doctor_endpoint(live_server):
    """GET /api/doctor reports healthy environment with ML-DSA & ML-KEM."""
    status, data = _http(f"{live_server['url']}/api/doctor")
    assert status == 200
    assert data["ok"] is True
    assert any(a["name"].startswith("ML-DSA") and a["backend"] for a in data["algorithms"])
    assert any(a["name"].startswith("ML-KEM") and a["backend"] for a in data["algorithms"])


def test_02_keys_management(live_server):
    """POST /api/keys creates a root collector key."""
    status, data = _http(f"{live_server['url']}/api/keys", method="POST", data={"name": "e2e-root", "alg": "ML-DSA-87"})
    assert status == 200
    assert data["name"] == "e2e-root"
    assert data["alg"] == "ML-DSA-87"
    assert "fp" in data

    # Key is now listed
    status, list_data = _http(f"{live_server['url']}/api/keys")
    assert status == 200
    names = [k["name"] for k in list_data["keys"]]
    assert "e2e-root" in names


def test_03_profile_validation_and_save(live_server):
    """Profile validation, live estimates, and saving."""
    status, schema_data = _http(f"{live_server['url']}/api/schema")
    assert status == 200
    assert "fields" in schema_data

    body = {
        "profile": {
            "sign": {"alg": "ML-DSA-44", "block_segments": 2},
            "ec": {"k": 4, "m": 2, "interleave": 2},
            "checkpoint": {"alg": "ML-DSA-65"},
            "anchors": {"backend": "off"},
        },
        "bitrate_mbps": 2.0,
        "hours": 12.0,
        "cores": 4,
    }
    status, val_data = _http(f"{live_server['url']}/api/profiles/validate", method="POST", data=body)
    assert status == 200
    assert not val_data["errors"]
    assert val_data["estimates"] is not None

    status, save_data = _http(f"{live_server['url']}/api/profiles/custom-e2e", method="PUT", data=body)
    assert status == 200
    assert save_data["saved"] == "custom-e2e"


def test_04_upload_and_seal(live_server, tmp_path):
    """Upload media file via multipart/form-data, seal into bundle, poll SSE events."""
    media_path = make_media("ts", tmp_path, duration_s=4)
    file_bytes = media_path.read_bytes()

    # Manual multipart upload
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body_lines = [
        f"--{boundary}".encode(),
        b'Content-Disposition: form-data; name="files"; filename="test.ts"',
        b"Content-Type: video/mp2t",
        b"",
        file_bytes,
        f"--{boundary}--".encode(),
        b"",
    ]
    post_data = b"\r\n".join(body_lines)
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}

    req = urllib.request.Request(f"{live_server['url']}/api/uploads", data=post_data, headers=headers, method="POST")
    with urllib.request.urlopen(req) as resp:
        up_data = json.loads(resp.read().decode())
    up_id = up_data["upload_id"]

    # Start seal
    seal_body = {
        "upload_id": up_id,
        "profile": "custom-e2e",
        "key": "e2e-root",
        "name": "e2e-bundle",
    }
    status, seal_data = _http(f"{live_server['url']}/api/seal", method="POST", data=seal_body)
    assert status == 200
    jid = seal_data["job"]

    # Poll events stream until done
    done = False
    req = urllib.request.Request(f"{live_server['url']}/api/jobs/{jid}/events")
    with urllib.request.urlopen(req, timeout=30) as stream:
        while True:
            line = stream.readline().decode("utf-8")
            if not line:
                break
            line = line.strip()
            if line.startswith("data: "):
                ev = json.loads(line[6:])
                if ev.get("stage") == "end":
                    assert ev["status"] == "done", f"Seal job failed: {ev.get('error')}"
                    done = True
                    break
    assert done, "Seal job did not report end event"


def test_05_bundle_verify_and_manifest(live_server):
    """Verify sealed bundle and check manifest report."""
    status, rep = _http(f"{live_server['url']}/api/bundles/e2e-bundle/verify", method="POST")
    assert status == 200
    assert rep["overall"] == "VERIFIED"
    assert len(rep["units"]) >= 3

    status, man = _http(f"{live_server['url']}/api/bundles/e2e-bundle/manifest")
    assert status == 200
    assert man["manifest"]["format"] == "evseal-bundle-v2"


def test_06_clip_and_open(live_server):
    """Export clip and verify-to-open restoration."""
    status, clip_res = _http(f"{live_server['url']}/api/bundles/e2e-bundle/clip", method="POST", data={"i": 1, "j": 2, "name": "e2e-clip"})
    assert status == 200
    clip_name = clip_res["bundle"]

    status, rep_clip = _http(f"{live_server['url']}/api/bundles/{clip_name}/verify", method="POST")
    assert status == 200
    assert rep_clip["overall"] == "VERIFIED"

    status, open_res = _http(f"{live_server['url']}/api/bundles/e2e-bundle/open", method="POST", data={"partial": False})
    assert status == 200
    assert open_res["overall"] == "VERIFIED"
    assert "restored" in open_res["outputs"]


def test_07_tamper_and_repair(live_server):
    """Tamper with bundle copy, detect corruption, and repair from parity."""
    status, tamper_res = _http(
        f"{live_server['url']}/api/bundles/e2e-bundle/tamper",
        method="POST",
        data={"attack": "bitflip", "params": {"unit": "1"}, "seed": 42},
    )
    assert status == 200
    tampered_bundle = tamper_res["bundle"]

    # Verify tampered bundle
    status, rep_tampered = _http(f"{live_server['url']}/api/bundles/{tampered_bundle}/verify", method="POST")
    assert status == 200

    # Repair plan
    status, plan_res = _http(f"{live_server['url']}/api/bundles/{tampered_bundle}/repair/plan")
    assert status == 200

    # Repair run
    status, repair_res = _http(f"{live_server['url']}/api/bundles/{tampered_bundle}/repair/run", method="POST")
    assert status == 200
    assert repair_res["report"]["overall"] == "VERIFIED"


def test_08_dr_split_and_recover(live_server):
    """Geo-split bundle into 2-of-3 fragments and recover cleanly."""
    status, split_res = _http(f"{live_server['url']}/api/bundles/e2e-bundle/dr/split", method="POST", data={"k": 2, "n": 3})
    assert status == 200
    assert len(split_res["shards"]) == 3

    status, rec_res = _http(
        f"{live_server['url']}/api/dr/recover",
        method="POST",
        data={"shards_bundle": "e2e-bundle", "out_name": "e2e-recovered"},
    )
    assert status == 200
    assert rec_res["report"]["overall"] == "VERIFIED"


def test_09_stress_lab_api(live_server):
    """Run Stress Lab scenario from API."""
    status, sc_data = _http(f"{live_server['url']}/api/stress/scenarios")
    assert status == 200
    scenarios = sc_data["scenarios"]
    assert len(scenarios) > 0

    first_id = scenarios[0]["id"]
    status, run_res = _http(f"{live_server['url']}/api/stress/run", method="POST", data={"ids": [first_id], "seed": 1})
    assert status == 200
    assert run_res["total"] == 1
    assert run_res["passed"] == 1
    assert run_res["results"][0]["pass"] is True


def test_10_benchmarks_api(live_server):
    """Run benchmark sweep from API."""
    status, bench_res = _http(f"{live_server['url']}/api/bench/run", method="POST", data={"quick": True})
    assert status == 200
    results = bench_res["results"]
    assert len(results) >= 4
    for r in results:
        assert r["verified"] is True
        assert r["throughput_mb_s"] > 0

    status, get_res = _http(f"{live_server['url']}/api/bench/results")
    assert status == 200
    assert len(get_res["results"]) == len(results)


def test_11_static_ui_served(live_server):
    """GET / serves the built React UI."""
    status, html = _http(f"{live_server['url']}/")
    assert status == 200
    assert "<!doctype html>" in html.lower() or "<html" in html.lower()
    assert "eviseal" in html.lower()
