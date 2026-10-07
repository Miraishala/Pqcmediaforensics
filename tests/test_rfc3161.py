"""RFC 3161: real CMS verification via openssl, tamper detection, and the offline queue."""
from __future__ import annotations

import datetime
import http.server
import random
import shutil
import subprocess
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from evseal.core import profile as prof
from evseal.core.hashing import dual_hash
from evseal.core.seal import seal
from evseal.core.unit import SourceUnits, Unit
from evseal.core.verify import verify
from evseal.longterm.timestamps import flush_queue
from evseal.workspace import Workspace

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not available")

FAST = {"checkpoint": {"alg": "ML-DSA-44"}, "ec": {"k": 2, "m": 1, "interleave": 1}}


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, key, signer, *, ca=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer)).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    return b.sign(signer, hashes.SHA256())


@pytest.fixture(scope="module")
def tsa_env(tmp_path_factory):
    d = tmp_path_factory.mktemp("tsa")
    ca_key, tsa_key = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
    ca = _cert("test-ca", "test-ca", ca_key, ca_key, ca=True)
    tsa = _cert("test-tsa", "test-ca", tsa_key, ca_key)
    pem = serialization.Encoding.PEM
    (d / "ca.crt").write_bytes(ca.public_bytes(pem))
    (d / "tsa.crt").write_bytes(tsa.public_bytes(pem))
    (d / "tsa.key").write_bytes(tsa_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (d / "serial").write_text("01\n")
    (d / "ts.cnf").write_text(f"""[tsa]
default_tsa = t
[t]
serial = {d}/serial
crypto_device = builtin
signer_cert = {d}/tsa.crt
certs = {d}/ca.crt
signer_key = {d}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4
other_policies = 1.2.3.4
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_alg = sha256
""")

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            q = d / "q.tsq"
            q.write_bytes(self.rfile.read(int(self.headers["Content-Length"])))
            subprocess.run(["openssl", "ts", "-reply", "-queryfile", str(q), "-config", str(d / "ts.cnf"), "-out", str(d / "r.tsr")],
                           check=True, capture_output=True)
            body = (d / "r.tsr").read_bytes()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield {"url": f"http://127.0.0.1:{srv.server_port}", "ca": d / "ca.crt"}
    srv.shutdown()


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    ws = Workspace(tmp_path_factory.mktemp("rfc") / "ws")
    ws.keygen("r")
    return ws


def _seal(lab, out, urls, tsa=None):
    rng = random.Random(5)
    p = prof._merge(lab.profile(None), {**FAST, "timestamps": {"tsa_urls": urls}})
    su = SourceUnits("video", [Unit(data=rng.randbytes(300), t=float(i), dur=1.0, offset=i * 300) for i in range(3)], {})
    seal(su, p, lab.root("r"), out, file_hash=dual_hash(su.reconstruct(), p["hash"]["content"]), tsa=tsa, anchor_log=lab.anchor_log())
    return out


def test_real_tsa_token_verifies_with_ca(lab, tsa_env, tmp_path):
    b = _seal(lab, tmp_path / "b", [tsa_env["url"]])
    tr = lab.trust()
    tr.tsa_ca_file = tsa_env["ca"]
    assert verify(b, tr).overall == "VERIFIED"


def test_real_tsa_token_without_ca_is_not_verified(lab, tsa_env, tmp_path):
    b = _seal(lab, tmp_path / "b", [tsa_env["url"]])
    rep = verify(b, lab.trust())
    assert rep.overall == "NOT_VERIFIED" and any("CA bundle" in r for r in rep.reasons)


def test_wrong_ca_rejects_token(lab, tsa_env, tmp_path):
    other = tmp_path / "other-ca.pem"
    key = rsa.generate_private_key(65537, 2048)
    other.write_bytes(_cert("evil-ca", "evil-ca", key, key, ca=True).public_bytes(serialization.Encoding.PEM))
    b = _seal(lab, tmp_path / "b", [tsa_env["url"]])
    tr = lab.trust()
    tr.tsa_ca_file = other
    assert verify(b, tr).overall == "NOT_VERIFIED"


def test_unreachable_tsa_is_queued_then_flushed(lab, tsa_env, tmp_path):
    b = _seal(lab, tmp_path / "b", ["http://127.0.0.1:9"])  # nothing listens: seal must still succeed
    tr = lab.trust()
    tr.tsa_ca_file = tsa_env["ca"]
    rep = verify(b, tr)
    assert rep.overall == "NOT_VERIFIED" and any("queued" in r for r in rep.reasons)
    import json

    m = json.loads((b / "manifest.json").read_text())
    for r in m["records"]:
        for t in r.get("tst") or []:
            t["url"] = tsa_env["url"]  # the TSA is reachable now
    (b / "manifest.json").write_text(json.dumps(m))
    (b / "manifest.copy.json").write_text(json.dumps(m))
    shutil.rmtree(b / "manifest_rs", ignore_errors=True)
    assert flush_queue(b) >= 1
    rep = verify(b, tr)
    assert rep.overall == "VERIFIED"
    assert any("offline queue" in c["detail"] for c in rep.checks)


def test_hybrid_timestamp_rfc3161_plus_pq_witness_verifies(lab, tsa_env, tmp_path):
    b = _seal(lab, tmp_path / "b", [tsa_env["url"]], tsa=lab.tsa())
    tr = lab.trust()
    tr.tsa_ca_file = tsa_env["ca"]
    rep = verify(b, tr)
    assert rep.overall == "VERIFIED"
    assert {"RFC 3161 token verified (classical, non-PQ TSA)", "local TSA"} <= {c["detail"] for c in rep.checks}
