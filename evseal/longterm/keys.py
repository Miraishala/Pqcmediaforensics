"""Key hierarchy (SPEC §2 step 7): a long-term root (collector/device) key certifies an
ephemeral signing key per `keys.rotation_s` period and a checkpoint key; ephemeral private
keys exist only in memory and are wiped at period end (forward security).

# ponytail: dev private keys are file-based JSON (SPEC §9.2) and "secure delete" is a
# best-effort bytearray wipe — the pure-Python backends take immutable bytes, so copies may
# linger in the heap. Upgrade path: HSM/TPM-held root, liboqs keys in mlock'd buffers.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from evseal.core import crypto
from evseal.core.manifest import cert_msg


@dataclass
class KeyPair:
    alg: str
    pk: bytes
    sk: bytearray
    name: str = ""
    signer: list[str] | None = None  # external signer command (HSM / TPM / gateway): the private key never enters this process

    @property
    def fp(self) -> str:
        return crypto.fingerprint(self.pk)

    def sign(self, msg: bytes) -> bytes:
        if self.signer:
            # Protocol: message on stdin, algorithm in EVSEAL_SIGN_ALG, raw signature on stdout, non-zero exit = refusal.
            r = subprocess.run(self.signer, input=msg, capture_output=True, env={**os.environ, "EVSEAL_SIGN_ALG": self.alg})
            if r.returncode != 0 or not r.stdout:
                raise RuntimeError(f"external signer failed ({r.returncode}): {r.stderr.decode(errors='replace')[:200]}")
            if not crypto.verify(self.alg, self.pk, msg, r.stdout):  # a bad signer must fail now, not at verify time
                raise RuntimeError("external signer returned a signature that does not verify under the registered public key")
            return r.stdout
        if not self.sk:
            raise RuntimeError("key already wiped (forward security)")
        return crypto.sign(self.alg, bytes(self.sk), msg)

    def wipe(self) -> None:
        for j in range(len(self.sk)):
            self.sk[j] = 0
        self.sk = bytearray()

    def public(self) -> dict:
        return {"alg": self.alg, "pk": self.pk.hex(), "fp": self.fp, "name": self.name}


def generate(alg: str, name: str = "") -> KeyPair:
    pk, sk = crypto.keygen(alg)
    return KeyPair(alg, pk, bytearray(sk), name)


def save(kp: KeyPair, out_dir: Path, passphrase: str | None = None) -> tuple[Path, Path]:
    """Write <name>.pub.json and <name>.key.json (file-based private key; encrypted at rest when a passphrase is given)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pub = out_dir / f"{kp.name}.pub.json"
    key = out_dir / f"{kp.name}.key.json"
    pub.write_text(json.dumps(kp.public(), indent=1))
    if passphrase:
        body = {**kp.public(), "enc": crypto.wrap_secret(passphrase, bytes(kp.sk), kp.pk), "warning": "passphrase-protected file-based private key"}
    else:
        body = {**kp.public(), "sk": bytes(kp.sk).hex(), "warning": "DEV-ONLY file-based private key"}
    key.write_text(json.dumps(body))
    return pub, key


def register_external(name: str, pub: dict, cmd: list[str], out_dir: Path) -> tuple[Path, Path]:
    """Register a key whose private half lives in an external signer. Writes <name>.pub.json and a
    <name>.key.json holding only the signer command (never any private key material)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pub_rec = {"alg": pub["alg"], "pk": pub["pk"], "fp": crypto.fingerprint(bytes.fromhex(pub["pk"])), "name": name}
    p, k = out_dir / f"{name}.pub.json", out_dir / f"{name}.key.json"
    p.write_text(json.dumps(pub_rec, indent=1))
    k.write_text(json.dumps({**pub_rec, "signer": {"cmd": cmd}, "warning": "private key held by an external signer"}))
    return p, k


def load_private(path: Path, passphrase: str | None = None) -> KeyPair:
    d = json.loads(Path(path).read_text())
    if "signer" in d:
        return KeyPair(d["alg"], bytes.fromhex(d["pk"]), bytearray(), d.get("name", ""), signer=list(d["signer"]["cmd"]))
    if "enc" in d:
        if not passphrase:
            raise ValueError(f"{Path(path).name} is passphrase-protected: set EVSEAL_KEY_PASSPHRASE")
        sk = bytearray(crypto.unwrap_secret(passphrase, d["enc"], bytes.fromhex(d["pk"])))
    else:
        sk = bytearray.fromhex(d["sk"])
    return KeyPair(d["alg"], bytes.fromhex(d["pk"]), sk, d.get("name", ""))


def load_public(path: Path) -> dict:
    d = json.loads(Path(path).read_text())
    return {"alg": d["alg"], "pk": d["pk"], "fp": crypto.fingerprint(bytes.fromhex(d["pk"])), "name": d.get("name", "")}


def issue_cert(root: KeyPair, *, cert_id: str, role: str, subject: KeyPair, rid: bytes, profile_hash: bytes,
               period: int, t_from: float, t_to: float, not_before: float, not_after: float) -> dict:
    cert = {
        "type": "cert", "id": cert_id, "role": role, "alg": subject.alg, "pk": subject.pk.hex(),
        "rid": rid.hex(), "profile_hash": profile_hash.hex(), "period": period,
        "t_from": t_from, "t_to": t_to, "not_before": round(not_before, 3), "not_after": round(not_after, 3),
        "root_alg": root.alg, "root_fp": root.fp,
    }
    cert["sig"] = root.sign(cert_msg(cert)).hex()
    return cert


@dataclass
class Trust:
    """What the verifier trusts: root keys, timestamp authorities, algorithm policy, logs."""

    roots: dict[str, dict] = field(default_factory=dict)  # fp -> public record
    tsas: dict[str, dict] = field(default_factory=dict)
    actors: dict[str, dict] = field(default_factory=dict)  # fp -> public record of users who may sign custody records (never roots)
    require_operator: bool = False  # policy: a bundle must carry a valid operator `seal` attestation to be VERIFIED
    allow_classical: bool = False  # Ed25519-only is NON-PQ: rejected unless explicitly allowed
    anchor_log: Path | None = None  # external anchor log to cross-check (SPEC §3.2 last line of defense)
    revocations: dict[str, float] = field(default_factory=dict)  # key fp -> revoked-at unix time (SPEC §10)
    tsa_ca_file: Path | None = None  # PEM bundle of trusted RFC 3161 TSA CA certificates; None = such tokens cannot verify
    slack_s: float = 300.0  # allowed skew between a timestamp token and its signing key's validity window

    @classmethod
    def from_paths(cls, roots=(), tsas=(), **kw) -> "Trust":
        def _load(paths):
            out = {}
            for p in paths:
                p = Path(p)
                for f in (sorted(p.glob("*.pub.json")) if p.is_dir() else [p]):
                    rec = load_public(f)
                    out[rec["fp"]] = rec
            return out

        return cls(roots=_load(roots), tsas=_load(tsas), **kw)


def check_cert(cert: dict, root_pub: dict, rid_hex: str, ph_hex: str, revocations: dict[str, float]) -> str | None:
    """Return None if valid, else a reason string."""
    try:
        if cert.get("root_fp") != root_pub["fp"] or cert.get("root_alg") != root_pub["alg"]:
            return "certificate not issued by the trusted root"
        if cert.get("rid") != rid_hex:
            return "certificate bound to another recording"
        if cert.get("profile_hash") != ph_hex:
            return "certificate bound to another profile (downgrade?)"
        if not crypto.verify(root_pub["alg"], bytes.fromhex(root_pub["pk"]), cert_msg(cert), bytes.fromhex(cert["sig"])):
            return "certificate signature invalid"
        for fp in (root_pub["fp"], crypto.fingerprint(bytes.fromhex(cert["pk"]))):
            if fp in revocations and revocations[fp] <= cert["not_before"]:
                return f"key {fp[:12]} revoked before this certificate was issued"
    except (KeyError, ValueError, TypeError):
        return "malformed certificate"
    return None


def now() -> float:
    return time.time()
