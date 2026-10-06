"""Timestamps (SPEC §2 step 5, §4 timestamps.tsa_urls): RFC 3161 client + local test TSA.

- `timestamps.tsa_urls = []` (default, dev): a local test TSA signs (imprint, time) with a
  PQ key kept in the workspace; verifiers trust it explicitly.
- Non-empty: an RFC 3161 TimeStampReq is POSTed to each URL; the token is stored verbatim
  (base64 DER) with its genTime and messageImprint parsed out and checked.

# ponytail: the RFC 3161 token's CMS signature (classical RSA/ECDSA) is NOT verified — no
# stdlib/`cryptography` API for CMS SignedData. Fail closed: such a token is reported
# "unverified" and blocks a VERIFIED verdict. Upgrade path: asn1crypto/`openssl ts -verify`.
# Offline queueing (SPEC §10) is also not implemented: an unreachable TSA fails the seal.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from evseal.core import crypto
from evseal.longterm import keys

SLACK_S = 300  # allowed clock skew between a timestamp and its signing key's validity window


def imprint(msg: bytes) -> bytes:
    return hashlib.new(crypto.TSA_IMPRINT_HASH, msg).digest()


from evseal.core.manifest import jcs


def _local_msg(tok: dict) -> bytes:
    return b"evseal-tst" + jcs({k: tok[k] for k in ("tsa_fp", "time", "imprint")})


class LocalTSA:
    def __init__(self, key_dir: Path, clock=time.time):
        self.key_dir = Path(key_dir)
        self.clock = clock
        key = self.key_dir / "tsa.key.json"
        if key.exists():
            self.kp = keys.load_private(key)
        else:
            self.kp = keys.generate(crypto.LOCAL_TSA_ALG, "tsa")
            keys.save(self.kp, self.key_dir)

    @property
    def pub_path(self) -> Path:
        return self.key_dir / "tsa.pub.json"

    def stamp(self, msg: bytes) -> dict:
        tok = {"kind": "local", "tsa_fp": self.kp.fp, "time": round(self.clock(), 3), "imprint": imprint(msg).hex()}
        tok["sig"] = self.kp.sign(_local_msg(tok)).hex()
        return tok


# ---- minimal DER for RFC 3161 ----


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        while p > 0x7F:
            p >>= 7
            enc.insert(0, 0x80 | (p & 0x7F))
        out += bytes(enc)
    return _der(0x06, out)


def rfc3161_request(digest: bytes, nonce: int) -> bytes:
    alg = _der(0x30, _oid(crypto.TSA_IMPRINT_OID) + b"\x05\x00")
    mi = _der(0x30, alg + _der(0x04, digest))
    nb = nonce.to_bytes((nonce.bit_length() + 8) // 8, "big")
    return _der(0x30, _der(0x02, b"\x01") + mi + _der(0x02, nb) + b"\x01\x01\xff")


def _walk(der: bytes):
    """Yield (tag, content) for every TLV, depth-first (constructed types and explicit tags)."""
    j = 0
    while j + 2 <= len(der):
        tag, ln = der[j], der[j + 1]
        j += 2
        if ln & 0x80:
            nb = ln & 0x7F
            ln = int.from_bytes(der[j : j + nb], "big")
            j += nb
        content = der[j : j + ln]
        j += ln
        yield tag, content
        if tag & 0x20 or tag == 0x04:  # constructed, or OCTET STRING wrapping eContent
            yield from _walk(content)


def rfc3161_parse(token: bytes) -> tuple[bytes | None, float | None]:
    """Return (messageImprint digest, genTime) from a TimeStampResp/TimeStampToken."""
    digest = gen = None
    for tag, content in _walk(token):
        if tag == 0x18 and gen is None:  # GeneralizedTime
            s = content.decode(errors="ignore").rstrip("Z").split(".")[0]
            try:
                gen = datetime.strptime(s, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp()
            except ValueError:
                pass
        if tag == 0x04 and len(content) == 32 and digest is None:
            digest = content
    return digest, gen


def rfc3161_stamp(url: str, msg: bytes) -> dict:
    req = rfc3161_request(imprint(msg), int.from_bytes(os.urandom(8), "big"))
    r = urllib.request.Request(url, data=req, headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(r, timeout=20) as resp:
        der = resp.read()
    digest, gen = rfc3161_parse(der)
    return {"kind": "rfc3161", "url": url, "time": gen, "imprint": imprint(msg).hex(), "der": base64.b64encode(der).decode(),
            "parsed_imprint": digest.hex() if digest else None}


def stamp(profile: dict, msg: bytes, local: LocalTSA | None) -> list[dict]:
    urls = profile["timestamps"]["tsa_urls"]
    if urls:
        return [rfc3161_stamp(u, msg) for u in urls]
    return [local.stamp(msg)] if local is not None else []


def verify_token(tok: dict, msg: bytes, trust: keys.Trust) -> tuple[bool, float | None, str]:
    """Return (ok, time, detail). Fail closed: anything unverifiable is not ok."""
    try:
        if tok.get("imprint") != imprint(msg).hex():
            return False, tok.get("time"), "timestamp imprint does not match the signed record"
        if tok.get("kind") == "local":
            tsa = trust.tsas.get(tok["tsa_fp"])
            if tsa is None:
                return False, tok["time"], "timestamp from an untrusted TSA"
            ok = crypto.verify(tsa["alg"], bytes.fromhex(tsa["pk"]), _local_msg(tok), bytes.fromhex(tok["sig"]))
            return ok, tok["time"], "local TSA" if ok else "timestamp signature invalid"
        if tok.get("kind") == "rfc3161":
            digest, gen = rfc3161_parse(base64.b64decode(tok["der"]))
            if digest is None or digest.hex() != tok["imprint"]:
                return False, gen, "RFC 3161 token imprint mismatch"
            return False, gen, "RFC 3161 token: imprint ok, CMS signature not verified (unsupported)"
    except (KeyError, ValueError, TypeError):
        pass
    return False, None, "malformed timestamp token"
