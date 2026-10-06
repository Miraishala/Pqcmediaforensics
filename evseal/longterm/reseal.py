"""Re-sealing (SPEC §3.4, RFC 4998 evidence-record idea): sign and timestamp the whole current
manifest — including every old signature, timestamp and earlier reseal — with current
algorithms. Run on schedule or when an algorithm is deprecated.

# ponytail: the verifier checks every reseal but its algorithm policy still applies to the
# original signatures. Upgrade path: accept a deprecated original algorithm when a valid
# reseal under an allowed algorithm is timestamped before the deprecation date.
"""

from __future__ import annotations

import time
from pathlib import Path

from evseal.core.manifest import Bundle, manifest_hash, reseal_msg, write_manifest
from evseal.longterm.keys import KeyPair
from evseal.longterm.timestamps import LocalTSA, stamp


def reseal(bundle_dir: Path, signer: KeyPair, tsa: LocalTSA | None = None, hash_alg: str | None = None) -> dict:
    bdir = Path(bundle_dir)
    m, src = Bundle(bdir).load_manifest()
    if m is None or src == "journal.jsonl":
        raise ValueError("reseal needs a finished bundle with a manifest")
    hash_alg = hash_alg or m["profile"]["hash"]["chain"]
    rec = {"type": "reseal", "time": round(time.time(), 3), "alg": signer.alg, "root_fp": signer.fp, "hash_alg": hash_alg}
    mh = manifest_hash(m, hash_alg)
    rec["manifest_hash"] = mh.hex()
    msg = reseal_msg(mh, rec)
    rec["sig"] = signer.sign(msg).hex()
    rec["tst"] = stamp(m["profile"], msg, tsa)
    m.setdefault("reseals", []).append(rec)
    write_manifest(bdir, m)
    return rec
