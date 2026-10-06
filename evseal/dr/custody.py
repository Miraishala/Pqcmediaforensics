"""Custody log (SPEC §3.3 item 5): every copy, repair or transfer appends a signed, chained
record to the bundle's custody.log. Hashes only; never content, never private keys.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from evseal.core import crypto
from evseal.core.manifest import jcs
from evseal.longterm.keys import KeyPair, Trust

GENESIS = "0" * 64


def _h(rec: dict) -> str:
    return crypto.hashlib.new(crypto.FINGERPRINT_HASH, jcs({k: v for k, v in rec.items() if k not in ("h", "sig")})).hexdigest()


def entries(bundle_dir: Path) -> list[dict]:
    p = Path(bundle_dir) / "custody.log"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


def append(bundle_dir: Path, actor: KeyPair, action: str, detail: dict) -> dict:
    prev = entries(bundle_dir)
    rec = {"seq": len(prev), "time": round(time.time(), 3), "action": action, "detail": detail,
           "actor_alg": actor.alg, "actor_fp": actor.fp, "prev": prev[-1]["h"] if prev else GENESIS}
    rec["h"] = _h(rec)
    rec["sig"] = actor.sign(rec["h"].encode()).hex()
    with open(Path(bundle_dir) / "custody.log", "a") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    return rec


def check(records: list[dict], trust: Trust) -> list[str]:
    """Return problems (empty = chain intact and every record signed by a trusted key)."""
    problems, prev = [], GENESIS
    for r in records:
        if r.get("prev") != prev or r.get("h") != _h(r):
            problems.append(f"custody record {r.get('seq')} breaks the chain")
        key = trust.roots.get(r.get("actor_fp", ""))
        if key is None or not crypto.verify(key["alg"], bytes.fromhex(key["pk"]), r["h"].encode(), bytes.fromhex(r.get("sig", ""))):
            problems.append(f"custody record {r.get('seq')} not signed by a trusted key")
        prev = r.get("h")
    return problems
