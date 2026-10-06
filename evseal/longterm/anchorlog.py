"""Anchor log (SPEC §2 step 5, §3.2): append-only log of checkpoint/final chain values —
hashes only, never content. Also carries key revocation records (SPEC §10).

# ponytail: a local hash-chained JSONL file (each entry commits to the previous entry hash),
# not a Merkle log with inclusion proofs. Upgrade path: a transparency-log backend
# (anchors.backend) with signed tree heads once an external log exists.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from evseal.core import crypto
from evseal.core.manifest import jcs

GENESIS = "0" * 64


def entry_hash(e: dict) -> str:
    return crypto.hashlib.new(crypto.FINGERPRINT_HASH, jcs({k: v for k, v in e.items() if k != "h"})).hexdigest()


class AnchorLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for ln in self.path.read_text().splitlines():
            try:
                out.append(json.loads(ln))
            except ValueError:
                break
        return out

    def append(self, **fields) -> dict:
        prev = self.entries()
        e = {"seq": len(prev), "time": round(time.time(), 3), "prev": prev[-1]["h"] if prev else GENESIS, **fields}
        e["h"] = entry_hash(e)
        with open(self.path, "a") as f:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return e

    def revoke(self, fp: str, reason: str = "") -> dict:
        return self.append(kind="revoke", fp=fp, reason=reason)

    def revocations(self) -> dict[str, float]:
        return {e["fp"]: e["time"] for e in self.entries() if e.get("kind") == "revoke"}


def check_entries(entries: list[dict]) -> str | None:
    """Each entry must hash correctly; consecutive bundle-copied entries must link (a bundle
    holds a subset of the global log, so links are only checked between adjacent seqs)."""
    for a, b in zip(entries, entries[1:]):
        if b["seq"] == a["seq"] + 1 and b["prev"] != a["h"]:
            return f"anchor log link broken at seq {b['seq']}"
    for e in entries:
        if e.get("h") != entry_hash(e):
            return f"anchor entry {e.get('seq')} hash mismatch"
    return None
