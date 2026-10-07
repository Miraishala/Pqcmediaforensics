"""Bundle format: manifest (RFC 8785 JCS canonical JSON), journal, signed-message layouts,
and a reader over a bundle directory or a single `.evseal` zip (stored mode).

Bundle layout (SPEC §5):
  manifest.json          compiled manifest (written at end of seal)
  manifest.copy.json     embedded second copy (SPEC §3.2); last member of a .evseal zip
  manifest_rs/NN.shard   RS-protected copy of the manifest (SPEC §3.2), when ec.m > 0
  journal.jsonl          append-only record journal, fsync'd per block (present only while/if
                         a seal never finished — a crashed seal verifies up to its last record)
  segments/NNNNNN.seg    sealed unit i: AEAD chunks back to back
  parity/SSSSSS_P.par    RS parity shard P of stripe S
  certs/root.pub.json    the collector's root public key (never a private key)
  anchors/anchors.jsonl  copy of this bundle's anchor-log entries (hashes only)
  custody.log            signed, chained custody records (SPEC §3.3)

Signed messages use the SPEC §2 layouts exactly, integers as 8-byte big-endian:
  block       rid || i_start || i_end || R_i... || C_i...                   (format v1)
              ... || b"evseal-timing" || JCS([[t_i, dur_i], ...])           (format v2: unit times are signed, D6)
  checkpoint  rid || i || C_i || count
  final       rid || n || C_n || H(original input file)
Records the SPEC doesn't lay out get a domain tag: b"evseal-gap", b"evseal-cert", b"evseal-reseal".
"""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

from evseal.core.profile import canonical_json

FORMAT = "evseal-bundle-v2"
FORMAT_V1 = "evseal-bundle-v1"  # still verifiable: block signatures without signed unit times
READABLE = (FORMAT, FORMAT_V1)
MANIFEST = "manifest.json"
MANIFEST_COPY = "manifest.copy.json"
JOURNAL = "journal.jsonl"


def jcs(obj) -> bytes:
    return canonical_json(obj)


def _i(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


def block_msg(rid: bytes, i_start: int, i_end: int, rs: list[bytes], cs: list[bytes], ts: list | None = None) -> bytes:
    """`ts` = [[t, dur], ...] per unit for format v2; None gives the v1 layout."""
    msg = rid + _i(i_start) + _i(i_end) + b"".join(rs) + b"".join(cs)
    return msg if ts is None else msg + b"evseal-timing" + jcs(ts)


def checkpoint_msg(rid: bytes, i: int, c_i: bytes, count: int) -> bytes:
    return rid + _i(i) + c_i + _i(count)


def final_msg(rid: bytes, n: int, c_n: bytes, file_hash: bytes) -> bytes:
    return rid + _i(n) + c_n + file_hash


def gap_msg(rid: bytes, i_start: int, i_end: int, reason: str) -> bytes:
    return b"evseal-gap" + rid + _i(i_start) + _i(i_end) + reason.encode()


def body(record: dict, drop=("sig", "tst")) -> dict:
    return {k: v for k, v in record.items() if k not in drop}


def cert_msg(cert: dict) -> bytes:
    return b"evseal-cert" + jcs(body(cert))


def reseal_msg(manifest_hash: bytes, record: dict) -> bytes:
    return b"evseal-reseal" + manifest_hash + jcs(body(record))


def manifest_hash(manifest: dict, alg: str, upto_reseal: int | None = None) -> bytes:
    """Hash of the manifest as an evidence record covers it: everything, with reseals[:k]."""
    from evseal.core.crypto import hash_bytes

    m = {k: v for k, v in manifest.items() if k != "reseals"}
    m["reseals"] = manifest.get("reseals", [])[: upto_reseal if upto_reseal is not None else None]
    return hash_bytes(alg, jcs(m))


def compile_manifest(genesis: dict, lines: list[dict]) -> dict:
    m = dict(genesis)
    m["units"] = [ln["unit"] for ln in lines if ln.get("type") == "unit"]
    m["records"] = [ln for ln in lines if ln.get("type") not in ("unit", "genesis")]
    m.setdefault("reseals", [])
    return m


# ---- writing ----


class Journal:
    """Append-only, fsync per batch (SPEC §7C kill -9 durability)."""

    def __init__(self, path: Path, genesis: dict):
        self.path = Path(path)
        self.f = open(self.path, "ab")
        self.append([{"type": "genesis", **genesis}])

    def append(self, lines: list[dict]) -> None:
        self.f.write(b"".join(json.dumps(ln, separators=(",", ":")).encode() + b"\n" for ln in lines))
        self.f.flush()
        os.fsync(self.f.fileno())

    def close(self) -> None:
        self.f.close()


def write_atomic(path: Path, data: bytes) -> None:
    tmp = Path(str(path) + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def write_manifest(bundle_dir: Path, manifest: dict) -> None:
    from evseal.resilience.ec import write_manifest_rs

    data = jcs(manifest)
    write_atomic(Path(bundle_dir) / MANIFEST, data)
    write_atomic(Path(bundle_dir) / MANIFEST_COPY, data)
    ec = manifest["profile"]["ec"]
    if ec["m"] > 0:
        write_manifest_rs(Path(bundle_dir), data, ec["k"], ec["m"])


def seg_name(i: int) -> str:
    return f"segments/{i:06d}.seg"


# ---- reading ----


class Bundle:
    """Read-only view over a bundle directory or a .evseal zip. Every read is a trust boundary."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._zip = None
        if self.path.is_file():
            self._zip = zipfile.ZipFile(self.path)
            self._names = set(self._zip.namelist())

    def read(self, name: str) -> bytes | None:
        try:
            if self._zip is not None:
                return self._zip.read(name) if name in self._names else None
            p = self.path / name
            return p.read_bytes() if p.is_file() else None
        except (OSError, zipfile.BadZipFile, KeyError):
            return None

    def list(self, prefix: str) -> list[str]:
        if self._zip is not None:
            return sorted(n for n in self._names if n.startswith(prefix))
        d = self.path / prefix
        return sorted(f"{prefix}{p.name}" for p in d.iterdir() if p.is_file()) if d.is_dir() else []

    @property
    def writable_dir(self) -> Path | None:
        return None if self._zip is not None else self.path

    def load_manifest(self) -> tuple[dict | None, str]:
        """Return (manifest, source). Order: manifest.json, embedded copy, RS copy, journal."""
        from evseal.resilience.ec import read_manifest_rs

        rs_data, rs_hash = read_manifest_rs(self)
        for name in (MANIFEST, MANIFEST_COPY):
            raw = self.read(name)
            if raw is None:
                continue
            if rs_hash is not None and _sha3(raw) != rs_hash:
                continue  # damaged copy — the RS copy knows the true hash
            m = _parse(raw)
            if m is not None:
                return m, name
        if rs_data is not None:
            m = _parse(rs_data)
            if m is not None:
                return m, "manifest_rs"
        raw = self.read(JOURNAL)
        if raw is not None:
            lines = []
            for ln in raw.split(b"\n"):
                try:
                    lines.append(json.loads(ln))
                except ValueError:
                    break  # torn tail write from a crash: everything before it is durable
            if lines and lines[0].get("type") == "genesis":
                genesis = {k: v for k, v in lines[0].items() if k != "type"}
                return compile_manifest(genesis, lines[1:]), JOURNAL
        return None, "none"


def _sha3(b: bytes) -> str:
    import hashlib

    from evseal.core.crypto import FINGERPRINT_HASH

    return hashlib.new(FINGERPRINT_HASH, b).hexdigest()


def _parse(raw: bytes) -> dict | None:
    try:
        m = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    return m if isinstance(m, dict) and m.get("format") in READABLE else None


def pack(bundle_dir: Path, out: Path) -> Path:
    """Directory bundle -> single .evseal zip (stored mode), manifest copy as the last member."""
    bundle_dir, out = Path(bundle_dir), Path(out)
    files = sorted(p for p in bundle_dir.rglob("*") if p.is_file() and p.name != MANIFEST_COPY)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as z:
        for p in files:
            z.write(p, p.relative_to(bundle_dir).as_posix())
        copy = bundle_dir / MANIFEST_COPY
        if copy.exists():
            z.write(copy, MANIFEST_COPY)
    return out


def unpack(src: Path, out_dir: Path) -> Path:
    with zipfile.ZipFile(src) as z:
        for n in z.namelist():
            target = (Path(out_dir) / n).resolve()
            if not str(target).startswith(str(Path(out_dir).resolve())):
                raise ValueError(f"unsafe path in bundle: {n}")  # zip-slip
        z.extractall(out_dir)
    return Path(out_dir)


def hexb(s) -> bytes:
    """Strict hex decode for manifest fields (trust boundary): raises ValueError on junk."""
    if not isinstance(s, str):
        raise ValueError("expected hex string")
    return bytes.fromhex(s)

