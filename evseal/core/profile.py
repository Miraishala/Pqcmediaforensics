"""Profiles (SPEC §4): every tunable, presets, validation, TOML I/O, live estimates.

The profile used for sealing is embedded in the manifest and bound into C_0 via profile_hash,
so verification always uses the sealed settings.
"""

from __future__ import annotations

import copy
import json
import tomllib
from pathlib import Path

from evseal.core import crypto

DEFAULTS: dict = {
    "segment": {"duration_s": 1.0, "mode": "byte-range", "assumed_fps": 0.0, "max_unit_mb": 64},
    "audio": {"segment_duration_s": 1.0},
    "image": {"set_order": "capture_time", "tile_px": 64, "perceptual_hash": "thumb8", "likely_edited_threshold": 10.0, "aead_chunk_kb": 64},
    "unit": {"container_map": {}},
    "hash": {"content": ["sha256", "sha3-256"], "chain": "sha3-256"},
    "sign": {"alg": "ML-DSA-44", "block_segments": 1},
    "keys": {"root_alg": "ML-DSA-87", "rotation_s": 3600},
    "checkpoint": {"interval_s": 3600, "alg": "SLH-DSA-SHA2-128s"},
    "timestamps": {"tsa_urls": []},
    "anchors": {"backend": "local-log"},
    "aead": {"alg": "AES-256-GCM", "chunk": "segment"},
    "kdf": {"alg": "HKDF-SHA256"},
    "ec": {"k": 10, "m": 2, "interleave": 60},
    "outer": {"enabled": False, "kem": "ML-KEM-768"},
    "dr": {"k_sites": 2, "n_sites": 3},
    "parallel": {"workers": "auto"},
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) and k != "container_map" else v
    return out


PRESETS: dict[str, dict] = {
    "court-grade": DEFAULTS,
    "low-storage": _merge(DEFAULTS, {"sign": {"block_segments": 60}, "ec": {"k": 20, "m": 2}}),
    "max-security": _merge(
        DEFAULTS, {"sign": {"alg": "ML-DSA-87"}, "hash": {"content": ["sha256", "sha3-512"]}, "ec": {"k": 10, "m": 4}}
    ),
}

_SIG = crypto.SIG_ALGS
_PQ_SIG = [a for a in _SIG if crypto.security_class(a) != "classical"]
# (group, key) -> ("num", lo, hi) | ("int", lo, hi) | ("enum", options) | ("list", options) | ("bool",) | ...
# Knobs added after bundles already existed: a verifier must still accept bundles sealed without them
# (they only steer sealing). Never remove an entry; add new seal-only knobs here.
OPTIONAL: set[tuple[str, str]] = {("segment", "max_unit_mb")}
SCHEMA: dict[tuple[str, str], tuple] = {
    ("segment", "duration_s"): ("num", 0.5, 10),
    ("segment", "mode"): ("enum", ["byte-range", "remux"]),
    ("segment", "max_unit_mb"): ("num", 0, 4096),  # 0 = off; splits oversized (VFR / long-GOP) units at packet boundaries
    ("segment", "assumed_fps"): ("num", 0, 240),  # 0 = auto; raw elementary streams carry no timing
    ("audio", "segment_duration_s"): ("num", 0.5, 10),
    ("image", "set_order"): ("enum", ["capture_time", "filename"]),
    ("image", "tile_px"): ("int", 16, 512),
    ("image", "perceptual_hash"): ("enum", ["thumb8", "off"]),
    ("image", "likely_edited_threshold"): ("num", 1, 128),  # mean |Δgray| of a tile thumbnail
    ("image", "aead_chunk_kb"): ("int", 4, 4096),
    ("unit", "container_map"): ("map", ["video", "audio", "image"]),
    ("hash", "content"): ("list", list(crypto.CONTENT_HASHES)),
    ("hash", "chain"): ("enum", list(crypto.CHAIN_HASHES)),
    ("sign", "alg"): ("enum", _SIG),
    ("sign", "block_segments"): ("int", 1, 3600),
    ("keys", "root_alg"): ("enum", _PQ_SIG),
    ("keys", "rotation_s"): ("int", 60, 86400),
    ("checkpoint", "interval_s"): ("int", 60, 86400),
    ("checkpoint", "alg"): ("enum", _SIG),
    ("timestamps", "tsa_urls"): ("urls",),
    ("anchors", "backend"): ("enum", ["local-log", "off"]),
    ("aead", "alg"): ("enum", list(crypto.AEADS)),
    ("aead", "chunk"): ("enum", ["segment", "frame"]),
    ("kdf", "alg"): ("enum", list(crypto.KDFS)),
    ("ec", "k"): ("int", 2, 64),
    ("ec", "m"): ("int", 0, 16),
    ("ec", "interleave"): ("int", 1, 3600),
    ("outer", "enabled"): ("bool",),
    ("outer", "kem"): ("enum", crypto.KEM_ALGS),
    ("dr", "k_sites"): ("int", 1, 16),
    ("dr", "n_sites"): ("int", 1, 16),
    ("parallel", "workers"): ("workers",),
}


class ProfileError(ValueError):
    pass


def validate(profile: dict) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Errors block sealing; warnings are shown in the UI."""
    errors, warnings = [], []
    for (g, k), rule in SCHEMA.items():
        if g not in profile or k not in profile[g]:
            if (g, k) not in OPTIONAL:
                errors.append(f"{g}.{k}: missing")
            continue
        v, kind = profile[g][k], rule[0]
        name = f"{g}.{k}"
        if kind in ("num", "int"):
            ok = isinstance(v, (int, float)) and not isinstance(v, bool) and (kind == "num" or float(v).is_integer())
            if not ok or not (rule[1] <= v <= rule[2]):
                errors.append(f"{name}: {v!r} outside {rule[1]}–{rule[2]}")
        elif kind == "enum" and v not in rule[1]:
            errors.append(f"{name}: {v!r} not one of {rule[1]}")
        elif kind == "list" and (not isinstance(v, list) or not v or any(x not in rule[1] for x in v)):
            errors.append(f"{name}: {v!r} must be a non-empty list of {rule[1]}")
        elif kind == "bool" and not isinstance(v, bool):
            errors.append(f"{name}: must be true/false")
        elif kind == "map" and (not isinstance(v, dict) or any(x not in rule[1] for x in v.values())):
            errors.append(f"{name}: must map extension -> one of {rule[1]}")
        elif kind == "urls" and (not isinstance(v, list) or any(not str(u).startswith(("http://", "https://")) for u in v)):
            errors.append(f"{name}: must be a list of http(s) URLs")
        elif kind == "workers" and not (v == "auto" or (isinstance(v, int) and 1 <= v <= 256)):
            errors.append(f"{name}: 'auto' or 1–256")
    if not errors:
        fams = {crypto.HASH_FAMILY[a] for a in profile["hash"]["content"]}
        if len(fams) < 2:
            warnings.append("hash.content uses only one hash family — dual hashing is meant to survive one family breaking")
        if profile["dr"]["k_sites"] > profile["dr"]["n_sites"]:
            errors.append("dr.k_sites must be ≤ dr.n_sites")
        for key in ("sign", "checkpoint"):
            alg = profile[key]["alg"]
            if crypto.security_class(alg) == "classical":
                warnings.append(f"{key}.alg {alg} is NON-PQ (baseline only) — the verifier rejects it by default")
            _, kind = crypto.get_signature_backend(alg)
            if kind is None:
                errors.append(f"{key}.alg {alg} has no working backend here (see `evseal doctor`)")
            elif kind == "pure-python":
                warnings.append(f"{key}.alg {alg}: {crypto.DEV_ONLY_NOTE}")
        if profile["ec"]["m"] == 0:
            warnings.append("ec.m = 0: no parity — any corruption is unrecoverable")
    return errors, warnings


def check(profile: dict) -> dict:
    errors, _ = validate(profile)
    if errors:
        raise ProfileError("; ".join(errors))
    return profile


def canonical_json(obj) -> bytes:
    """RFC 8785 (JCS) canonical bytes."""
    import rfc8785

    return rfc8785.dumps(obj)


def profile_hash(profile: dict) -> bytes:
    return crypto.hash_bytes(profile["hash"]["chain"], canonical_json(profile))


def load(path: Path) -> dict:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return _merge(DEFAULTS, data)


def resolve(spec: str | dict | None) -> dict:
    """A preset name, a TOML path, a dict (merged over defaults), or None (defaults)."""
    if spec is None:
        return copy.deepcopy(DEFAULTS)
    if isinstance(spec, dict):
        return _merge(DEFAULTS, spec)
    if spec in PRESETS:
        return copy.deepcopy(PRESETS[spec])
    return load(Path(spec))


def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{json.dumps(k)} = {_toml_value(x)}" for k, x in v.items()) + "}"
    raise TypeError(type(v))


def dumps(profile: dict) -> str:
    """Minimal TOML writer: one [table] per group, scalar/list/inline-table values (all a profile has)."""
    out = []
    for group, kv in profile.items():
        out.append(f"[{group}]")
        out.extend(f"{k} = {_toml_value(v)}" for k, v in kv.items())
        out.append("")
    return "\n".join(out)


def diff(a: dict, b: dict) -> list[dict]:
    return [
        {"key": f"{g}.{k}", "a": a.get(g, {}).get(k), "b": b.get(g, {}).get(k)}
        for g in sorted(set(a) | set(b))
        for k in sorted(set(a.get(g, {})) | set(b.get(g, {})))
        if a.get(g, {}).get(k) != b.get(g, {}).get(k)
    ]


# Approximate signature sizes (bytes) for estimates only — real sizes come from the backend.
_SIG_BYTES = {"ML-DSA-44": 2420, "ML-DSA-65": 3309, "ML-DSA-87": 4627, "Ed25519": 64}
# ponytail: per-primitive throughput constants are the SPEC §4 design-session figures, not
# measurements; `evseal bench` replaces them once run on WSL2/liboqs (never on the fallback).
_SIGN_PER_S = {"ML-DSA-44": 25000, "ML-DSA-65": 15000, "ML-DSA-87": 10000}


def _sig_bytes(alg: str) -> int:
    if alg.startswith("SLH-DSA"):
        bits, var = int(alg.split("-")[3][:3]), alg[-1]
        return {(128, "s"): 7856, (128, "f"): 17088, (192, "s"): 16224, (192, "f"): 35664, (256, "s"): 29792, (256, "f"): 49856}[(bits, var)]
    if alg.startswith("Ed25519+"):
        return 64 + _SIG_BYTES[alg.removeprefix("Ed25519+")]
    return _SIG_BYTES[alg]


def estimates(profile: dict, bitrate_mbps: float = 2.0, hours: float = 12.0, cores: int = 8) -> dict:
    """Live estimates for the UI side panel (SPEC §4), computed from formulas."""
    seg = profile["segment"]["duration_s"]
    n_units = hours * 3600 / seg
    blk = profile["sign"]["block_segments"]
    hash_len = sum(crypto.hashlib.new(crypto.CONTENT_HASHES[a]).digest_size for a in profile["hash"]["content"])
    chain_len = crypto.hashlib.new(crypto.CHAIN_HASHES[profile["hash"]["chain"]]).digest_size
    sig = _sig_bytes(profile["sign"]["alg"])
    per_block = sig + blk * (hash_len + chain_len) * 2 + 120  # hex-encoded hashes + JSON framing
    signed_bytes_s = (per_block / blk + 16 * 1) / seg  # + AEAD tag per unit
    video_bytes_s = bitrate_mbps * 1e6 / 8
    k, m = profile["ec"]["k"], profile["ec"]["m"]
    signing_pct = 100 * signed_bytes_s / video_bytes_s
    parity_pct = 100 * m / k
    sign_rate = _SIGN_PER_S.get(profile["sign"]["alg"].removeprefix("Ed25519+"), 2000)
    workers = cores if profile["parallel"]["workers"] == "auto" else min(cores, profile["parallel"]["workers"])
    total_bytes = video_bytes_s * hours * 3600
    hash_s = total_bytes / (400e6 * workers)  # ~400 MB/s/core dual hash
    aead_s = total_bytes / (1.5e9 * workers)
    sign_s = (n_units / blk) / (sign_rate * workers)
    ckpt_s = hours * 3600 / profile["checkpoint"]["interval_s"] * (2.0 if profile["checkpoint"]["alg"].endswith("s") else 0.1)
    return {
        "storage_overhead_pct": round(signing_pct + parity_pct, 3),
        "signing_overhead_pct": round(signing_pct, 3),
        "parity_overhead_pct": round(parity_pct, 2),
        "signatures_per_day": round(86400 / seg / blk),
        "checkpoints_per_day": round(86400 / profile["checkpoint"]["interval_s"]),
        "survives": f"survives {m} bad segments per stripe of {k}, bursts up to {profile['ec']['interleave']}",
        "seal_time_s": round(hash_s + aead_s + sign_s + ckpt_s, 1),
        "inputs": {"bitrate_mbps": bitrate_mbps, "hours": hours, "cores": cores},
    }
