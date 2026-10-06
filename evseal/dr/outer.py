"""Disaster-Recovery Outer Layer (SPEC §3.3 item 1).

Provides real confidentiality by wrapping a random DEK to custodian public keys
via ML-KEM-768/1024, and encrypting the bundle archive with AES-256-GCM.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from evseal.core import crypto
from evseal.core.manifest import jcs, pack, unpack

MAGIC_OUTER = b"EVSEAL-DR-OUTER1"  # 16 bytes
AAD_OUTER = b"evseal-dr-outer-v1"


def keygen_custodian(custodian_id: str, alg: str = "ML-KEM-768") -> dict:
    """Generate a custodian ML-KEM keypair for outer encryption."""
    kem = crypto.require_kem_backend(alg)
    pk, sk = kem.keygen()
    return {
        "id": custodian_id,
        "alg": alg,
        "pk": pk.hex(),
        "sk": sk.hex(),
        "fp": crypto.fingerprint(pk),
    }


def save_custodian_keys(path: Path, key_data: dict) -> Path:
    """Save custodian keys (sk split or combined)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(key_data, indent=2))
    return p


def load_custodian_key(path: Path) -> dict:
    return json.loads(Path(path).read_text())


def encrypt_outer(
    bundle_path: Path,
    custodians: list[dict],
    out_file: Path,
    kem_alg: str = "ML-KEM-768",
) -> Path:
    """Encrypt a bundle directory or packed bundle file for one or more custodians.

    Each custodian dict: {"id": str, "pk": bytes | hex_str, "alg": opt_str}
    """
    bundle_path = Path(bundle_path)
    out_file = Path(out_file)

    if not custodians:
        raise ValueError("At least one custodian key is required for outer encryption")

    # 1. Read bundle payload bytes (pack directory to temp zip if needed)
    with tempfile.TemporaryDirectory() as td:
        if bundle_path.is_dir():
            packed_path = Path(td) / "bundle.evseal"
            pack(bundle_path, packed_path)
            payload = packed_path.read_bytes()
        else:
            payload = bundle_path.read_bytes()

    # 2. Generate random 256-bit DEK and 96-bit IV
    dek = os.urandom(32)
    iv = os.urandom(12)

    # 3. Encapsulate DEK to each custodian
    custodian_entries = []
    for c in custodians:
        cid = c["id"]
        alg = c.get("alg", kem_alg)
        pk = bytes.fromhex(c["pk"]) if isinstance(c["pk"], str) else c["pk"]

        kem = crypto.require_kem_backend(alg)
        ss, kem_ct = kem.encaps(pk)

        # Derive wrap key from shared secret
        wrap_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=iv,
            info=b"evseal-dek-wrap:" + cid.encode(),
        ).derive(ss)

        wrapped_dek = AESGCM(wrap_key).encrypt(iv, dek, associated_data=cid.encode())

        custodian_entries.append({
            "id": cid,
            "alg": alg,
            "fp": crypto.fingerprint(pk),
            "kem_ct": kem_ct.hex(),
            "wrapped_dek": wrapped_dek.hex(),
        })

    # 4. Encrypt payload
    ct = AESGCM(dek).encrypt(iv, payload, associated_data=AAD_OUTER)

    # 5. Build container
    hdr = {
        "format": "evseal-dr-outer-v1",
        "aead": "AES-256-GCM",
        "nonce": iv.hex(),
        "custodians": custodian_entries,
        "payload_len": len(payload),
    }
    hdr_bytes = jcs(hdr)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "wb") as f:
        f.write(MAGIC_OUTER)
        f.write(len(hdr_bytes).to_bytes(4, "big"))
        f.write(hdr_bytes)
        f.write(ct)

    return out_file


def decrypt_outer(
    outer_file: Path,
    custodian_id: str,
    sk: bytes | str,
    out_path: Path,
) -> Path:
    """Decrypt outer container using a custodian's private key and restore bundle."""
    outer_file = Path(outer_file)
    out_path = Path(out_path)

    data = outer_file.read_bytes()
    if len(data) < len(MAGIC_OUTER) + 4:
        raise ValueError("File too small for outer container")
    if data[:len(MAGIC_OUTER)] != MAGIC_OUTER:
        raise ValueError(f"Invalid magic: {data[:len(MAGIC_OUTER)]!r}")

    hdr_len = int.from_bytes(data[len(MAGIC_OUTER):len(MAGIC_OUTER) + 4], "big")
    offset = len(MAGIC_OUTER) + 4
    hdr_bytes = data[offset:offset + hdr_len]
    ct = data[offset + hdr_len:]

    hdr = json.loads(hdr_bytes)
    if hdr.get("format") != "evseal-dr-outer-v1":
        raise ValueError(f"Unsupported format: {hdr.get('format')}")

    # Find matching custodian
    target = None
    for c in hdr.get("custodians", []):
        if c["id"] == custodian_id:
            target = c
            break

    if target is None:
        available_ids = [c["id"] for c in hdr.get("custodians", [])]
        raise ValueError(f"Custodian {custodian_id!r} not found in container (available: {available_ids})")

    alg = target["alg"]
    kem = crypto.require_kem_backend(alg)

    sk_bytes = bytes.fromhex(sk) if isinstance(sk, str) else sk
    kem_ct = bytes.fromhex(target["kem_ct"])
    wrapped_dek = bytes.fromhex(target["wrapped_dek"])
    iv = bytes.fromhex(hdr["nonce"])

    # Decapsulate shared secret
    ss = kem.decaps(sk_bytes, kem_ct)

    # Derive wrap key
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=iv,
        info=b"evseal-dek-wrap:" + custodian_id.encode(),
    ).derive(ss)

    # Unwrap DEK
    dek = AESGCM(wrap_key).decrypt(iv, wrapped_dek, associated_data=custodian_id.encode())

    # Decrypt payload
    payload = AESGCM(dek).decrypt(iv, ct, associated_data=AAD_OUTER)

    # Unpack or write to out_path
    if out_path.suffix.lower() in (".zip", ".evseal"):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(payload)
    else:
        # Destination is directory: unpack as bundle
        out_path.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as td:
            temp_zip = Path(td) / "bundle.zip"
            temp_zip.write_bytes(payload)
            unpack(temp_zip, out_path)

    return out_path
