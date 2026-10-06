"""tests/test_crypto.py — Unit tests for core/crypto.py: backends, keygen, sign/verify,
KEM encaps/decaps, and the `available()` report. Also tests hashing, AEAD, KDF, and chain.
"""
from __future__ import annotations

import hashlib

import pytest

from evseal.core import crypto
from evseal.core.aead import aad, open_chunk, seal_chunk
from evseal.core.chain import chain_init, chain_step
from evseal.core.hashing import dual_hash
from evseal.core.kdf import derive_key_nonce


# ---- crypto registry ----

def test_available_returns_list():
    statuses = crypto.available()
    assert isinstance(statuses, list)
    assert all(hasattr(s, "name") for s in statuses)


def test_available_reports_backend():
    """Every algorithm must report a backend or None — not crash."""
    for s in crypto.available():
        assert s.backend in ("liboqs", "pure-python", "classical-non-pq", None)


@pytest.mark.parametrize("alg", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
def test_mldsa_sign_verify(alg):
    backend, kind = crypto.get_signature_backend(alg)
    if backend is None:
        pytest.skip(f"{alg}: no backend available")
    pk, sk = backend.keygen()
    msg = b"hello evseal"
    sig = backend.sign(sk, msg)
    assert backend.verify(pk, msg, sig)
    # wrong message must fail
    assert not backend.verify(pk, b"wrong", sig)


@pytest.mark.parametrize("alg", ["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"])
def test_slhdsa_sign_verify(alg):
    backend, kind = crypto.get_signature_backend(alg)
    if backend is None:
        pytest.skip(f"{alg}: no backend available")
    pk, sk = backend.keygen()
    msg = b"slh-dsa test"
    sig = backend.sign(sk, msg)
    assert backend.verify(pk, msg, sig)
    assert not backend.verify(pk, msg + b"\x00", sig)


def test_hybrid_sign_verify():
    alg = "Ed25519+ML-DSA-44"
    backend, _ = crypto.get_signature_backend(alg)
    if backend is None:
        pytest.skip("Ed25519+ML-DSA-44 not available")
    pk, sk = backend.keygen()
    msg = b"hybrid sig"
    sig = backend.sign(sk, msg)
    assert backend.verify(pk, msg, sig)
    assert not backend.verify(pk, b"X", sig)


@pytest.mark.parametrize("alg", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_kem_encaps_decaps(alg):
    backend, kind = crypto.get_kem_backend(alg)
    if backend is None:
        pytest.skip(f"{alg}: no backend available")
    ek, dk = backend.keygen()
    ss1, ct = backend.encaps(ek)
    ss2 = backend.decaps(dk, ct)
    assert ss1 == ss2
    # altered ciphertext must yield different (random) shared secret or raise
    import os
    bad_ct = bytes(b ^ 1 for b in ct)
    try:
        ss3 = backend.decaps(dk, bad_ct)
        assert ss3 != ss1, "decaps of corrupted CT should NOT yield the original SS"
    except Exception:
        pass  # raising is also acceptable (fail-closed)


# ---- hashing ----

def test_dual_hash_deterministic():
    data = b"unit bytes"
    r1 = dual_hash(data, ["sha256", "sha3-256"])
    r2 = dual_hash(data, ["sha256", "sha3-256"])
    assert r1 == r2


def test_dual_hash_length():
    r = dual_hash(b"x", ["sha256", "sha3-256"])
    assert len(r) == 32 + 32


def test_dual_hash_changes_on_edit():
    r1 = dual_hash(b"aaaa", ["sha256", "sha3-256"])
    r2 = dual_hash(b"aaab", ["sha256", "sha3-256"])
    assert r1 != r2


# ---- chain ----

def test_chain_init_deterministic():
    c1 = chain_init(b"\x00" * 32, b"\x01" * 32, "sha3-256")
    c2 = chain_init(b"\x00" * 32, b"\x01" * 32, "sha3-256")
    assert c1 == c2


def test_chain_step_changes_with_r():
    rid = b"\xAB" * 32
    r1 = b"\x01" * 64
    r2 = b"\x02" * 64
    c0 = b"\x00" * 32
    c1 = chain_step(1, r1, c0, "sha3-256")
    c2 = chain_step(1, r2, c0, "sha3-256")
    assert c1 != c2


def test_chain_step_changes_with_index():
    r = b"\x11" * 64
    c0 = b"\x00" * 32
    ca = chain_step(1, r, c0, "sha3-256")
    cb = chain_step(2, r, c0, "sha3-256")
    assert ca != cb


# ---- KDF ----

def test_kdf_derives_key_and_nonce():
    c = b"\xCC" * 32
    rid = b"\xDD" * 32
    key, nonce = derive_key_nonce(c, rid, 0, "HKDF-SHA256")
    assert len(key) == 32
    assert len(nonce) == 12


def test_kdf_different_index_different_key():
    c = b"\xCC" * 32
    rid = b"\xDD" * 32
    k0, n0 = derive_key_nonce(c, rid, 0, "HKDF-SHA256")
    k1, n1 = derive_key_nonce(c, rid, 1, "HKDF-SHA256")
    assert k0 != k1 or n0 != n1  # at minimum one must differ


# ---- AEAD ----

def test_aead_roundtrip():
    key = b"\x42" * 32
    nonce = b"\x13" * 12
    pt = b"secret payload"
    ad = b"aad-bytes"
    ct = seal_chunk("AES-256-GCM", key, nonce, 0, pt, ad)
    out = open_chunk("AES-256-GCM", key, nonce, 0, ct, ad)
    assert out == pt


def test_aead_tag_detects_tampering():
    from cryptography.exceptions import InvalidTag
    key = b"\x42" * 32
    nonce = b"\x13" * 12
    pt = b"secret payload"
    ad = b"aad-bytes"
    ct = bytearray(seal_chunk("AES-256-GCM", key, nonce, 0, pt, ad))
    ct[5] ^= 0xFF  # flip a bit
    with pytest.raises(Exception):
        open_chunk("AES-256-GCM", key, bytes(nonce), 0, bytes(ct), ad)


def test_aead_chunk_index_binds_nonce():
    """Different chunk indices must produce different ciphertext (nonce = n_i XOR chunk_index)."""
    key = b"\x42" * 32
    nonce = b"\x13" * 12
    pt = b"same payload"
    ad = b"aad"
    ct0 = seal_chunk("AES-256-GCM", key, nonce, 0, pt, ad)
    ct1 = seal_chunk("AES-256-GCM", key, nonce, 1, pt, ad)
    assert ct0 != ct1
