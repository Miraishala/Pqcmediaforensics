"""Crypto backend registry.

Every algorithm name used anywhere else in evseal — signatures, KEMs, content/chain hashes,
AEADs, KDFs — must be resolved through this module. No algorithm name or size is hardcoded
outside this file (CLAUDE.md non-negotiable); everything else takes names from the profile.

Backend preference per signature/KEM: liboqs-python first (the real, audited-upstream
implementation), then a pure-Python reference implementation. `available()` reports which
backend actually works, so `evseal doctor` shows the truth instead of assuming.

# ponytail: pure-Python ML-DSA/ML-KEM/SLH-DSA fallbacks (dilithium-py / kyber-py / slh-dsa)
# are reference implementations, not hardened against side channels — DEV-ONLY (CLAUDE.md).
# Upgrade path: once liboqs builds natively (WSL2), the liboqs backend is picked
# automatically — no call-site changes, this registry is the only place that knows.
"""

from __future__ import annotations

import functools
import hashlib
import platform
import shutil
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes as _crypto_hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

DEV_ONLY_NOTE = "DEV-ONLY pure-Python fallback: slow, not timing-hardened — never benchmark or seal real evidence"

# ---- hashes / AEAD / KDF (SPEC §4 option names -> implementations) ----

CONTENT_HASHES = {"sha256": "sha256", "sha512": "sha512", "sha3-256": "sha3_256", "sha3-512": "sha3_512", "blake2b": "blake2b"}
CHAIN_HASHES = {"sha256": "sha256", "sha3-256": "sha3_256", "sha3-512": "sha3_512"}
HASH_FAMILY = {"sha256": "sha2", "sha512": "sha2", "sha3-256": "sha3", "sha3-512": "sha3", "blake2b": "blake2"}
AEADS = {"AES-256-GCM": AESGCM, "ChaCha20-Poly1305": ChaCha20Poly1305}
KDFS = {"HKDF-SHA256": _crypto_hashes.SHA256, "HKDF-SHA3-256": _crypto_hashes.SHA3_256}
AEAD_KEY_LEN = 32  # AES-256 / ChaCha20
AEAD_NONCE_LEN = 12
AEAD_TAG_LEN = 16
FINGERPRINT_HASH = "sha3_256"  # key fingerprints / anchor-log entry hashes
TSA_IMPRINT_HASH = "sha256"  # RFC 3161 messageImprint (OID below)
TSA_IMPRINT_OID = "2.16.840.1.101.3.4.2.1"
LEGACY_BROKEN_HASHES = {"md5", "sha1"}  # SPEC §10: record + check, flag as broken, never use in protocol
LOCAL_TSA_ALG = "ML-DSA-44"  # dev/test timestamp authority key (SPEC §4 timestamps: local test TSA)


def hash_bytes(alg: str, data: bytes) -> bytes:
    name = CONTENT_HASHES.get(alg) or CHAIN_HASHES.get(alg) or alg.replace("-", "_")
    return hashlib.new(name, data).digest()


def fingerprint(pk: bytes) -> str:
    return hashlib.new(FINGERPRINT_HASH, pk).hexdigest()


# ---- signatures ----

SIG_ALGS = [
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    *[f"SLH-DSA-{h}-{s}{v}" for h in ("SHA2", "SHAKE") for s in (128, 192, 256) for v in ("s", "f")],
    "Ed25519+ML-DSA-44", "Ed25519+ML-DSA-65", "Ed25519+ML-DSA-87",
    "Ed25519",
]
KEM_ALGS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]


def security_class(name: str) -> str:
    """UI badge + verifier policy: 'pq' | 'hybrid' | 'classical'."""
    if name.startswith("Ed25519+"):
        return "hybrid"
    if name == "Ed25519":
        return "classical"
    return "pq"


@functools.lru_cache(maxsize=1)
def _liboqs_buildable() -> bool:
    """Cheap preflight: does a C toolchain liboqs-python could actually build with exist?

    liboqs-python's `import oqs` auto-builds liboqs from source on first use if no prebuilt
    lib is found, and raises `SystemExit` (not a catchable `Exception`) if that build fails —
    plus it retries the full git-clone-and-cmake dance on every import. Skip the attempt
    entirely when we already know the build can't succeed.
    """
    if platform.system() == "Windows":
        return shutil.which("cl.exe") is not None or shutil.which("nmake") is not None
    return shutil.which("cc") is not None or shutil.which("gcc") is not None or shutil.which("clang") is not None


@functools.lru_cache(maxsize=1)
def _import_oqs():
    """Import the `oqs` module, treating both Exception and SystemExit as failure."""
    if not _liboqs_buildable():
        return None
    try:
        import oqs  # type: ignore

        return oqs
    except (Exception, SystemExit):
        return None


class SignatureBackend(Protocol):
    def keygen(self) -> tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True)
class AlgorithmStatus:
    name: str
    family: str  # "signature" | "kem"
    backend: str | None  # "liboqs" | "pure-python" | "classical-non-pq" | None (unavailable)
    note: str = ""


def _try_liboqs_sig(oqs_names: list[str]) -> SignatureBackend | None:
    oqs = _import_oqs()
    if oqs is None:
        return None
    for oqs_name in oqs_names:
        try:
            with oqs.Signature(oqs_name):
                break
        except (Exception, SystemExit):
            continue
    else:
        return None

    class _LiboqsSig:
        def keygen(self) -> tuple[bytes, bytes]:
            signer = oqs.Signature(oqs_name)
            pk = signer.generate_keypair()
            return pk, signer.export_secret_key()

        def sign(self, sk: bytes, message: bytes) -> bytes:
            return oqs.Signature(oqs_name, sk).sign(message)

        def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
            try:
                return oqs.Signature(oqs_name).verify(message, signature, pk)
            except Exception:
                return False

    return _LiboqsSig()


class _DilithiumPySig:
    """Pure-Python ML-DSA fallback, wrapping dilithium-py's ML_DSA_* objects."""

    def __init__(self, impl):
        self._impl = impl

    def keygen(self) -> tuple[bytes, bytes]:
        pk, sk = self._impl.keygen()
        return pk, sk

    def sign(self, sk: bytes, message: bytes) -> bytes:
        return self._impl.sign(sk, message)

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return self._impl.verify(pk, message, signature)
        except Exception:
            return False


class _SlhDsaPySig:
    """Pure-Python SLH-DSA fallback (slh-dsa package, FIPS 205 'pure' API)."""

    def __init__(self, par):
        self._par = par

    def keygen(self) -> tuple[bytes, bytes]:
        import slhdsa

        kp = slhdsa.KeyPair.gen(self._par)
        return kp.pub.digest(), kp.sec.digest()

    def sign(self, sk: bytes, message: bytes) -> bytes:
        import slhdsa

        return slhdsa.SecretKey.from_digest(sk, self._par).sign_pure(message)

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        import slhdsa

        try:
            return slhdsa.PublicKey.from_digest(pk, self._par).verify_pure(message, signature)
        except Exception:
            return False


class _Ed25519Sig:
    def keygen(self) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

        sk_obj = Ed25519PrivateKey.generate()
        pk = sk_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return pk, sk_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign(self, sk: bytes, message: bytes) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(sk).sign(message)

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(signature, message)
            return True
        except Exception:
            return False


_ED_PK, _ED_SK, _ED_SIG = 32, 32, 64


class _HybridSig:
    """Ed25519 + ML-DSA: both signatures must verify (AND-composition). Keys/sigs concatenated, Ed25519 first."""

    def __init__(self, pq: SignatureBackend):
        self._ed, self._pq = _Ed25519Sig(), pq

    def keygen(self) -> tuple[bytes, bytes]:
        epk, esk = self._ed.keygen()
        ppk, psk = self._pq.keygen()
        return epk + ppk, esk + psk

    def sign(self, sk: bytes, message: bytes) -> bytes:
        return self._ed.sign(sk[:_ED_SK], message) + self._pq.sign(sk[_ED_SK:], message)

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        return self._ed.verify(pk[:_ED_PK], message, signature[:_ED_SIG]) and self._pq.verify(
            pk[_ED_PK:], message, signature[_ED_SIG:]
        )


@functools.lru_cache(maxsize=None)
def get_signature_backend(name: str) -> tuple[SignatureBackend | None, str | None]:
    """Return (backend, backend_kind) for a signature algorithm name, or (None, None)."""
    if name in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        liboqs_backend = _try_liboqs_sig([name])
        if liboqs_backend is not None:
            return liboqs_backend, "liboqs"
        try:
            from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
        except ImportError:
            return None, None
        impl = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}[name]
        return _DilithiumPySig(impl), "pure-python"

    if name.startswith("SLH-DSA-") and name in SIG_ALGS:
        _, _, h, sv = name.split("-")
        liboqs_backend = _try_liboqs_sig([name, f"SLH_DSA_PURE_{h}_{sv.upper()}", f"SPHINCS+-{h}-{sv}-simple"])
        if liboqs_backend is not None:
            return liboqs_backend, "liboqs"
        try:
            import slhdsa
        except ImportError:
            return None, None
        return _SlhDsaPySig(getattr(slhdsa, f"{h.lower()}_{sv}")), "pure-python"

    if name.startswith("Ed25519+"):
        pq, kind = get_signature_backend(name.removeprefix("Ed25519+"))
        return (None, None) if pq is None else (_HybridSig(pq), kind)

    if name == "Ed25519":
        return _Ed25519Sig(), "classical-non-pq"

    return None, None


def require_signature_backend(name: str) -> SignatureBackend:
    backend, _ = get_signature_backend(name)
    if backend is None:
        raise RuntimeError(f"signature algorithm {name!r} has no working backend here (see `evseal doctor`)")
    return backend


def sign(alg: str, sk: bytes, message: bytes) -> bytes:
    return require_signature_backend(alg).sign(sk, message)


def verify(alg: str, pk: bytes, message: bytes, signature: bytes) -> bool:
    backend, _ = get_signature_backend(alg)
    return backend is not None and backend.verify(pk, message, signature)


def keygen(alg: str) -> tuple[bytes, bytes]:
    return require_signature_backend(alg).keygen()


# ---- KEMs ----


class KemBackend(Protocol):
    def keygen(self) -> tuple[bytes, bytes]: ...
    def encaps(self, ek: bytes) -> tuple[bytes, bytes]: ...
    def decaps(self, dk: bytes, ct: bytes) -> bytes: ...


class _LiboqsKem:
    def __init__(self, oqs, oqs_name: str):
        self._oqs, self._oqs_name = oqs, oqs_name

    def keygen(self) -> tuple[bytes, bytes]:
        kem = self._oqs.KeyEncapsulation(self._oqs_name)
        ek = kem.generate_keypair()
        return ek, kem.export_secret_key()

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        ct, shared_secret = self._oqs.KeyEncapsulation(self._oqs_name).encap_secret(ek)
        return shared_secret, ct

    def decaps(self, dk: bytes, ct: bytes) -> bytes:
        return self._oqs.KeyEncapsulation(self._oqs_name, dk).decap_secret(ct)


class _KyberPyKem:
    def __init__(self, impl):
        self._impl = impl

    def keygen(self) -> tuple[bytes, bytes]:
        return self._impl.keygen()

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        key, ct = self._impl.encaps(ek)
        return key, ct

    def decaps(self, dk: bytes, ct: bytes) -> bytes:
        return self._impl.decaps(dk, ct)


@functools.lru_cache(maxsize=None)
def get_kem_backend(name: str) -> tuple[KemBackend | None, str | None]:
    if name not in KEM_ALGS:
        return None, None
    oqs = _import_oqs()
    if oqs is not None:
        try:
            with oqs.KeyEncapsulation(name):
                pass
            return _LiboqsKem(oqs, name), "liboqs"
        except (Exception, SystemExit):
            pass
    try:
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    except ImportError:
        return None, None
    impl = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}[name]
    return _KyberPyKem(impl), "pure-python"


def require_kem_backend(name: str) -> KemBackend:
    backend, _ = get_kem_backend(name)
    if backend is None:
        raise RuntimeError(f"KEM {name!r} has no working backend here (see `evseal doctor`)")
    return backend


def _note(kind: str | None, missing: str) -> str:
    if kind is None:
        return missing
    if kind == "pure-python":
        return DEV_ONLY_NOTE
    if kind == "classical-non-pq":
        return "NON-PQ classical baseline only"
    return ""


def available() -> list[AlgorithmStatus]:
    """Report every algorithm this registry knows about and whether it actually works."""
    statuses: list[AlgorithmStatus] = []
    for name in SIG_ALGS:
        _, kind = get_signature_backend(name)
        statuses.append(AlgorithmStatus(name, "signature", kind, _note(kind, "unavailable: no liboqs and no pure-Python package")))
    for name in KEM_ALGS:
        _, kind = get_kem_backend(name)
        statuses.append(AlgorithmStatus(name, "kem", kind, _note(kind, "unavailable")))
    return statuses
