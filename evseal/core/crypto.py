"""Crypto backend registry.

Every signature/KEM algorithm name used anywhere else in evseal must be
resolved through this module. No algorithm name or size is hardcoded
outside this file (CLAUDE.md non-negotiable).

Backend preference per algorithm family: try liboqs-python first (the
real, audited-upstream implementation), fall back to a pure-Python
reference implementation if liboqs's native library isn't available in
this environment. `available()` reports which backend (if any) actually
works, so `evseal doctor` can show the truth instead of assuming.

# ponytail: pure-Python ML-DSA/ML-KEM fallback (dilithium-py / kyber-py)
# is a reference implementation, not hardened against side channels.
# Upgrade path: once liboqs builds natively here (needs an MSVC/clang
# toolchain for `nmake`, confirmed absent on this dev machine), the
# liboqs backend will be picked automatically — no call-site changes
# needed, this registry is the only place that knows the difference.
"""

from __future__ import annotations

import functools
import platform
import shutil
from dataclasses import dataclass
from typing import Protocol


@functools.lru_cache(maxsize=1)
def _liboqs_buildable() -> bool:
    """Cheap preflight: does a C toolchain liboqs-python could actually build with exist?

    liboqs-python's `import oqs` auto-builds liboqs from source on first
    use if no prebuilt lib is found, and raises `SystemExit` (not a
    catchable `Exception`) if that build fails — plus it retries the full
    git-clone-and-cmake dance on every single import, with no caching of
    a prior failure. Skip the `import oqs` attempt entirely when we
    already know the build can't succeed, instead of eating that cost
    (and the SystemExit risk) on every CLI call.
    """
    if platform.system() == "Windows":
        return shutil.which("cl.exe") is not None or shutil.which("nmake") is not None
    return shutil.which("cc") is not None or shutil.which("gcc") is not None or shutil.which("clang") is not None


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
    backend: str | None  # "liboqs" | "pure-python" | None (unavailable)
    note: str = ""


def _try_liboqs_sig(oqs_name: str) -> SignatureBackend | None:
    oqs = _import_oqs()
    if oqs is None:
        return None
    try:
        with oqs.Signature(oqs_name):
            pass
    except (Exception, SystemExit):
        return None

    class _LiboqsSig:
        def keygen(self) -> tuple[bytes, bytes]:
            signer = oqs.Signature(oqs_name)
            pk = signer.generate_keypair()
            sk = signer.export_secret_key()
            return pk, sk

        def sign(self, sk: bytes, message: bytes) -> bytes:
            signer = oqs.Signature(oqs_name, sk)
            return signer.sign(message)

        def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
            verifier = oqs.Signature(oqs_name)
            return verifier.verify(message, signature, pk)

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
        return self._impl.verify(pk, message, signature)


_ML_DSA_LIBOQS_NAMES = {
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
}


def get_signature_backend(name: str) -> tuple[SignatureBackend | None, str | None]:
    """Return (backend, backend_kind) for a signature algorithm name, or (None, None)."""
    if name in _ML_DSA_LIBOQS_NAMES:
        liboqs_backend = _try_liboqs_sig(_ML_DSA_LIBOQS_NAMES[name])
        if liboqs_backend is not None:
            return liboqs_backend, "liboqs"
        try:
            from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
        except ImportError:
            return None, None
        impl = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}[name]
        return _DilithiumPySig(impl), "pure-python"

    if name.startswith("SLH-DSA"):
        liboqs_backend = _try_liboqs_sig(name)
        if liboqs_backend is not None:
            return liboqs_backend, "liboqs"
        # pyspx has no Windows/cp312 wheel today — see SPEC §9.2 known limits.
        return None, None

    if name == "Ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        class _Ed25519Sig:
            def keygen(self) -> tuple[bytes, bytes]:
                sk_obj = Ed25519PrivateKey.generate()
                pk = sk_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                sk = sk_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                return pk, sk

            def sign(self, sk: bytes, message: bytes) -> bytes:
                return Ed25519PrivateKey.from_private_bytes(sk).sign(message)

            def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
                try:
                    Ed25519PublicKey.from_public_bytes(pk).verify(signature, message)
                    return True
                except Exception:
                    return False

        return _Ed25519Sig(), "classical-non-pq"

    return None, None


class KemBackend(Protocol):
    def keygen(self) -> tuple[bytes, bytes]: ...
    def encaps(self, ek: bytes) -> tuple[bytes, bytes]: ...
    def decaps(self, dk: bytes, ct: bytes) -> bytes: ...


class _LiboqsKem:
    def __init__(self, oqs_name: str):
        self._oqs_name = oqs_name

    def keygen(self) -> tuple[bytes, bytes]:
        import oqs  # type: ignore

        kem = oqs.KeyEncapsulation(self._oqs_name)
        ek = kem.generate_keypair()
        dk = kem.export_secret_key()
        return ek, dk

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        import oqs  # type: ignore

        kem = oqs.KeyEncapsulation(self._oqs_name)
        ct, shared_secret = kem.encap_secret(ek)
        return shared_secret, ct

    def decaps(self, dk: bytes, ct: bytes) -> bytes:
        import oqs  # type: ignore

        kem = oqs.KeyEncapsulation(self._oqs_name, dk)
        return kem.decap_secret(ct)


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


def get_kem_backend(name: str) -> tuple[KemBackend | None, str | None]:
    if not name.startswith("ML-KEM"):
        return None, None

    oqs = _import_oqs()
    if oqs is not None:
        try:
            with oqs.KeyEncapsulation(name):
                pass
            return _LiboqsKem(name), "liboqs"
        except (Exception, SystemExit):
            pass

    try:
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    except ImportError:
        return None, None
    impl = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}.get(name)
    if impl is None:
        return None, None
    return _KyberPyKem(impl), "pure-python"


def available() -> list[AlgorithmStatus]:
    """Report every algorithm this registry knows about and whether it actually works."""
    statuses: list[AlgorithmStatus] = []

    for name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        backend, kind = get_signature_backend(name)
        statuses.append(
            AlgorithmStatus(
                name=name,
                family="signature",
                backend=kind,
                note="" if backend is not None else "unavailable",
            )
        )

    for name in ["SLH-DSA-SHA2-128s"]:
        backend, kind = get_signature_backend(name)
        statuses.append(
            AlgorithmStatus(
                name=name,
                family="signature",
                backend=kind,
                note="unavailable: liboqs not built, no Windows/cp312 pure-Python wheel (pyspx)"
                if backend is None
                else "",
            )
        )

    for name in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        backend, kind = get_kem_backend(name)
        statuses.append(
            AlgorithmStatus(
                name=name,
                family="kem",
                backend=kind,
                note="" if backend is not None else "unavailable",
            )
        )

    return statuses
