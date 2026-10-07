"""HTTP sessions for the API: login with a user's own signing key, live role checks, signed access log.

A login proves possession of the registered key (the key is unlocked with the user's passphrase,
or an external signer is asked, and a fresh nonce must verify against the public key in the signed
directory). The unlocked key stays in server memory for the session so each privileged request can
be signed by that person, not by a shared service key.

# ponytail: with a file key the server holds the unlocked key for the session (custodial in memory).
# For true client-side non-repudiation, use an external signer (keys.register_external) or a
# client-side signing agent. Upgrade path: WebAuthn/PQ-capable token signing the request digest.
"""

from __future__ import annotations

import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from evseal import access
from evseal.core import crypto
from evseal.longterm import keys

TTL_S = 8 * 3600
MAX_FAILS, FAIL_WINDOW_S = 5, 300

_ANY = None
_B = r"^/api/bundles/[^/]+"
# (methods or None for any, path regex, permission). First match wins. Unmatched routes need `users` (admin): fail closed.
ROUTES: list[tuple[set[str] | None, str, str]] = [
    ({"GET"}, r"^/api/(doctor|schema)$", "read"),
    ({"GET"}, r"^/api/profiles(/[^/]+)?$", "read"),
    ({"POST"}, r"^/api/profiles/(validate|diff)$", "read"),
    ({"PUT", "DELETE"}, r"^/api/profiles/[^/]+$", "profiles"),
    ({"GET"}, r"^/api/keys(/rotation)?$", "read"),
    ({"POST"}, r"^/api/keys$", "keys"),
    ({"POST"}, r"^/api/(uploads|seal)$", "seal"),
    ({"GET"}, r"^/api/jobs/[^/]+/events$", "seal"),
    ({"GET"}, r"^/api/bundles$", "read"),
    ({"POST"}, _B + r"/(verify|compare)$", "verify"),
    ({"GET"}, _B + r"/(report|manifest)$", "read"),
    ({"GET"}, _B + r"/court-report$", "report"),
    ({"GET"}, _B + r"/(image|tiles)/.+$", "open"),
    ({"POST"}, _B + r"/clip$", "clip"),
    ({"POST"}, _B + r"/open$", "open"),
    ({"GET"}, r"^/api/opened/.+$", "open"),
    (_ANY, _B + r"/repair/.+$", "repair"),
    (_ANY, _B + r"/dr/.+$", "dr"),
    (_ANY, r"^/api/dr/.+$", "dr"),
    ({"DELETE"}, _B + r"$", "delete"),
    ({"POST"}, _B + r"/tamper$", "lab"),
    (_ANY, r"^/api/(attacks|stress|bench)(/.*)?$", "lab"),
    ({"GET"}, r"^/api/audit/.+$", "audit"),
]
_COMPILED = [(m, re.compile(rx), perm) for m, rx, perm in ROUTES]


def perm_for(method: str, path: str) -> str:
    for methods, rx, perm in _COMPILED:
        if (methods is None or method in methods) and rx.match(path):
            return perm
    return "users"


@dataclass
class Session:
    user: access.User
    kp: keys.KeyPair
    expires: float


class Throttled(Exception):
    pass


class Sessions:
    def __init__(self) -> None:
        self._s: dict[str, Session] = {}
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._dir_key: tuple | None = None
        self._dir: access.Directory | None = None

    # ---- directory cache: replaying verifies every signature, so reuse it until the log file changes ----
    def directory(self, ws) -> access.Directory | None:
        p = ws.home / access.LOG
        if not p.exists():
            return None
        st = p.stat()
        key = (str(p), st.st_mtime_ns, st.st_size)
        with self._lock:
            if key != self._dir_key:
                self._dir, self._dir_key = access.replay(ws.home), key
            return self._dir

    def own_append(self, ws) -> None:
        """An operational (non-directory) entry we just wrote does not change the directory: keep the cache."""
        p = ws.home / access.LOG
        st = p.stat()
        with self._lock:
            if self._dir is not None:
                self._dir_key = (str(p), st.st_mtime_ns, st.st_size)

    # ---- login / logout ----
    def login(self, ws, user_id: str, passphrase: str | None) -> str:
        now = time.time()
        with self._lock:
            recent = [t for t in self._fails.get(user_id, []) if now - t < FAIL_WINDOW_S]
            self._fails[user_id] = recent
            if len(recent) >= MAX_FAILS:
                raise Throttled("too many failed logins; try again later")
        try:
            d = self.directory(ws)
            u = d.users.get(user_id) if d else None
            if u is None or not u.active:
                raise access.Denied("unknown or revoked user")
            kp = keys.load_private(ws.user_keys_dir / f"{user_id}.key.json", passphrase or None)
            nonce = os.urandom(16)
            if kp.fp != u.fp or not crypto.verify(u.alg, bytes.fromhex(u.pk), b"evseal-login" + nonce, kp.sign(b"evseal-login" + nonce)):
                raise access.Denied("key does not match the registered key")
        except (access.Denied, ValueError, FileNotFoundError):
            with self._lock:
                self._fails.setdefault(user_id, []).append(now)
            raise access.Denied("login failed") from None
        access.record(ws.home, u, kp, "login", {})
        self.own_append(ws)
        tok = secrets.token_urlsafe(32)
        with self._lock:
            self._s[tok] = Session(u, kp, now + TTL_S)
        return tok

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self._lock:
            s = self._s.get(token)
            if s and s.expires < time.time():
                self._s.pop(token, None)
                return None
            return s

    def logout(self, ws, token: str | None) -> None:
        s = self.get(token)
        if s is None:
            return
        access.record(ws.home, s.user, s.kp, "logout", {})
        self.own_append(ws)
        with self._lock:
            self._s.pop(token, None)


SESSIONS = Sessions()
