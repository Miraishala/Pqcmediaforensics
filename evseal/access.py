"""Access management with roles and signed identities (non-repudiation).

The user directory IS a signed, hash-chained log (`access.log`, same record format as the bundle
custody log). Entry 0 is a self-signed admin. Every later `user-add`, `user-role` and `user-revoke`
must be signed by a then-active admin. Replaying the log rebuilds the directory and verifies every
signature, so editing, reordering or truncating the middle of the log invalidates the whole
directory: access then fails closed. Operational entries (login, privileged actions, denials) are
signed by the acting user's own key, so each action is attributable to a person.

Bundles carry the operator's signature too: `attest_seal` appends a signed `seal` custody record
(rid, C_n, original-file hash, user, role) that the verifier checks against the final seal.

No UI/API imports here. HTTP sessions live in `evseal/api/auth.py`.

# ponytail: the log is a single local file; a truncated tail is not detectable without an external
# anchor. Upgrade path: anchor the log head hash in the anchor log / TSA at each admin action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from evseal.core import crypto
from evseal.dr import custody
from evseal.longterm.keys import KeyPair

LOG = "access.log"
ROLES = ("admin", "collector", "examiner", "custodian", "auditor")
_ALL = set(ROLES)
PERMS: dict[str, set[str]] = {
    "read": _ALL,                                   # list bundles, reports, manifests, profiles, public keys
    "verify": _ALL,
    "report": _ALL,
    "seal": {"admin", "collector"},
    "open": {"admin", "examiner", "custodian"},      # releases plaintext
    "clip": {"admin", "examiner", "custodian"},
    "repair": {"admin", "custodian"},
    "reseal": {"admin", "custodian"},
    "dr": {"admin", "custodian"},
    "profiles": {"admin", "collector"},
    "keys": {"admin"},
    "users": {"admin"},
    "delete": {"admin"},
    "lab": {"admin"},                                # attack simulation, stress lab, benchmarks
    "audit": {"admin", "auditor"},
}
LOGGED = set(PERMS) - {"read", "verify"}             # signed access-log entry before each of these runs


class AccessError(Exception):
    """The access log is damaged or forged: no identity can be trusted."""


class Denied(PermissionError):
    pass


@dataclass
class User:
    id: str
    role: str
    alg: str
    pk: str
    fp: str
    active: bool = True

    def public(self) -> dict:
        return {"id": self.id, "role": self.role, "alg": self.alg, "fp": self.fp, "active": self.active}


@dataclass
class Directory:
    users: dict[str, User] = field(default_factory=dict)

    def admins(self) -> list[User]:
        return [u for u in self.users.values() if u.active and u.role == "admin"]

    def pubs(self) -> dict[str, dict]:
        """fp -> public record, for every user ever registered (history stays verifiable after revocation)."""
        return {u.fp: {"alg": u.alg, "pk": u.pk, "fp": u.fp, "name": u.id} for u in self.users.values()}


def exists(home: Path) -> bool:
    return bool(custody.entries(home, LOG))


def replay(home: Path) -> Directory:
    """Rebuild the directory, verifying the chain and every signature. Raises AccessError on any fault."""
    d, prev = Directory(), custody.GENESIS
    for n, r in enumerate(custody.entries(home, LOG)):
        try:
            if r["seq"] != n or r["prev"] != prev or r["h"] != custody._h(r):
                raise AccessError(f"access log broken at entry {n}")
            action, det = r["action"], r["detail"]
            if n == 0:
                if action != "user-add" or det["role"] != "admin" or r["actor_fp"] != det["fp"] or r["actor_id"] != det["id"]:
                    raise AccessError("entry 0 must be a self-signed admin")
                alg, pk = det["alg"], bytes.fromhex(det["pk"])
            else:
                actor = d.users.get(r["actor_id"])
                if actor is None or not actor.active or actor.fp != r["actor_fp"]:
                    raise AccessError(f"entry {n} signed by an unknown or revoked actor")
                alg, pk = actor.alg, bytes.fromhex(actor.pk)
            if not crypto.verify(alg, pk, r["h"].encode(), bytes.fromhex(r["sig"])):
                raise AccessError(f"entry {n} signature invalid")
            if action in ("user-add", "user-role", "user-revoke"):
                if n > 0 and d.users[r["actor_id"]].role != "admin":
                    raise AccessError(f"entry {n}: only an admin may change the directory")
                _apply(d, action, det)
            prev = r["h"]
        except (KeyError, ValueError, TypeError) as exc:
            raise AccessError(f"malformed access log entry {n}: {exc}") from exc
    return d


def _apply(d: Directory, action: str, det: dict) -> None:
    if action == "user-add":
        if det["id"] in d.users or det["role"] not in ROLES:
            raise AccessError(f"cannot add user {det['id']!r} as {det['role']!r}")
        if crypto.fingerprint(bytes.fromhex(det["pk"])) != det["fp"]:
            raise AccessError("user fingerprint does not match its public key")
        d.users[det["id"]] = User(det["id"], det["role"], det["alg"], det["pk"], det["fp"])
        return
    u = d.users.get(det["id"])
    if u is None:
        raise AccessError(f"unknown user {det['id']!r}")
    if action == "user-role":
        if det["role"] not in ROLES:
            raise AccessError(f"unknown role {det['role']!r}")
        u.role = det["role"]
    else:
        u.active = False
    if not d.admins():
        raise AccessError("the directory must keep at least one active admin")


def _append(home: Path, user_id: str, kp: KeyPair, action: str, detail: dict) -> dict:
    return custody.append(home, kp, action, detail, name=LOG, actor_id=user_id)


def init_admin(home: Path, user_id: str, kp: KeyPair) -> dict:
    if exists(home):
        raise AccessError("access log already exists")
    return _append(home, user_id, kp, "user-add", {"id": user_id, "role": "admin", "alg": kp.alg, "pk": kp.pk.hex(), "fp": kp.fp})


def _admin_step(home: Path, by_id: str, by: KeyPair, action: str, detail: dict) -> dict:
    d = replay(home)
    actor = d.users.get(by_id)
    if actor is None or not actor.active or actor.role != "admin" or actor.fp != by.fp:
        raise Denied(f"{by_id!r} is not an active admin holding this key")
    _apply(_copy(d), action, detail)  # dry run: refuse before anything is written
    return _append(home, by_id, by, action, detail)


def _copy(d: Directory) -> Directory:
    return Directory({k: User(**vars(v)) for k, v in d.users.items()})


def add_user(home: Path, by_id: str, by: KeyPair, user_id: str, role: str, pub: dict) -> dict:
    return _admin_step(home, by_id, by, "user-add", {"id": user_id, "role": role, "alg": pub["alg"], "pk": pub["pk"],
                                                     "fp": crypto.fingerprint(bytes.fromhex(pub["pk"]))})


def set_role(home: Path, by_id: str, by: KeyPair, user_id: str, role: str) -> dict:
    return _admin_step(home, by_id, by, "user-role", {"id": user_id, "role": role})


def revoke_user(home: Path, by_id: str, by: KeyPair, user_id: str) -> dict:
    return _admin_step(home, by_id, by, "user-revoke", {"id": user_id})


def authorize(d: Directory, user_id: str, perm: str) -> User:
    u = d.users.get(user_id)
    if u is None or not u.active:
        raise Denied(f"unknown or revoked user {user_id!r}")
    if perm not in PERMS:
        raise Denied(f"unknown permission {perm!r}")
    if u.role not in PERMS[perm]:
        raise Denied(f"role {u.role!r} may not {perm}")
    return u


def record(home: Path, user: User, kp: KeyPair, action: str, detail: dict) -> dict:
    """Append a signed operational entry (login, privileged action, denial) under the user's own key."""
    if kp.fp != user.fp:
        raise Denied("signing key does not belong to this user")
    return _append(home, user.id, kp, action, detail)


def attest_seal(bundle_dir: Path, user: User, kp: KeyPair) -> dict:
    """The sealing operator signs what was sealed: rid, final chain value, original-file hash, user and role."""
    from evseal.core.manifest import Bundle

    if kp.fp != user.fp:
        raise Denied("signing key does not belong to this user")
    m, _ = Bundle(Path(bundle_dir)).load_manifest()
    fin = next((r for r in (m or {}).get("records", []) if r.get("type") == "final"), None)
    if fin is None:
        raise ValueError("bundle has no final seal to attest")
    return custody.append(Path(bundle_dir), kp, "seal", {"user": user.id, "role": user.role, "rid": m["rid"], "n": fin["n"],
                                                       "C_n": fin["C_n"], "file_hash": fin["file_hash"]}, actor_id=user.id)
