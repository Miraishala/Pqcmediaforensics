"""Local workspace shared by CLI and API: keys, local test TSA, anchor log, profiles, bundles.

Location: $EVSEAL_HOME, else ~/.evseal. Private keys here are DEV-ONLY files (SPEC §9.2).
"""

from __future__ import annotations

import os
from pathlib import Path

from evseal.core import profile as prof
from evseal.longterm import keys
from evseal.longterm.anchorlog import AnchorLog
from evseal.longterm.timestamps import LocalTSA


class Workspace:
    def __init__(self, home: Path | str | None = None):
        self.home = Path(home or os.environ.get("EVSEAL_HOME") or Path.home() / ".evseal")
        for d in ("keys", "tsa", "profiles", "bundles", "uploads", "opened"):
            (self.home / d).mkdir(parents=True, exist_ok=True)

    @property
    def keys_dir(self) -> Path:
        return self.home / "keys"

    @property
    def anchor_path(self) -> Path:
        return self.home / "anchors.log"

    def anchor_log(self) -> AnchorLog:
        return AnchorLog(self.anchor_path)

    def tsa(self) -> LocalTSA:
        return LocalTSA(self.home / "tsa")

    def trust(self, allow_classical: bool = False) -> keys.Trust:
        self.tsa()  # make sure the local TSA key exists before trusting its directory
        return keys.Trust.from_paths(roots=[self.keys_dir], tsas=[self.home / "tsa"], allow_classical=allow_classical,
                                     anchor_log=self.anchor_path if self.anchor_path.exists() else None)

    def keygen(self, name: str, alg: str = prof.DEFAULTS["keys"]["root_alg"]) -> dict:
        if (self.keys_dir / f"{name}.key.json").exists():
            raise FileExistsError(f"key {name!r} already exists")
        kp = keys.generate(alg, name)
        keys.save(kp, self.keys_dir)
        return kp.public()

    def root(self, name: str) -> keys.KeyPair:
        return keys.load_private(self.keys_dir / f"{name}.key.json")

    def list_keys(self) -> list[dict]:
        return [keys.load_public(p) | {"has_private": (p.parent / p.name.replace(".pub.json", ".key.json")).exists()}
                for p in sorted(self.keys_dir.glob("*.pub.json"))]

    def profile(self, spec: str | None) -> dict:
        if spec and (self.home / "profiles" / f"{spec}.toml").exists():
            return prof.load(self.home / "profiles" / f"{spec}.toml")
        return prof.resolve(spec)
