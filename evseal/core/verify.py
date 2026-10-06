"""Reference verifier (SPEC §2 "Verification and opening order", §10 `evseal-verify`).

Standalone: imports only core/, resilience/ec, longterm/ — never api/ or ui/. Fail closed:
anything failed, missing or skipped means not VERIFIED; there is no "unsigned but OK" path.

Overall verdicts:
  VERIFIED      every expected unit VERIFIED or REPAIRED, and every global check passed
  NOT_VERIFIED  trust established, but some unit or global check failed (listed exactly)
  REJECTED      no basis for trust: manifest missing/malformed, profile edited, untrusted root,
                disallowed algorithm, or no valid signatures at all

Order per unit: signed C_{i-1}, chain check -> derive K_i from the *signed* C_i -> AEAD open
(repair from parity/replicas on tag failure) -> recompute R_i -> compare with the signed R_i.

# ponytail: units are verified sequentially — hashing/AEAD dominate and stay well under disk
# speed on one core for test-sized bundles. Upgrade path: thread-pool the per-unit open+hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from evseal.core import crypto
from evseal.core.aead import TagMismatch, aad, open_chunk
from evseal.core.chain import chain_init, chain_step
from evseal.core.hashing import dual_hash
from evseal.core.kdf import derive_key_nonce
from evseal.core.manifest import (Bundle, block_msg, checkpoint_msg, final_msg, gap_msg, hexb, jcs, manifest_hash,
                                  reseal_msg, seg_name)
from evseal.core.profile import profile_hash, validate
from evseal.core.tilemerkle import merkle_root
from evseal.longterm import keys
from evseal.longterm.anchorlog import AnchorLog, check_entries
from evseal.longterm.timestamps import SLACK_S, verify_token
from evseal.resilience import ec

OK = ("VERIFIED", "REPAIRED")
GAP_PREFIX = b"evseal-gap:"
MISPLACE_WINDOW = 64  # how far away a misplaced unit's true index is searched for


@dataclass
class UnitResult:
    i: int
    status: str
    detail: str = ""
    role: str = "data"
    t: float = 0.0
    dur: float = 0.0
    name: str = ""
    R: str = ""
    C: str = ""
    block: dict | None = None  # the signed record covering this unit (minus R/C lists)
    cert: str = ""
    repaired_chunks: list[int] = field(default_factory=list)
    tiles: dict | None = None  # per-tile map for a tampered tiled unit


@dataclass
class Report:
    overall: str = "REJECTED"
    reasons: list[str] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    units: list[UnitResult] = field(default_factory=list)
    rid: str = ""
    media: dict = field(default_factory=dict)
    profile: dict = field(default_factory=dict)
    manifest_source: str = ""
    clip: dict | None = None
    certs: list[dict] = field(default_factory=list)
    checkpoints: list[dict] = field(default_factory=list)
    final: dict | None = None
    reseals: list[dict] = field(default_factory=list)

    def check(self, name: str, ok: bool, detail: str = "", fatal: bool = False, info: str = "") -> bool:
        """`detail` explains a failure; `info` is shown when the check passes."""
        self.checks.append({"name": name, "ok": bool(ok), "detail": info if ok else detail})
        if not ok:
            self.reasons.append(f"{name}: {detail}" if detail else name)
            if fatal:
                raise _Reject()
        return ok

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for u in self.units:
            out[u.status] = out.get(u.status, 0) + 1
        return out

    def to_dict(self) -> dict:
        d = asdict(self)
        d["counts"] = self.counts()
        return d


class _Reject(Exception):
    pass


def _tst_ok(rep: Report, label: str, rec: dict, msg: bytes, cert: dict | None, trust: keys.Trust, require: bool) -> None:
    toks = rec.get("tst") or []
    if require and not toks:
        rep.check(f"{label} timestamp", False, "no timestamp token")
    for tok in toks:
        ok, t, detail = verify_token(tok, msg, trust)
        rep.check(f"{label} timestamp", ok, detail, info=detail)
        if ok and cert is not None and t is not None and not (cert["not_before"] - SLACK_S <= t <= cert["not_after"] + SLACK_S):
            rep.check(f"{label} timestamp window", False, "timestamp outside the signing key's validity (backdated?)")


class _Opener:
    """Decrypt units by signed C_i; rebuild bad chunks from parity stripes or replicas."""

    def __init__(self, b: Bundle, m: dict, rid: bytes, signed: dict, profile: dict, replicas: list[Bundle], repair: bool):
        self.b, self.m, self.rid, self.signed, self.p = b, m, rid, signed, profile
        self.units = {u["i"]: u for u in m["units"] if isinstance(u, dict) and "i" in u}
        self.replicas, self.repair = replicas, repair
        self._keys: dict[int, tuple[bytes, bytes]] = {}
        self._seg: dict[int, bytes | None] = {}
        self.ecinfo = m.get("ec") if repair else None
        self.table = ec.chunk_table(list(self.units.values())) if self.ecinfo else []
        self.gidx = {(i, c): g for g, (i, c, _, _) in enumerate(self.table)}
        self.stripe_of: dict[int, tuple[int, int]] = {}
        if self.ecinfo:
            if self.ecinfo.get("n_chunks") != len(self.table):
                self.ecinfo = None  # manifest units and parity layout disagree: parity unusable
            else:
                for s, members in enumerate(ec.stripes(len(self.table), self.ecinfo["k"], self.ecinfo["interleave"])):
                    for pos, g in enumerate(members):
                        self.stripe_of[g] = (s, pos)
        self._good: dict[int, bytes] = {}  # global chunk -> verified ciphertext (incl. rebuilt)

    def key(self, i: int):
        if i not in self._keys:
            self._keys[i] = derive_key_nonce(self.signed[i][1], self.rid, i, self.p["kdf"]["alg"])
        return self._keys[i]

    def seg(self, i: int, b: Bundle | None = None) -> bytes | None:
        if b is not None:
            return b.read(seg_name(i))
        if i not in self._seg:
            self._seg[i] = self.b.read(seg_name(i))
        return self._seg[i]

    def chunk_ct(self, i: int, c: int, b: Bundle | None = None) -> bytes | None:
        u = self.units.get(i)
        data = self.seg(i, b)
        if u is None or data is None:
            return None
        off = sum(ln + crypto.AEAD_TAG_LEN for ln in u["chunks"][:c])
        ct = data[off : off + u["chunks"][c] + crypto.AEAD_TAG_LEN]
        return ct if len(ct) == u["chunks"][c] + crypto.AEAD_TAG_LEN else None

    def try_open(self, i: int, c: int, ct: bytes | None) -> bytes | None:
        if ct is None or i not in self.signed:
            return None
        key, nonce = self.key(i)
        try:
            return open_chunk(self.p["aead"]["alg"], key, nonce, c, ct, aad(self.rid, i))
        except TagMismatch:
            return None

    def _rebuild(self, g: int) -> bytes | None:
        s, pos = self.stripe_of[g]
        members = ec.stripes(len(self.table), self.ecinfo["k"], self.ecinfo["interleave"])[s]
        k_eff, m = len(members), self.ecinfo["m"]
        have: dict[int, bytes] = {}
        for j, gg in enumerate(members):
            if gg == g:
                continue
            if gg in self._good:
                have[j] = self._good[gg]
                continue
            ii, cc, _, _ = self.table[gg]
            ct = self.chunk_ct(ii, cc)
            if self.try_open(ii, cc, ct) is not None:
                self._good[gg] = ct
                have[j] = ct
        hashes = self.ecinfo["parity"][s] if s < len(self.ecinfo["parity"]) else []
        for p in range(m):
            sh = self.b.read(ec.par_name(s, p))
            if sh is not None and p < len(hashes) and ec.shard_hash(sh) == hashes[p]:
                have[k_eff + p] = sh
        lens = [self.table[gg][3] for gg in members]
        try:
            out = ec.decode(k_eff, m, have, lens)
        except Exception:
            return None
        return out[pos] if out else None

    def open_unit(self, i: int, repair: bool) -> tuple[bytes | None, list[int], list[int], str]:
        """Return (plaintext or None, repaired chunk numbers, bad chunk numbers, detail)."""
        u = self.units[i]
        parts, repaired, bad, how = [], [], [], set()
        seg_missing = self.seg(i) is None
        for c in range(len(u["chunks"])):
            ct = self.chunk_ct(i, c)
            pt = self.try_open(i, c, ct)
            if pt is None and repair and self.repair:
                for rb in self.replicas:  # SPEC §10 repair from replicas: accept only if it opens
                    pt = self.try_open(i, c, self.chunk_ct(i, c, rb))
                    if pt is not None:
                        how.add("replica")
                        break
                if pt is None and self.ecinfo and (i, c) in self.gidx:
                    g = self.gidx[(i, c)]
                    rebuilt = self._rebuild(g)
                    pt = self.try_open(i, c, rebuilt)
                    if pt is not None:
                        self._good[g] = rebuilt
                        how.add("parity")
                if pt is not None:
                    repaired.append(c)
            if pt is None:
                bad.append(c)
                parts.append(b"")
            else:
                parts.append(pt)
        detail = ("segment file missing" if seg_missing else f"AEAD tag failed on chunk(s) {bad}") if bad else ""
        if repaired:
            detail = f"rebuilt chunk(s) {repaired} from {'/'.join(sorted(how))}" + (f"; {detail}" if detail else "")
        partial = b"".join(parts[c] if parts[c] else b"\x00" * u["chunks"][c] for c in range(len(u["chunks"])))
        return (None if bad else b"".join(parts)), repaired, bad, detail, partial

    def misplaced(self, i: int) -> int | None:
        """A file that fails under K_i but opens under K_j holds unit j: deleted/inserted/reordered."""
        data = self.seg(i)
        if data is None:
            return None
        for j in sorted(self.signed, key=lambda j: abs(j - i)):
            if j == i or abs(j - i) > MISPLACE_WINDOW:
                continue
            uj = self.units.get(j)
            if uj is None or not uj.get("chunks"):
                continue
            # the attacker may have swapped manifest lengths too: try every plausible chunk-0 length
            lens = {len(data), uj["chunks"][0] + crypto.AEAD_TAG_LEN, *[c + crypto.AEAD_TAG_LEN for c in self.units[i]["chunks"][:1]]}
            if any(self.try_open(j, 0, data[:ln]) is not None for ln in lens):
                return j
        return None


def verify(path: Path, trust: keys.Trust, *, repair: bool = True, replicas: tuple = (), sink=None,
           tile_maps: bool = True) -> Report:
    """Verify a bundle or clip. `sink(i, plaintext, unit_result)` receives each VERIFIED/REPAIRED unit in order."""
    rep = Report()
    b = Bundle(Path(path))
    try:
        _verify(rep, b, trust, repair, [Bundle(Path(r)) for r in replicas], sink, tile_maps)
    except _Reject:
        rep.overall = "REJECTED"
        return rep
    except (KeyError, ValueError, TypeError, AttributeError, IndexError) as exc:  # malformed manifest: trust boundary
        rep.reasons.append(f"malformed manifest: {type(exc).__name__}: {exc}")
        rep.overall = "REJECTED"
        return rep
    hard_fail = any(not c["ok"] for c in rep.checks)
    rep.overall = "VERIFIED" if (rep.units and all(u.status in OK for u in rep.units) and not hard_fail) else "NOT_VERIFIED"
    return rep


def _verify(rep: Report, b: Bundle, trust: keys.Trust, repair: bool, replicas: list[Bundle], sink, tile_maps: bool) -> None:
    m, src = b.load_manifest()
    rep.manifest_source = src
    rep.check("manifest present", m is not None, "no readable manifest (stripped or destroyed)", fatal=True)
    rep.check("manifest source", src in ("manifest.json", "manifest.copy.json", "manifest_rs", "journal.jsonl"), src,
              info={"manifest_rs": "primary and embedded copies damaged; recovered from RS copy",
                    "journal.jsonl": "seal never finished; read from the crash-safe journal"}.get(src, src))
    profile = m["profile"]
    rep.profile, rep.media, rep.rid, rep.clip = profile, m.get("media", {}), m["rid"], m.get("clip")
    rid = hexb(m["rid"])
    if len(rid) != 32:
        raise ValueError("rid must be 256 bits")

    # 1. certificate chain + algorithm policy (profile is bound into C_0 and every certificate)
    errors, _ = validate(profile)
    rep.check("profile valid", not errors, "; ".join(errors), fatal=True)
    ph = profile_hash(profile)
    rep.check("profile hash", ph.hex() == m["profile_hash"], "embedded profile does not match its hash (edited?)", fatal=True)
    for key in ("sign", "checkpoint"):
        alg = profile[key]["alg"]
        rep.check(f"policy {key}.alg", crypto.security_class(alg) != "classical" or trust.allow_classical,
                  f"{alg} is NON-PQ; not on the verifier allow-list", fatal=True)
    root = m["root"]
    trusted = trust.roots.get(root.get("fp", ""))
    rep.check("root trusted", trusted is not None and trusted["pk"] == root["pk"] and trusted["alg"] == root["alg"]
              and crypto.fingerprint(hexb(root["pk"])) == root["fp"], "sealed by a key that is not a trusted root", fatal=True)
    revocations = dict(trust.revocations)
    if trust.anchor_log:
        revocations.update(AnchorLog(trust.anchor_log).revocations())

    records = m["records"]
    certs: dict[str, dict] = {}
    for r in (r for r in records if r.get("type") == "cert"):
        reason = keys.check_cert(r, trusted, m["rid"], m["profile_hash"], revocations)
        if reason is None and r["id"] not in certs:
            certs[r["id"]] = r
        rep.certs.append({**keys_view(r), "valid": reason is None, "reason": reason or ""})
        if reason:
            rep.check(f"certificate {r.get('id')}", False, reason)
    eph = {cid: c for cid, c in certs.items() if c["role"] == "ephemeral"}
    rep.check("signing certificate", bool(eph), "no valid ephemeral-key certificate", fatal=True)

    # 2. block signatures (and the key validity window, SPEC §7B attack 11)
    units_meta: dict[int, dict] = {}
    dup: set[int] = set()
    for u in m["units"]:
        if u["i"] in units_meta:
            dup.add(u["i"])
        units_meta[u["i"]] = u
    signed: dict[int, tuple[bytes, bytes]] = {}
    block_of: dict[int, dict] = {}
    conflict: set[int] = set()
    bad_sig: dict[int, str] = {}
    max_period = -1
    alg_c = profile["hash"]["chain"]
    for blk in sorted((r for r in records if r.get("type") == "block"), key=lambda r: r.get("i_start", 0)):
        a, z = int(blk["i_start"]), int(blk["i_end"])
        rs, cs = [hexb(x) for x in blk["R"]], [hexb(x) for x in blk["C"]]
        cert = eph.get(blk.get("cert"))
        why = ""
        if a < 1 or z < a or len(rs) != z - a + 1 or len(cs) != z - a + 1:
            why = "malformed block"
        elif cert is None:
            why = "block signed by an unknown or invalid certificate"
        elif not crypto.verify(cert["alg"], hexb(cert["pk"]), block_msg(rid, a, z, rs, cs), hexb(blk["sig"])):
            why = "block signature invalid (forged, edited or replayed at another index)"
        elif cert["period"] < max_period:
            why = f"signed with period {cert['period']} key after period {max_period} (validity window)"
        else:
            for i in range(a, z + 1):
                t = units_meta.get(i, {}).get("t", cert["t_from"])
                if not (cert["t_from"] <= t < cert["t_to"]):
                    why = f"unit {i} at t={t}s outside key validity window [{cert['t_from']}, {cert['t_to']})"
                    break
        if why:
            for i in range(max(a, 1), z + 1):
                bad_sig[i] = why
            rep.check(f"block {a}-{z}", False, why)
            continue
        max_period = cert["period"]
        view = {k: v for k, v in blk.items() if k not in ("R", "C")}
        for i, r_i, c_i in zip(range(a, z + 1), rs, cs):
            if i in signed and signed[i] != (r_i, c_i):
                conflict.add(i)
            signed[i] = (r_i, c_i)
            block_of[i] = view
    rep.check("block signatures", bool(signed), "no valid block signature at all (stripped?)", fatal=True)

    # final seal, checkpoints, timestamps, anchors
    finals = [r for r in records if r.get("type") == "final"]
    final_ok = False
    n_final = None
    if finals:
        f = finals[-1]
        cert = eph.get(f.get("cert"))
        last_period = max(c["period"] for c in eph.values())
        msg = final_msg(rid, int(f["n"]), hexb(f["C_n"]), hexb(f["file_hash"]))
        final_ok = rep.check("final seal", cert is not None and cert["period"] == last_period
                             and crypto.verify(cert["alg"], hexb(cert["pk"]), msg, hexb(f["sig"]))
                             and int(f["n"]) in signed and signed[int(f["n"])][1] == hexb(f["C_n"]) and len(finals) == 1,
                             "final seal signature/count/C_n check failed")
        if final_ok:
            n_final = int(f["n"])
            _tst_ok(rep, "final seal", f, msg, cert, trust, require=True)
        rep.final = {k: v for k, v in f.items() if k != "sig"} | {"valid": final_ok}
    ck_cert = {cid: c for cid, c in certs.items() if c["role"] == "checkpoint"}
    last_ckpt = 0
    for ck in (r for r in records if r.get("type") == "checkpoint"):
        cert = ck_cert.get(ck.get("cert"))
        i = int(ck["i"])
        msg = checkpoint_msg(rid, i, hexb(ck["C"]), int(ck["count"]))
        ok = rep.check(f"checkpoint {i}", cert is not None and int(ck["count"]) == i and i in signed
                       and signed[i][1] == hexb(ck["C"]) and crypto.verify(cert["alg"], hexb(cert["pk"]), msg, hexb(ck["sig"])),
                       "checkpoint signature or chain value invalid")
        if ok:
            last_ckpt = max(last_ckpt, i)
            _tst_ok(rep, f"checkpoint {i}", ck, msg, cert, trust, require=True)
        rep.checkpoints.append({k: v for k, v in ck.items() if k != "sig"} | {"valid": ok})
    if profile["anchors"]["backend"] == "local-log" and "clip" not in m:
        raw = b.read("anchors/anchors.jsonl")
        entries = [json.loads(x) for x in (raw or b"").decode().splitlines() if x.strip()]
        bad = check_entries(entries) if entries else None
        rep.check("anchor log copy", bad is None, bad or "")
        anchored = {(e.get("kind"), e.get("i"), e.get("C")) for e in entries if e.get("rid") == m["rid"]}
        wanted = [("checkpoint", c["i"], c["C"]) for c in rep.checkpoints if c["valid"]]
        if final_ok:
            wanted.append(("final", n_final, rep.final["C_n"]))
        missing = [w for w in wanted if w not in anchored]
        rep.check("anchored", not missing and (raw is not None or not wanted), f"not in anchor log: {missing}" if missing else "anchor log copy missing")
        if trust.anchor_log:
            ext = {e["h"] for e in AnchorLog(trust.anchor_log).entries()}
            rep.check("external anchor log", all(e["h"] in ext for e in entries), "bundle anchors not found in the external log")

    # reseals (RFC 4998-style evidence records)
    for k, rs_rec in enumerate(m.get("reseals", [])):
        signer = trust.roots.get(rs_rec.get("root_fp", ""))
        mh = manifest_hash(m, rs_rec["hash_alg"], upto_reseal=k)
        ok = rep.check(f"reseal {k}", signer is not None and mh.hex() == rs_rec["manifest_hash"]
                       and crypto.verify(signer["alg"], hexb(signer["pk"]), reseal_msg(mh, rs_rec), hexb(rs_rec["sig"])),
                       "reseal signature or manifest hash invalid")
        if ok:
            _tst_ok(rep, f"reseal {k}", rs_rec, reseal_msg(mh, rs_rec), None, trust, require=False)
        rep.reseals.append({kk: v for kk, v in rs_rec.items() if kk != "sig"} | {"valid": ok})

    # custody log (SPEC §3.3, Deviation D5)
    raw_custody = b.read("custody.log")
    if raw_custody:
        from evseal.dr import custody

        try:
            custody_recs = [json.loads(x) for x in raw_custody.decode().splitlines() if x.strip()]
            problems = custody.check(custody_recs, trust)
            rep.check("custody log", not problems, "; ".join(problems) if problems else "",
                      info=f"{len(custody_recs)} chained custody record(s) verified")
        except Exception as exc:
            rep.check("custody log", False, f"malformed custody log: {exc}")

    # 3. expected unit set
    clip = m.get("clip")
    if clip:
        expected = set(range(int(clip["i"]), int(clip["j"]) + 1))
        expected |= {i for i, u in units_meta.items() if u.get("role") in ("header", "trailer")}
    elif n_final is not None:
        expected = set(range(1, n_final + 1))
    else:
        expected = set(range(1, max(signed) + 1))
        rep.check("final seal present", False, f"no valid final seal: units after checkpoint {last_ckpt} are UNSEALED_TAIL")
    seg_files = {int(Path(n).stem) for n in b.list("segments/") if Path(n).stem.isdigit()}
    extras = (set(units_meta) | seg_files) - expected
    gaps = {}
    for g in (r for r in records if r.get("type") == "gap"):
        cert = eph.get(g.get("cert"))
        if cert and crypto.verify(cert["alg"], hexb(cert["pk"]), gap_msg(rid, int(g["i_start"]), int(g["i_end"]), g["reason"]), hexb(g["sig"])):
            for i in range(int(g["i_start"]), int(g["i_end"]) + 1):
                gaps[i] = g["reason"]

    opener = _Opener(b, m, rid, signed, profile, replicas, repair)
    c0 = chain_init(rid, ph, alg_c)
    algs = profile["hash"]["content"]
    whole = [hashlib.new(crypto.CONTENT_HASHES[a]) for a in algs]
    image_list: list[list[str]] = []
    for i in sorted(expected | extras):
        u = units_meta.get(i, {})
        res = UnitResult(i=i, status="VERIFIED", role=u.get("role", "data"), t=u.get("t", 0.0), dur=u.get("dur", 0.0),
                         name=u.get("name", ""), block=block_of.get(i), cert=(block_of.get(i) or {}).get("cert", ""))
        rep.units.append(res)
        if i in signed:
            res.R, res.C = signed[i][0].hex(), signed[i][1].hex()
        if i in extras:
            res.status, res.detail = "SEQUENCE_ERROR", "not part of the signed sequence (inserted?)"
            continue
        if not u:
            res.status, res.detail = "SEQUENCE_ERROR", "unit missing from manifest (deleted?)"
            continue
        if i in dup or i in conflict:
            res.status, res.detail = "SEQUENCE_ERROR", "conflicting records for this index"
            continue
        if i not in signed:
            res.status, res.detail = "SEQUENCE_ERROR", bad_sig.get(i, "not covered by any signed block")
            continue
        r_s, c_s = signed[i]
        c_prev = c0 if i == 1 else (signed.get(i - 1) or (None, None))[1]
        if c_prev is None:
            res.status, res.detail = "SEQUENCE_ERROR", "signed C_{i-1} unavailable (forged or missing clip boundary)"
            continue
        if chain_step(i, r_s, c_prev, alg_c) != c_s:
            res.status, res.detail = "SEQUENCE_ERROR", "chain check C_i = Hc(i || R_i || C_{i-1}) failed"
            continue
        if u.get("role") == "gap":
            ok = gaps.get(i) == u.get("gap") and dual_hash(GAP_PREFIX + u["gap"].encode(), algs) == r_s
            res.status, res.detail = ("GAP_DECLARED", u["gap"]) if ok else ("SEQUENCE_ERROR", "gap without a valid signed gap record")
            continue
        pt, repaired, bad, detail, partial = opener.open_unit(i, repair=False)
        if pt is None:
            j = opener.misplaced(i)  # before repair: a moved unit is manipulation, not damage to rebuild
            if j is not None:
                res.status, res.detail = "SEQUENCE_ERROR", f"holds unit {j}'s sealed data (deleted/inserted/reordered)"
                continue
            pt, repaired, bad, detail, partial = opener.open_unit(i, repair=True)
        res.repaired_chunks = repaired
        if pt is None:
            res.status, res.detail = "CORRUPT", detail
            if "tiles" in u and tile_maps:
                from evseal.media.image import tile_map

                res.tiles = tile_map(u["tiles"], partial, alg_c, profile["image"]["likely_edited_threshold"], in_bundle=True)
            continue
        if len(pt) != u["len"]:
            res.status, res.detail = "TAMPERED", "length differs from the sealed unit"
            continue
        r = dual_hash(pt, algs)
        if "tiles" in u:
            root_ok = merkle_root(alg_c, u["tiles"]["leaves"]) == r_s[len(r):]
            if r == r_s[: len(r)] and root_ok:
                pass
            else:
                res.status = "TAMPERED"
                res.detail = "content differs from the signed R_i" if root_ok else "tile leaves in the manifest do not match the signed root"
                if root_ok and tile_maps:
                    from evseal.media.image import tile_map  # format logic stays in media/

                    res.tiles = tile_map(u["tiles"], pt, alg_c, profile["image"]["likely_edited_threshold"], in_bundle=True)
                continue
        elif r != r_s:
            res.status, res.detail = "TAMPERED", "decrypts cleanly but R_i differs from the signed value (re-encrypted edit)"
            continue
        if repaired:
            res.status, res.detail = "REPAIRED", detail
        if n_final is None and not clip and i > last_ckpt:
            res.status, res.detail = "UNSEALED_TAIL", "after the last checkpoint and no final seal (truncation risk)"
        for h in whole:
            h.update(pt)
        if res.role == "data" and rep.media.get("kind") == "image":
            image_list.append([res.name, dual_hash(pt, algs).hex()])
        if sink is not None and res.status in OK:
            sink(i, pt, res)

    # whole-input hash from the final seal (bit-exact restore check, full bundles only)
    if final_ok and not clip and all(x.status in OK for x in rep.units) and profile["segment"]["mode"] == "byte-range":
        got = dual_hash(jcs(image_list), algs) if rep.media.get("kind") == "image" else b"".join(h.digest() for h in whole)
        rep.check("original file hash", got.hex() == rep.final["file_hash"], "reassembled input differs from H(original) in the final seal",
                  info="reassembled input matches H(original) in the final seal (bit-exact)")
    for alg, rec in (rep.media.get("legacy_hashes") or {}).items():
        rep.check(f"legacy {alg} acquisition hash", rec.get("match", False),
                  f"{alg.upper()} mismatch at acquisition", info=f"{alg.upper()} matches but is classically broken; recorded only")


def keys_view(cert: dict) -> dict:
    return {k: cert.get(k) for k in ("id", "role", "alg", "period", "t_from", "t_to", "not_before", "not_after", "root_fp")} | {
        "fp": crypto.fingerprint(bytes.fromhex(cert["pk"])) if isinstance(cert.get("pk"), str) else ""}


def compare_copy(path: Path, trust: keys.Trust, i: int, candidate: bytes) -> dict:
    """Check an external copy of sealed unit i (e.g. a photo handed over separately) against
    the sealed original: per-tile cryptographic map, plus the advisory perceptual layer."""
    captured: dict[int, bytes] = {}
    rep = verify(path, trust, sink=lambda j, pt, res: captured.__setitem__(j, pt) if j == i else None)
    u = next((x for x in rep.units if x.i == i), None)
    if u is None or u.status not in OK:
        return {"verdict": "UNVERIFIABLE", "detail": f"sealed unit {i} is not verified ({u.status if u else 'absent'})",
                "bundle_overall": rep.overall, "tiles": []}
    m, _ = Bundle(Path(path)).load_manifest()
    meta = next(x for x in m["units"] if x["i"] == i)
    p = m["profile"]
    if dual_hash(candidate, p["hash"]["content"]) == dual_hash(captured[i], p["hash"]["content"]):
        out = {"verdict": "VERIFIED", "tiles": []}
        if "tiles" in meta:
            from evseal.media.image import tile_map

            out = tile_map(meta["tiles"], candidate, p["hash"]["chain"], p["image"]["likely_edited_threshold"], captured[i])
    elif "tiles" in meta:
        from evseal.media.image import tile_map

        out = tile_map(meta["tiles"], candidate, p["hash"]["chain"], p["image"]["likely_edited_threshold"], captured[i])
    else:
        out = {"verdict": "TAMPERED", "detail": "bytes differ from the sealed unit", "tiles": []}
    out["bundle_overall"] = rep.overall
    out["unit"] = i
    return out
