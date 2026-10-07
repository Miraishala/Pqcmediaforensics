"""Court report (SPEC "Later": BSA 2023 s.63 annexure / FRE 902(13)-(14) support).

Builds a DRAFT certificate from facts the verifier established. It never asserts anything the
verifier did not check, and it is only a draft: a human custodian must read, complete and sign it,
and counsel must review the wording for the jurisdiction. A bundle that is not VERIFIED yields a
report that says so and offers no certificate text.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from evseal.core import crypto
from evseal.core.manifest import Bundle
from evseal.core.verify import verify
from evseal.longterm.keys import Trust

DISCLOSURES = [
    "Integrity is proven from the moment of collection (sealing) onward; edits made before collection are outside what this tool can detect.",
    "A timestamp is only as trustworthy as the time-stamping authority that issued it. RFC 3161 tokens from a conventional TSA use classical (non post-quantum) signatures.",
    "Perceptual-hash results on images are advisory statistics, never a cryptographic finding.",
    "The signing keys were held by the collection device or collector; their custody is a matter for the certifying person, not something this software can attest.",
]


def _file_hashes(final_hash_hex: str, algs: list[str]) -> list[tuple[str, str]]:
    raw, out, pos = bytes.fromhex(final_hash_hex), [], 0
    for a in algs:
        n = hashlib.new(crypto.CONTENT_HASHES[a]).digest_size
        out.append((a, raw[pos : pos + n].hex()))
        pos += n
    return out


def build_report(bundle: Path, trust: Trust, *, custodian: str = "", designation: str = "", organisation: str = "",
                 device: str = "", place: str = "") -> dict:
    rep = verify(Path(bundle), trust)
    m, _ = Bundle(Path(bundle)).load_manifest()
    facts: dict = {"verdict": rep.overall, "units": rep.counts(), "reasons": rep.reasons}
    if m is not None:
        algs = m["profile"]["hash"]["content"]
        facts.update(
            rid=m["rid"], format=m.get("format"), tool=m.get("tool"), sealed_at=m.get("created"),
            source_name=(m.get("media") or {}).get("source_name"), media_kind=(m.get("media") or {}).get("kind"),
            root={k: m["root"][k] for k in ("alg", "fp")}, sign_alg=m["profile"]["sign"]["alg"],
            checkpoint_alg=m["profile"]["checkpoint"]["alg"], profile_hash=m["profile_hash"],
            backends={a: (crypto.get_signature_backend(a)[1] or "unavailable")
                      for a in {m["profile"]["sign"]["alg"], m["profile"]["checkpoint"]["alg"], m["root"]["alg"]}},
        )
        if rep.final:
            facts["original_file_hashes"] = _file_hashes(rep.final["file_hash"], algs)
            facts["timestamps"] = [{"kind": t.get("kind"), "time": t.get("time")} for t in (next(
                (r for r in m["records"] if r.get("type") == "final"), {}).get("tst") or [])]
    cust = Bundle(Path(bundle)).read("custody.log")
    recs = [json.loads(x) for x in (cust or b"").decode().splitlines() if x.strip()]
    facts["custody_records"] = len(recs)
    facts["operators"] = [{"user": r["detail"].get("user"), "role": r["detail"].get("role"), "alg": r.get("actor_alg"),
                           "fp": r.get("actor_fp"), "signed_at": r.get("time")} for r in recs if r.get("action") == "seal"]
    return {"facts": facts, "declarant": {"name": custodian, "designation": designation, "organisation": organisation,
                                          "device": device, "place": place}, "disclosures": DISCLOSURES}


def render_markdown(r: dict) -> str:
    f, d = r["facts"], r["declarant"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"# Electronic record verification report: DRAFT ({now})", "",
           "> DRAFT for a human custodian to review, complete and sign. Not legal advice; counsel must confirm the form required in the jurisdiction (e.g. BSA 2023 s.63 certificate, FRE 902(13)/(14)).", "",
           f"## Verification result: **{f['verdict']}**", ""]
    if f["verdict"] != "VERIFIED":
        out += ["The bundle did **not** verify. Do not sign a certificate relying on it.", ""] + [f"- {x}" for x in f["reasons"]]
        return "\n".join(out) + "\n"
    out += [f"- Recording id: `{f['rid']}`", f"- Bundle format: {f['format']}; tool: {f['tool']}",
            f"- Media: {f['media_kind']} ({f['source_name']}); units checked: {f['units']}",
            f"- Sealing key: {f['root']['alg']} fingerprint `{f['root']['fp']}`; per-unit signatures {f['sign_alg']}; checkpoints {f['checkpoint_alg']}",
            f"- Cryptographic backends used: {f['backends']}",
            f"- Profile hash: `{f['profile_hash']}`", f"- Custody log records: {f['custody_records']}"]
    out += [f"- Sealed by operator **{o['user']}** ({o['role']}), who signed the seal with {o['alg']} key `{str(o['fp'])[:16]}…`"
            for o in f.get("operators", [])] or ["- No operator signature is attached to this bundle."]
    out += [""]
    out += ["## Hash values of the original electronic record", ""]
    out += [f"- {a}: `{h}`" for a, h in f.get("original_file_hashes", [])]
    out += ["", "## Timestamps", ""] + [f"- {t['kind']}: {datetime.fromtimestamp(t['time'], timezone.utc).isoformat()}" for t in f.get("timestamps", []) if t.get("time")]
    out += ["", "## Matters this verification does not establish", ""] + [f"- {x}" for x in r["disclosures"]]
    out += ["", "## Part A: to be completed and signed by the person in charge of the device or system", "",
            f"I, {d['name'] or '____________'}, {d['designation'] or '____________'} of {d['organisation'] or '____________'}, "
            f"state that the electronic record identified above was produced by {d['device'] or '____________'} at {d['place'] or '____________'}, "
            "which was in regular use and operating properly during the relevant period, and that the hash values above are those of the record as sealed. "
            "[Complete or strike each statement according to the facts known to the signatory.]", "",
            "Signature: ____________    Date: ____________", "",
            "## Part B: to be completed and signed by the examining expert", "",
            "I have verified the sealed bundle with the reference verifier and obtained the result and hash values stated above.", "",
            "Name: ____________    Signature: ____________    Date: ____________"]
    return "\n".join(out) + "\n"


def write_report(bundle: Path, trust: Trust, out: Path, **who) -> dict:
    r = build_report(bundle, trust, **who)
    out = Path(out)
    out.write_text(render_markdown(r), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(r, indent=1, default=str), encoding="utf-8")
    return r
