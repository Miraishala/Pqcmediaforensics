"""`evseal-verify`: the separable reference verifier (SPEC §10). Standard library + the crypto
backends only; no typer, FastAPI or UI is imported, so a defence expert can run it alone.

    evseal-verify BUNDLE --root root.pub.json [--tsa tsa.pub.json] [--tsa-ca ca.pem] [--anchor-log log.jsonl]

Exit status 0 only when the overall verdict is VERIFIED.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="evseal-verify", description=__doc__.splitlines()[0])
    ap.add_argument("bundle", help="bundle directory, .evseal file or clip")
    ap.add_argument("--root", action="append", default=[], required=True, help="trusted root .pub.json (or a directory of them)")
    ap.add_argument("--tsa", action="append", default=[], help="trusted local-TSA .pub.json")
    ap.add_argument("--tsa-ca", help="PEM bundle of trusted RFC 3161 TSA CA certificates")
    ap.add_argument("--anchor-log", help="external anchor log (JSONL) to cross-check and read revocations from")
    ap.add_argument("--allow-classical", action="store_true", help="accept NON-PQ (Ed25519-only) signatures")
    ap.add_argument("--slack-s", type=float, default=300.0, help="allowed timestamp skew against key validity windows")
    ap.add_argument("--json", dest="json_out", help="write the full report as JSON")
    a = ap.parse_args(argv)

    from evseal.core.verify import verify
    from evseal.longterm.keys import Trust

    trust = Trust.from_paths(roots=a.root, tsas=a.tsa, allow_classical=a.allow_classical, slack_s=a.slack_s,
                             anchor_log=Path(a.anchor_log) if a.anchor_log else None,
                             tsa_ca_file=Path(a.tsa_ca) if a.tsa_ca else None)
    rep = verify(Path(a.bundle), trust)
    print(f"overall: {rep.overall}   {rep.counts()}")
    for r in rep.reasons:
        print(f"  ! {r}")
    for u in rep.units:
        if u.status != "VERIFIED":
            print(f"  unit {u.i:>6} {u.status:<15} {u.detail}")
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(rep.to_dict(), indent=1))
    return 0 if rep.overall == "VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
