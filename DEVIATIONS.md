# DEVIATIONS.md — EviSeal known deviations from SPEC

Each entry: symptom, SPEC reference, status (documented / fix-in-progress / fixed), and
the upgrade path. Fixing a deviation requires a test that turns red → green, then one line
here marking it Fixed.

---

## D1 — TS segmentation: audio PES can straddle a cut boundary

**SPEC §9.1:** cuts must land on packet boundaries of ALL streams.
**Status:** **Fixed** (2026-10-07) — `media/common.py::_ts_adjust` moves each MPEG-TS cut back (never more than half the previous unit)
to the nearest packet boundary where no PES on any PID straddles it; if none exists the keyframe cut is kept. Units may then open with a few
pre-keyframe frames a decoder skips. Test: `test_ts_clean_cut_moves_off_a_straddling_audio_pes` (hand-built TS). ffmpeg's own muxer already
flushes audio before keyframes, so only other muxers (DVR/cameras) exercise this.
---

## D2 — Tile-level CORRUPT: whole-unit granularity on image parity failure

**SPEC §2.5:** per-tile status `CORRUPT` when decode errors spread from a damage point beyond
the parity budget; matching tiles → `VERIFIED`.
**Status:** **Fixed** — in `core/verify.py` and `media/image.py`. When AEAD chunks fail and parity
is exhausted, partial plaintext is reconstructed with zero-filled gaps; `tile_map` assigns
per-tile `CORRUPT` statuses to damaged tiles while matching intact tiles remain `VERIFIED`.

---

## D3 — In-bundle JPEG edits: RECOMPRESSED verdict instead of TAMPERED

**SPEC §2.5:** "inside a bundle the cryptographic path must give per-tile TAMPERED;
RECOMPRESSED/LIKELY_EDITED is only for external copies via compare_copy."
**Status:** **Fixed** — `edit_image_region` now executes exact DCT-domain modifications via `jpeglib`
without full image re-compression; in-bundle verification in `verify.py` forces `in_bundle=True`
so cryptographic `TAMPERED` status is always reported for damaged tiles. Added `recompress_and_edit_photo`
scenario covering re-saved images in bundles.

---

## D4 — RFC 3161 token: CMS signature not verified

**SPEC §5 / §10:** timestamp tokens must be verified against a trusted TSA certificate.
**Status:** **Fixed** (2026-10-07) — `longterm/timestamps.py` verifies with `openssl ts -verify` against `Trust.tsa_ca_file` at the token's
genTime; no CA file or no openssl means unverified (fail closed). Unreachable TSA queues a token (`evseal stamp-queue` flushes it; the
verifier reports the delay). Tests: `tests/test_rfc3161.py` (real openssl-built TSA, wrong-CA rejection, queue + flush).
Remaining limit: conventional TSAs sign with classical RSA/ECDSA (disclosed in the court report).
---

## D5 — Custody log not wired into verifier

**SPEC §3.3:** every copy/repair/transfer appends a signed chained custody record; the verifier
checks it.
**Status:** **Fixed** — `core/verify.py` reads `custody.log` if present and validates the full
hash-chain and actor signatures under `trust.roots`, surfacing any discrepancies as global checks.

---

## D6 — Unit timestamp metadata was unsigned

**Status:** **Fixed** (2026-10-07, owner-approved SPEC amendment A1) — bundle format v2 signs `[t, dur]` per unit inside the block
signature; the verifier flags any manifest/signed mismatch as `TAMPERED` and uses the signed `t` for the key validity window. v1 bundles still verify.
Tests: `test_unit_time_is_signed_edit_is_detected`, `test_v1_bundle_without_signed_times_still_verifies`.
---

## D7 — MP4 clip preview: sparse file the size of the original

**Status:** **Fixed** (2026-10-07) — `media/common.py::_rewrite_mp4_offsets` rewrites stco/co64 offsets and the mdat size in a compact copy.
Test: `test_mp4_clip_preview_is_compact_not_sparse` plus the existing clip/ffprobe tests.
---

## D8 — Protocol additions

**Status:** **Approved** (2026-10-07) and recorded in SPEC §14 (A2). Domain tags, chunk nonce rule, profile knobs (incl. `segment.max_unit_mb`),
thumb8 perceptual hash.
---

## P5, P6, and §10 Implementation Status (All Green)

- **P6 Disaster Recovery Profile (§3.3):**
  - Implemented `evseal/dr/outer.py`: random DEK wrapped to custodian ML-KEM keys (ML-KEM-768/1024), bundle encrypted with AES-256-GCM.
  - Implemented `evseal/dr/split.py`: $k$-of-$n$ geo-split shards via `zfec.easyfec` with tamper detection and integrity verification against untrusted sites.
  - Chained custody log updates on DR split and recover.
  - Verified with 7 comprehensive tests in `tests/test_dr.py`.
- **P5 Stress Lab, Benchmarks & Fuzzing (SPEC §6, §7):**
  - Implemented `evseal/bench/sweep.py` parameter sweeps (throughput, wall time, CPU time, RAM, and overhead %).
  - Implemented Atheris fuzzing harness `tests/fuzz/fuzz_manifest.py` and `tests/test_fuzz.py`.
  - Added UI pages `evseal/ui/src/pages/StressLab.jsx` and `evseal/ui/src/pages/Benchmarks.jsx`.
  - Added FastAPI endpoints in `evseal/api/app.py` for `/api/stress/*`, `/api/bench/*`, and `/api/dr/*`.
  - Rebuilt production UI with Vite into `evseal/ui/dist`.
- **§10 Reproducible Transcoding:**
  - Implemented `evseal/media/transcode.py`: deterministic x264 transcode with ffmpeg, signed derivation records, and bit-exact verifier.
  - Verified with `tests/test_transcode.py`.
- **End-to-End Testing from Live UI / API:**
  - `tests/test_e2e_api.py`: 11 live HTTP end-to-end integration tests covering Doctor -> Keygen -> Profile -> Upload -> Seal (SSE) -> Verify -> Clip & Open -> Tamper & Repair -> DR Split & Recover -> Stress Lab -> Benchmarks -> Static UI.
  - Entire test suite: **146 passed, 0 failures, 2 skipped** (144 fast + 2 slow).

---

## Audit hardening (2026-10-07)

- Verifier: any exception on hostile input is `REJECTED` (bad zip, huge sizes); tile buffers capped by real file size.
- Seal: refuses non-monotonic unit time across key periods, refuses without a timestamp source, refuses the DEV-ONLY backend
  (override `EVSEAL_ALLOW_DEV_CRYPTO=1`), ephemeral cert window now `rotation_s + 1 day`, `Trust.slack_s` is verifier policy.
- Revocation is judged against verified timestamp proof of signing time (SPEC §14 A4).
- Profile evolution: `profile.OPTIONAL` keeps old bundles verifiable when knobs are added (A3).
- `evseal-verify` (argparse only) and `evseal report` (draft s.63 / FRE 902 certificate) added.

## Access management and non-repudiation (2026-10-07, SPEC §14 A6–A8)

- Roles and signed identities: `evseal/access.py` (signed hash-chained directory), CLI `user-init|user-add|user-role|user-revoke|users|access-log`, `--as USER` on seal, clip, open, repair, reseal, dr-*, report.
- API: key-based login, live role checks, signed intent in `access.log` before each privileged action, throttled logins, `EVSEAL_AUTH=off` dev switch (non-loopback serve refused with it).
- Bundles: operator `seal` attestation bound to the final seal; `Trust.require_operator` policy; `evseal verify --require-operator`.
- External signer interface and hybrid (classical + PQ) timestamps added.
- Accepted limits: with a file key the API server holds the unlocked key for a session (custodial in memory); use an external signer for client-side non-repudiation. The access log is one local file (a truncated tail is not detectable without an external anchor).
