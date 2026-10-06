You are continuing the EviSeal build: post-quantum sealed multimedia evidence (video, audio, images).
Repo: `D:\Projects\Pqcmediaforensics` on Windows = `/mnt/d/Projects/Pqcmediaforensics` in WSL.

## 0. Read first, in this order
1. `CLAUDE.md` (non-negotiables + phase process) and `SPEC.md` (source of truth). §2 protocol is fixed: if something
   looks wrong, STOP and propose it — never change it silently. §11 lists rejected ideas; don't re-propose them.
2. `git status`. Everything after P0 is UNCOMMITTED: `evseal/core/*`, `media/*`, `resilience/*`, `longterm/*`,
   `stresslab/*`, `dr/custody.py`, `api/app.py`, `ui/*`, `workspace.py`, `bench/synth.py`, `cli.py` changes.
3. `grep -rn "ponytail:" evseal` — every deliberate shortcut, with its upgrade path.
4. Ignore `NEXT_PROMPT.md` (older, generic); this file supersedes it.

## 1. Current state (what exists and was verified by hand, NOT by a test suite)
- Built: crypto registry (ML-DSA/SLH-DSA/ML-KEM via liboqs, else DEV-ONLY pure-Python fallback; hybrid Ed25519+ML-DSA),
  profiles (§4, presets, validation, TOML, live estimates), byte-range segmenter (bit-exact on MP4 moov-end/faststart,
  fMP4, TS, raw H.264/H.265, WAV, MP3, M4A, Opus) + remux fallback, seal (journal fsync per block, rotation, checkpoints,
  final seal, local test TSA, anchor log), verify (fail-closed, 7 unit statuses, misplacement detection, in-memory RS
  repair), clip, open (verify-to-open), images (ordered sets, gaps, tile Merkle: JPEG DCT via jpeglib / raw pixels,
  EXIF/XMP/ICC leaves, RGB 8x8 perceptual thumbs, compare_copy, heatmap), zfec stripes + interleave + RS manifest copy,
  repair write-back + custody log, reseal, CLI (`evseal keygen|seal|verify|clip|open|repair|reseal|compare|pack|serve|doctor`),
  FastAPI + React/Vite/Tailwind UI (Seal, Verify timeline + filmstrip/tile overlay + compare copy + "attack a copy",
  Clip & Open with preview, Repair, Profiles, Keys, Environment).
- Stress Lab library exists (`stresslab/attacks.py`, `transforms.py`, `runner.py`) but `stresslab/expected.toml` does NOT exist.
- Tests: only `tests/test_doctor.py`. NO pytest coverage for anything above yet.
- E2E done in the browser on Windows (all on the pure-Python fallback): seal upload → VERIFIED; re-encrypt edit → TAMPERED
  at 1 unit; clip 3–4 verifies standalone + preview plays; PNG region edit → exactly 1 tile TAMPERED; recompressed+edited
  copy → 1 tile LIKELY_EDITED; bit flip → REPAIRED → repair write-back → VERIFIED.
- Run UI: `pixi run ui-build` then `pixi run serve` → http://localhost:8000 (workspace `.evseal-demo/`, gitignored).

## 2. Step 0 — commit the baseline (before changing anything)
Commit current work in a few logical commits (P1 core+media, P1b images, P2 ec/repair, P3 longterm, P4 api+ui, stresslab).
Check no key material is staged (`*.key.json`, `.evseal-demo/`, `.pixi/`, `node_modules/`, `evseal/ui/dist/`).

## 3. Step 1 — WSL2 environment (now primary)
WSL: Ubuntu 26.04, user `user`, 8 cores. Has git + python3, NO gcc/cmake yet.
SUDO: the WSL account is `user` / password `user` (dev VM only). Use it only for `sudo apt-get install`.
1. `sudo apt-get update && sudo apt-get install -y build-essential cmake ninja-build libssl-dev python3-dev git`
2. Install pixi in WSL. IMPORTANT: the repo's `.pixi/envs/default` holds the Windows env. Before `pixi install` in WSL run
   `pixi config set detached-environments true` (GLOBAL config inside WSL, not `--local`) so the Linux env lives outside the
   repo and does not clobber the Windows one. Keep a single checkout on `/mnt/d` (Windows UI dev must keep working).
3. Build liboqs from source as a shared lib, at the version matching the pinned `liboqs-python` (check its docs/tag),
   install to `$HOME/.local` (or /usr/local), set `OQS_INSTALL_PATH`/`LD_LIBRARY_PATH` so `import oqs` does not auto-build.
4. Check real algorithm names: `python -c "import oqs; print(oqs.get_enabled_sig_mechanisms())"`. `core/crypto.py`
   tries `SLH-DSA-…`, `SLH_DSA_PURE_…`, `SPHINCS+-…-simple` — fix the mapping to whatever liboqs actually exposes.
5. `pixi run evseal doctor` must show ML-DSA-44/65/87, SLH-DSA-SHA2-128s (+others), ML-KEM-512/768/1024 as `liboqs`.
   Pure-Python stays DEV-ONLY (Windows UI dev only). Never benchmark or seal real evidence on it.

## 4. Step 2 — tests (the missing safety net; do this before new features)
1. Write `stresslab/expected.toml` (format is defined by `runner.py`: `id, title, media, profile, attack|kind, params,
   overall, affected, others, any, none, tail, head, verdict, tiles, tiles_min, tiles_max, slow`). Cover:
   §7A correctness; §7B attacks 1–14 (11 uses the leaked-key capture in runner, 13 uses `tsa_offset_s`, 14 forged clip
   boundary); audio attacks (splice 1 s from another recording, delete 1 s, reorder); §7C faults (bit-rot 1e-9…1e-5,
   bursts L vs interleave D, lose 0..m+1 shards per stripe — exactly m repairs, m+1 → CORRUPT, never a false VERIFIED;
   lose manifest copies; kill -9 via `kind = "crash"`); §7G image matrix (transforms in `stresslab/transforms.py`).
2. pytest: `tests/test_media.py` (bit-exact reconstruct + standalone clip open for every spike format, ffprobe on the
   opened clip), `tests/test_stress_matrix.py` (parametrize over expected.toml; fast set by default, `slow` marked),
   `tests/test_properties.py` (Hypothesis §7D: random profile + random edit → modified unit never VERIFIED, untouched never fails),
   unit tests for every parser/crypto/repair path. Seeded randomness everywhere; seed in results.
3. Run all on native liboqs in WSL. A mismatch vs expected.toml is a bug in code, not in the expectation (unless SPEC says otherwise — then ask).

## 5. Step 3 — fix known deviations (each: fix, test, one line in DEVIATIONS.md)
1. TS segmentation: cuts land on video-keyframe TS packets; an audio PES can straddle a cut (bit-exact restore OK, clip
   playback loses a partial audio frame). SPEC §9.1 wants cuts at packet boundaries of ALL streams. Investigate a small
   TS parser in `media/` (PID/PUSI) to pick the nearest boundary with no straddling PES; if none exists in interleaved TS,
   propose the fallback (e.g. clip includes guard bytes / remux mode) to the user instead of guessing.
2. Tile-level CORRUPT (§2.5): damage beyond parity in an image currently reports the whole unit CORRUPT. Decrypt good chunks,
   zero-fill bad ones, decode leniently, recompute leaves: matching tiles VERIFIED, the rest CORRUPT (not TAMPERED).
3. In-bundle JPEG edits report verdict RECOMPRESSED (attacker re-saved the JPEG). Inside a bundle the cryptographic
   path must give per-tile TAMPERED (RECOMPRESSED/LIKELY_EDITED is only for external copies via compare_copy; keep the
   perceptual layer as an extra advisory overlay). Also make `edit_image_region` do a DCT-domain JPEG edit (jpeglib) so
   localization is demonstrable; add a "JPEG re-saved + edited" scenario too.
4. RFC 3161: tokens are parsed (imprint, genTime) but the CMS signature isn't verified, so they fail closed. Verify
   SignedData against a trusted TSA cert (asn1crypto or `cryptography` + minimal parsing). Add offline queueing of
   anchors/timestamps with reported delay (§10).
5. Verifier does not yet check `custody.log` (`dr/custody.check` exists) — wire it into verify as a global check.
6. Unit `t` (time) metadata is unsigned; the cert validity-window check (attack 11) relies on period monotonicity +
   final-seal cert period as the real defence. Document in DEVIATIONS.md; don't change §2 without asking.
7. Protocol additions that need user approval (report, don't silently keep): domain tags on gap/cert/reseal messages;
   AEAD chunk nonce = n_i XOR chunk index (single chunk == SPEC formula); `segment.assumed_fps`,
   `image.likely_edited_threshold`, `aead.chunk` knobs; `perceptual_hash = thumb8` (RGB 8x8 thumbnail) as the §4 "TBD" choice;
   `image.aead_chunk_kb = 64` default. Propose a SPEC.md diff and wait for approval.
8. MP4 clip preview builds a sparse file as big as the original (ponytail) — fix by rewriting stco/co64 in the clip's moov if cheap.

## 6. Step 4 — remaining phases (plan → approval → implement → green → 3–5 line deviation report, per CLAUDE.md)
- P5: Stress Lab UI page (pick scenarios + params + profiles, run matrix via API job + SSE, expected vs actual, mismatches
  highlighted, seed shown); Benchmarks (`evseal bench` sweeps over §4 knobs with `ffmpeg testsrc2` + noise, H.264/H.265,
  2/4 Mbps, 10 min/1 h; throughput, CPU, RAM, overhead %; record CPU + liboqs version; WSL/liboqs only; compare to §4
  reference figures) + Benchmarks UI charts; atheris fuzz harness for manifest parser + bundle reader (Linux only).
- P6: `dr/outer.py` (random DEK wrapped to custodian ML-KEM keys, AES-256-GCM over the bundle), `dr/split.py` (k-of-n
  fragments via zfec, per-fragment hashes, sites can't read or undetectably alter), site-loss tests (lose 1..n sites),
  custody records for every copy/repair/transfer; CLI `dr-split`/`dr-recover` + UI.
- After P3 is solid: §10 reproducible transcoding (signed derivation records).

## 7. Working rules / gotchas
- Fail closed. No algorithm names outside `core/crypto.py`. `core/verify.py` never imports api/ or ui/. Format logic only in `media/`.
- Never write private keys into bundles, logs, test snapshots, or commits.
- When writing Python via a shell heredoc, avoid `\x..` escapes (they got interpreted once); use the editor tool.
- Tailwind v4: custom classes in `src/index.css` must be `@utility`, not `@apply` on plain classes.
- API needs `python-multipart` (already in pixi.toml). Server has no autoreload: restart after backend edits.
- Keep Windows working: UI dev runs on Windows with the pure-Python fallback.

Report back with: commit list, `evseal doctor` output from WSL, test counts (fast + slow), DEVIATIONS.md, and the plan
for the next phase — then wait for approval.
