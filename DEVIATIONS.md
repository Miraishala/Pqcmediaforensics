# DEVIATIONS.md — EviSeal known deviations from SPEC

Each entry: symptom, SPEC reference, status (documented / fix-in-progress / fixed), and
the upgrade path. Fixing a deviation requires a test that turns red → green, then one line
here marking it Fixed.

---

## D1 — TS segmentation: audio PES can straddle a cut boundary

**SPEC §9.1:** cuts must land on packet boundaries of ALL streams.
**Symptom:** for MPEG-TS the cutter picks the nearest video-keyframe TS packet; an audio
PES spanning that cut loses a partial frame (bit-exact restore is OK; clip playback may drop
one audio frame at the splice point).
**Status:** Documented — not yet fixed.
**Upgrade path:** Write a lightweight TS packet parser in `media/video.py` (PID + PUSI bits)
that picks the nearest boundary with no PES straddling across *all* PIDs. If none exists
in the interleaved TS, offer "remux mode" (stream-copy to independent TS segments) instead
of guessing.

---

## D2 — Tile-level CORRUPT: whole-unit granularity on image parity failure

**SPEC §2.5:** per-tile status `CORRUPT` when decode errors spread from a damage point beyond
the parity budget; matching tiles → `VERIFIED`.
**Symptom:** an image whose AEAD chunks exceed the RS parity budget currently reports the
whole unit as `CORRUPT` rather than per-tile statuses.
**Status:** Documented — fix planned for Step 3.
**Upgrade path:** Decrypt any chunks that survive, zero-fill the rest, decode leniently, recompute
tile leaves; matching leaves → `VERIFIED`, mismatching leaves beyond damage → `CORRUPT`.

---

## D3 — In-bundle JPEG edits: RECOMPRESSED verdict instead of TAMPERED

**SPEC §2.5:** "inside a bundle the cryptographic path must give per-tile TAMPERED;
RECOMPRESSED/LIKELY_EDITED is only for external copies via compare_copy."
**Symptom:** `edit_image_region` saves the patched image with Pillow (re-saves the JPEG),
so after reencrypt the DCT coefficients differ but the compare path fires first and reports
`RECOMPRESSED`.
**Status:** Documented — fix planned for Step 3.
**Upgrade path:** Make `edit_image_region` do a DCT-domain edit via jpeglib (no re-save),
so the tile hashes mismatch deterministically → `TAMPERED`. The perceptual layer stays as
an advisory overlay only.

---

## D4 — RFC 3161 token: CMS signature not verified

**SPEC §5 / §10:** timestamp tokens must be verified against a trusted TSA certificate;
"fail closed" means an unverified token is not `VERIFIED`.
**Symptom:** `longterm/timestamps.py` parses the token (imprint, genTime) but does not
verify the SignedData CMS structure or the TSA certificate.
**Status:** Documented — fix planned for Step 3.
**Upgrade path:** Parse SignedData with `cryptography` or `asn1crypto`; verify the signature
against the stored TSA cert; reject if verification fails. Add offline queueing per §10.

---

## D5 — Custody log not wired into verifier

**SPEC §3.3:** every copy/repair/transfer appends a signed chained custody record; the verifier
checks it.
**Symptom:** `dr/custody.py` implements `check()` but `core/verify.py` does not call it.
**Status:** Documented — fix planned for Step 3.
**Upgrade path:** Call `custody.check(bundle)` at the start of `verify()`; surface custody
chain failures as a global reason in the `Report`.

---

## D6 — Unit timestamp metadata is unsigned (for attack 11 detection)

**SPEC §2:** all `R_i` and `C_i` are signed; unit `t` (wall-clock timestamp) is unsigned metadata.
**Symptom:** An attacker can change the `t` field in `manifest.json` without breaking any
signature. Attack 11 (sign period q with period p's leaked key) is caught by the validity-window
check (cert `valid_from..valid_until` vs the signed period boundary), NOT by checking `t`.
The validity-window defence is real and tested (see `attack11_leaked_key_long` scenario).
**Status:** Documented — NOT fixing in §2. This is the correct design: the cert validity window
is the cryptographic defence; `t` is advisory context for the UI.
**Note:** Adding `t` to the signed payload would require a §2 change — stop and ask first.

---

## D7 — MP4 clip preview: sparse file the size of the original

**media/common.py ponytail:** the clip's `moov` still has stco/co64 offsets relative to the
full original file; the clip is opened as a sparse file the full original size.
**Status:** Documented — fix planned for Step 3.
**Upgrade path:** Rewrite `stco`/`co64` in the clip's `moov` box to compact offsets using
the `struct` parser already in `media/common.py`.

---

## D8 — Protocol additions pending approval (Step 3 items)

The following were implemented without explicit protocol approval. Proposed as a SPEC.md diff —
**waiting for user approval before any of these become canon:**

1. **Domain tags on gap/cert/reseal messages** — signed messages for those record types have
   a leading domain-separator string (e.g. `"evseal-v1-gap"`) not in §2.
2. **AEAD chunk nonce = n_i XOR chunk_index** — single-chunk units use the bare `n_i`
   (matching SPEC formula); multi-chunk units XOR the chunk index in. Confirm this is canonical.
3. **New profile knobs added:** `segment.assumed_fps`, `image.likely_edited_threshold`,
   `aead.chunk` (segment | frame), `image.aead_chunk_kb = 64` (the "TBD" from §4).
4. **`perceptual_hash = thumb8`** — the §4 "TBD" algorithm choice is implemented as an
   RGB 8×8 thumbnail average-hash. Confirm this is the chosen algorithm.

*These are tracked here to avoid silent protocol drift. None of these change the core §2
chain/signing/AEAD/RS mechanics.*
