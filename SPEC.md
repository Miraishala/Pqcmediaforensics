# EviSeal — Post-Quantum Sealed Video Evidence

Build spec v0.1 · working name, rename freely

## 1. Goal

A tool that seals video evidence in short segments so that:

1. Any edit, deletion, insertion or reordering is **detected and localized** to the segment.
2. A **clip** (e.g. 40 s out of 12 h) verifies on its own, without the source footage.
3. Sealed data **cannot be played without passing verification** (verify-to-open).
4. Corruption is **repaired** from parity (RAID-6/ZFS style), and **reported separately from tampering**.
5. Evidence stays verifiable for **decades**: post-quantum signatures, timestamps, re-sealing.

**First target: Mode A.** Seal footage at the moment of collection, from any DVR/NVR export.
- Mode B (seal on the NVR as it writes) and Mode C (seal on the camera) come later.
- The architecture must allow streaming input so Mode B is a drop-in later.

**Positioning.** Axis Signed Video and ONVIF Media Signing already sign per GOP, using classical crypto in SEI frames. Post-quantum signed video has also been presented. Our novelty is the evidence workflow:
- legacy DVR coverage (Mode A)
- strip-proof verify-to-open sealing
- standalone clips (redaction comes later)
- corruption repair
- decades-long validity
- disaster-recovery profile

## 2. Core protocol — do not change without discussion

### Notation

| Symbol | Meaning |
|---|---|
| `S_i` | bytes of segment *i* (see §9.1 for segmentation) |
| `R_i` | content hash of `S_i` = `H1(S_i) ‖ H2(S_i)` (default SHA-256 ‖ SHA3-256) |
| `C_i` | chain value |
| `rid` | random 256-bit recording id |
| `Hc` | chain hash (default SHA3-256) |

### Sealing

Steps for each segment *i*:

1. `R_i = H1(S_i) ‖ H2(S_i)`
2. `C_0 = Hc("evseal-v1" ‖ rid ‖ profile_hash)`; `C_i = Hc(i ‖ R_i ‖ C_{i-1})`
3. **Signed block** every `N` segments (`sign.block_segments`, default 1):
   `σ = Sign_eph(rid ‖ i_start ‖ i_end ‖ [R_i…] ‖ [C_i…])`.
   Every `R_i` and `C_i` is stored and covered by a signature. A damaged segment therefore never breaks verification of later segments, because the chain is checked against *signed* `C_{i-1}` and is never recomputed across damage.
4. **Verify-to-open sealing (key idea).**
   - `(K_i, n_i) = HKDF(ikm=C_i, salt=rid, info="evseal-seg" ‖ i)`
   - `E_i = AEAD(K_i, n_i, S_i, aad = rid ‖ i)`
   - The key is derivable only from the *signed* chain value, so data can't be opened without first verifying.
   - This is **not confidentiality**: `C_i` is in the manifest. Confidentiality comes from the outer layer (§3.3).
   - The opaque bytes also stop platforms from re-encoding.
5. **Checkpoint** every `checkpoint.interval_s`. Sign `(rid, i, C_i, count)` with the checkpoint algorithm (default SLH-DSA-SHA2-128s), attach timestamp token(s), and append `C_i` to the anchor log (hashes only, never content).
6. **Final seal** at end. Sign `(rid, n, C_n, H(original input file))`.
   - If the final seal is missing, report `UNSEALED_TAIL` after the last checkpoint. Never silently accept a truncated tail.
7. **Key hierarchy and rotation.**
   - A long-term collector/device key certifies an ephemeral signing key for each `keys.rotation_s` period.
   - The ephemeral private key is securely deleted at period end (forward security).
   - Certificates are stored in the manifest.
8. **Gap records.** Unreadable or dropped input produces a signed `GAP(i_start, i_end, reason)` record. A gap is evidence, not silence.

Stage 1 (hashing) and stage 3 (signing + encryption) run in parallel. Only the chain fold is sequential, and it costs about 64 bytes of hashing per segment.

### Verification and opening order (fail closed)

1. Validate the certificate chain and algorithm policy. Reject any algorithm not on the verifier's allow-list. The profile is inside the signed manifest, so downgrade attempts are caught.
2. Verify the block signatures, checkpoints, timestamps and final seal.
3. For each segment:
   1. Derive `K_i` from the signed `C_i`.
   2. AEAD-decrypt.
   3. Recompute `R_i`.
   4. Check `C_i = Hc(i ‖ R_i ‖ C_{i-1})` using the signed `C_{i-1}`.
4. Classify each segment:

| Status | Condition | Meaning |
|---|---|---|
| `VERIFIED` | all checks pass | original |
| `REPAIRED` | rebuilt from parity, then all checks pass | original, recovered |
| `CORRUPT` | AEAD tag fails, unrecoverable | random damage (or crude edit) |
| `TAMPERED` | tag passes but `R_i` mismatches signed value | deliberate re-encryption with derived key |
| `SEQUENCE_ERROR` | chain/index check fails | deleted, inserted or reordered |
| `GAP_DECLARED` | signed gap record | documented loss |
| `UNSEALED_TAIL` | after last checkpoint, no final seal | truncation risk |

A recording is `VERIFIED` overall only if every segment is `VERIFIED` or `REPAIRED`. Otherwise the report lists exactly which segments failed and why.

### Clip package

A clip contains:
- segments `i..j` (sealed)
- signed `C_{i-1}`
- the signed records covering `i..j`
- the certificates
- the nearest checkpoints

It verifies and opens with no access to the source.

## 3. Resilience

### 3.1 Erasure coding (RAID-6 / ZFS model)

- **Stripe** = `ec.k` sealed segments plus `ec.m` parity shards (zfec). Default is 10+2, about 20% overhead. Any `m` bad shards per stripe can be rebuilt.
- **Signed `R_i` locate bad shards.** That makes faults *erasures*, so Reed–Solomon gets its full capacity of `m`, not `m/2`.
- **Interleaving depth `ec.interleave`.** Stripe members are spread apart (`j, j+D, j+2D…`) so a burst (a bad disk region) hits each stripe at most once.
- Segments have variable sizes. Pad each stripe to its longest member and record the true lengths.
- A rebuilt segment is accepted **only** if it matches its signed `R_i`.
- **Overhead vs. industry baselines:** 3× replication +200% (rejected, too expensive); RAID-6 on an 8-disk NVR +33% (covers disk failure only — not silent bit-rot); Backblaze 17+3 ≈ +18%; Azure LRC 12+2+2 ≈ +33%. Our RS 10+2 (+20%) / 20+2 (+10%) is competitive, and unlike plain RAID it locates the bad segment via the signed `R_i` before repairing it. If the NVR already runs RAID 6, that covers disk failure; our parity targets bit-rot and export copies (USB, DVD) that have no RAID.

### 3.2 Manifest protection

The manifest is tiny (~1% of video) but irreplaceable, because the ephemeral keys are deleted. Store it:
- inside the stripes (parity-protected), and
- as an embedded copy at the bundle end.

The hourly anchors in the external log are the last line of defense: they prove what existed even if every copy is lost.

### 3.3 Disaster-recovery profile (India government setting)

1. **Outer layer (optional).** A random DEK is wrapped to custodian public keys with ML-KEM-768/1024 (e.g. FSL, court). The bundle is then encrypted with AES-256-GCM. This provides real confidentiality.
2. **Geo-split.** Split into `dr.n_sites` fragments, any `dr.k_sites` of which recover the bundle. The default 2-of-3 means +50% storage, versus +100% for a mirror.
3. **Sites stay inside government facilities.** Examples: state data centre, an NIC centre in another city, the FSL/court vault. Choosing and operating sites is out of scope; the format, procedure and tests are in scope.
4. **Sites are untrusted.** No site can read its fragment or alter it without detection.
5. **Custody records.** Every copy, repair or transfer appends a signed, chained custody record.

### 3.4 Re-sealing (decades)

`reseal` takes the current manifest, including all old signatures and timestamps, and signs and timestamps it again with current algorithms. This follows the RFC 4998 evidence-record idea. Run it on schedule or whenever an algorithm is deprecated.

## 4. Configuration — everything is a knob

All parameters live in a **profile** (TOML). The UI edits profiles. The profile used for sealing is embedded in the signed manifest, so verification always uses the sealed settings. No algorithm choice may be hardcoded outside the crypto backend registry.

| Group | Key | Default | Options / range |
|---|---|---|---|
| Segmenting | `segment.duration_s` | 1 | 0.5–10; actual cuts land on keyframes, actual lengths recorded |
| | `segment.mode` | byte-range | byte-range (bit-exact) · remux (see §9.1) |
| Hashing | `hash.content` | [sha256, sha3-256] | any of sha256, sha512, sha3-256, sha3-512, blake2b; warn if only 1 family |
| | `hash.chain` | sha3-256 | sha256, sha3-256, sha3-512 |
| Signatures | `sign.alg` | ML-DSA-44 | ML-DSA-44/65/87, SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}, hybrid Ed25519+ML-DSA, Ed25519 (baseline only, flagged NON-PQ) |
| | `sign.block_segments` | 1 | 1–3600 (60 = per-minute signing) |
| Keys | `keys.root_alg` | ML-DSA-87 | any PQ signature alg |
| | `keys.rotation_s` | 3600 | 60–86400 |
| Checkpoints | `checkpoint.interval_s` | 3600 | 60–86400 |
| | `checkpoint.alg` | SLH-DSA-SHA2-128s | any signature alg |
| Time | `timestamps.tsa_urls` | [] (local test TSA in dev) | RFC 3161 endpoints |
| | `anchors.backend` | local-log | local-log · off |
| Encryption | `aead.alg` | AES-256-GCM | AES-256-GCM · ChaCha20-Poly1305 |
| | `kdf.alg` | HKDF-SHA256 | HKDF-SHA256 · HKDF-SHA3-256 |
| Erasure coding | `ec.k`, `ec.m` | 10, 2 | k 2–64, m 0–16 |
| | `ec.interleave` | 60 | 1–3600 |
| DR | `outer.enabled`, `outer.kem` | false, ML-KEM-768 | ML-KEM-512/768/1024 |
| | `dr.k_sites`, `dr.n_sites` | 2, 3 | k ≤ n ≤ 16 |
| Performance | `parallel.workers` | auto | 1–N cores |

**Presets:**
- **Court-grade:** the defaults.
- **Low-storage:** `sign.block_segments=60`, `ec` 20+2.
- **Max-security:** ML-DSA-87, dual hash with SHA3-512, `ec` 10+4.
- **IoT/ultra-light:** later; HMAC ratchet on camera, PQ signing at the gateway.

**Live estimates** (shown in the UI, computed from formulas):
- storage overhead %
- signatures per day
- "survives m bad segments per stripe, bursts up to D"
- estimated seal time for a given footage length and core count

Reference figures from the design session, which the benchmarks must confirm or correct:
- About 2.5 KB/s overhead with per-second ML-DSA-44, roughly 1% of 2 Mbps video.
- Per-minute signing gives about 0.07%.
- 12 h of footage needs roughly 10–20 s of crypto on 8 cores; disk-bound in practice.
- Per-primitive breakdown (12h, 8-core laptop, to confirm in benchmark): disk read 20s (NVMe) to 5min (USB 2 export drive); dual hashing ~5s; chain fold milliseconds; 43,200 ML-DSA-44 signatures ~1–2s; AES-256-GCM <1s; 12 SLH-DSA checkpoints a few seconds total.
- 30-day retention on ~650 GB video: +6.6 GB with per-second signing, or +0.45 GB with per-minute signing.
- H.265 at ~1 Mbps roughly halves the video, so overhead % roughly doubles (~2% per-second signing).

## 5. Architecture

Python 3.12, one package, and minimal dependencies.

```
evseal/
  core/        segment.py  hashing.py  chain.py  kdf.py  aead.py
               crypto.py      # registry: keygen/sign/verify/kem per alg name (liboqs + cryptography)
               manifest.py    # JSON, canonical (RFC 8785 JCS) bytes for signing
               seal.py        # 3-stage pipeline, ProcessPoolExecutor
               verify.py      # returns Report{overall, per-segment statuses, evidence}
               clip.py  open.py
  resilience/  ec.py (zfec + interleave)  repair.py
  longterm/    keys.py (root, ephemeral certs, rotation, secure delete)
               checkpoint.py  timestamps.py (RFC 3161 client + local test TSA)
               anchorlog.py (append-only Merkle log)  reseal.py
  dr/          outer.py (ML-KEM wrap)  split.py (k-of-n fragments)  custody.py
  cli.py       # typer: keygen seal verify open clip repair reseal dr-split dr-recover bench stress
  api/         # FastAPI; long jobs with progress over SSE
  ui/          # web frontend
  stresslab/   # attack + fault scenarios, runner, expected-results matrix
  bench/       # parameter sweeps, synthetic footage generator
tests/
```

**Bundle layout:**
- A directory: `manifest.json`, `segments/000000.seg …`, `parity/`, `certs/`, `anchors/`, `custody.log`.
- Or a single `.evseal` file (zip, stored mode) for transport.

**Dependencies:**
- `liboqs` + `liboqs-python` (ML-DSA, SLH-DSA, ML-KEM)
- `cryptography` (AEAD, HKDF, Ed25519)
- `zfec`
- `typer`, `fastapi`, `uvicorn`
- `pytest`, `hypothesis`, `atheris` (fuzzing)
- `ffmpeg`/`ffprobe` on PATH

Note: `liboqs-python` needs the liboqs shared library built from source with cmake. Make that a setup step and fail clearly if it is missing.

## 6. UI — clean, all knobs reachable

The stack is FastAPI + React (Vite) + Tailwind. Use one accent colour, light/dark themes, and status shown as colour **plus** icon and text (never colour alone).

1. **Profiles.**
   - Grouped forms for every §4 parameter, with presets and validation.
   - Security badges per algorithm (PQ / hybrid / classical).
   - A live-estimates side panel. Profiles can be saved, duplicated and diffed.
2. **Keys.**
   - Generate root and collector keys, view certificates and the rotation log.
   - Show a dev-only warning for file-based private keys (HSM/TPM later).
3. **Seal.**
   - Choose input file(s) or folder, a profile and keys.
   - Show per-stage progress (hash ∥ / chain / sign+encrypt ∥ / parity).
   - Output a bundle.
4. **Verify (centerpiece).**
   - Overall verdict.
   - A **timeline strip**, one cell per segment, coloured by status, zoomable from 12 h down to 1 s.
   - Clicking a cell shows: hashes, signed record, key certificate, checkpoint, timestamp, and repair history.
   - Export the report as JSON (PDF court report later).
5. **Clip & Open.** Select a range on the timeline, export a standalone clip, then open it to the restored file plus a playable preview.
6. **Repair.** Show damaged segments with their stripes and a repair plan, run the repair, then re-verify.
7. **Stress Lab.**
   - Pick scenarios and their parameters (bit-rot rate, burst length, shards lost, sites lost, attacks) and one or more profiles.
   - Run the matrix and show expected versus actual results, highlighting mismatches.
8. **Benchmarks.** Parameter-sweep charts: throughput, overhead %, CPU and RAM against segment duration, algorithm, block size, k/m and workers.

## 7. Stress-testing plan

Each scenario has an **expected verdict** in `stresslab/expected.toml`. A mismatch is a bug. Use seeded randomness and record the seed in every result.

**A. Correctness**
- seal → open gives a bit-exact original
- a clip verifies and opens standalone
- an opened clip plays (ffprobe check)

**B. Attacks** (expected result in brackets)

| # | Attack | Expected |
|---|---|---|
| 1 | flip a bit in segment *i* ciphertext | `CORRUPT` at *i* (or `REPAIRED` with parity) |
| 2 | decrypt with derived key, edit frames, re-encrypt | `TAMPERED` at *i* only |
| 3 | swap in a segment from another recording | `TAMPERED` / `SEQUENCE_ERROR` at *i* |
| 4 | delete segment(s) | `SEQUENCE_ERROR` at the gap |
| 5 | insert a segment | `SEQUENCE_ERROR` |
| 6 | reorder segments | `SEQUENCE_ERROR` |
| 7 | truncate the tail before the final seal | `UNSEALED_TAIL` / count mismatch |
| 8 | strip manifest or signatures | REJECT, never "unsigned but OK" |
| 9 | edit the profile in the manifest (algorithm downgrade) | signature fail / policy reject |
| 10 | re-seal everything with an attacker key | certificate chain fail |
| 11 | sign period *q* with leaked ephemeral key of period *p* | reject (validity window) |
| 12 | replay a valid block signature at another index | reject (bound to `rid` and index) |
| 13 | backdated timestamp outside key validity | flag |
| 14 | clip with forged boundary `C_{i-1}` | fail |

**C. Faults**
- random bit-rot at 1e-9 to 1e-5
- bursts of length L for several interleave depths D
- lose 0…m+1 shards per stripe: exactly m must repair, m+1 must fail cleanly as `CORRUPT` with no false `VERIFIED`
- lose manifest copies
- lose 1…n DR sites
- `kill -9` at random points during seal: the partial bundle must verify up to the last durable record (fsync per record batch) and report `UNSEALED_TAIL`

**D. Properties** (Hypothesis), over random profiles and random edits:
- a modified segment is never `VERIFIED`
- untouched data never fails

**E. Fuzzing** (atheris). The manifest parser and bundle reader are trust boundaries.

**F. Performance**
- Synthetic footage: `ffmpeg testsrc2` + noise; H.264 and H.265; 2 and 4 Mbps; 10 min, 1 h and 12 h.
- Sweeps over §4 parameters. Measure throughput, CPU, RAM and overhead %, and compare against the §4 reference estimates.
- Raspberry Pi 4 run later.

CI runs A, B and a fast subset of C and D. The full matrix runs from Stress Lab or `evseal stress --full`.

## 8. Build phases

For every phase: plan, get approval, implement, get tests green, then write a short summary of deviations.

| Phase | Scope | Done when |
|---|---|---|
| P0 | Environment: liboqs build, deps, ffmpeg check, `evseal doctor` command | doctor lists ML-DSA, SLH-DSA, ML-KEM available |
| P1 | Spike §9.1 on MP4, TS, raw H.264 and one DVR proprietary sample; core seal/verify/open/clip CLI; manifest; profiles | tests A + attacks 1–8 pass |
| P2 | Erasure coding, interleave, manifest protection, repair, corruption-vs-tamper classification | fault tests C pass, including m vs m+1 |
| P3 | Key rotation, checkpoints, RFC 3161 + local TSA, anchor log, final seal, reseal | attacks 9–14 pass |
| P4 | API + UI: Profiles, Keys, Seal, Verify timeline, Clip & Open, Repair | full flow usable from UI |
| P5 | Stress Lab + Benchmarks UI, Hypothesis properties, fuzzing | expected-vs-actual matrix all green |
| P6 | DR profile: ML-KEM outer layer, k-of-n geo-split, custody log | site-loss tests pass |

**Later:**
- tile-level redaction proofs (Merkle over tiles inside each segment)
- court verification report (Section 63 BSA annexure)
- Mode B NVR live ingest
- ultra-light camera mode (hash + chain + ratcheting HMAC on device, PQ signing at gateway)
- ONVIF Media Signing interop (verify existing SEI signatures, add PQ layer)
- Raspberry Pi / ESP32 benchmarks

## 9. Open decisions and known limits

### 9.1 Segmentation vs bit-exact restore (decide in the P1 spike)

The key idea requires that opening restores the original file. Recommended default:
- **Byte-range segments of the original file**, cut at packet boundaries found with `ffprobe -show_packets` (pos + pts), targeting `segment.duration_s`. Concatenating the opened segments gives the bit-exact original.
- **Container header/index chunks** (e.g. MP4 `ftyp`/`moov`) are flagged and included in every clip, so a clip can be remuxed for playback.
- **Fallback `remux` mode:** stream-copy into independent TS segments. Frames stay bit-identical but the container is new. The whole original file's hash is still sealed in the final seal.

### 9.2 Known limits

- **Mode A** proves integrity from collection onward only. Edits made before seizure are out of reach.
- **No confidentiality without the outer layer.** Convergent keys are derivable from signed hashes.
- **Segment length follows the camera's GOP.** Long-GOP cameras give longer segments.
- **liboqs is a research library.** Swap in validated implementations via the crypto registry when available.
- **Dev private keys are file-based.** HSM/TPM support comes later.

## 10. Requirements recovered from the design discussion

These came up in the conversation and must not be lost.

- **Reproducible transcoding for derived copies.** When a playback or working copy is transcoded:
  - Record the encoder, its version and the exact deterministic settings (e.g. x264 single-threaded with fixed params).
  - Sign a derivation record (source segment range → output hash).
  - The verifier re-runs the transcode from the sealed original and compares bit-exactly.

  This solves re-encoding without trusting the transcoder. Schedule it after P3.
- **Repair from replicas.** Repair may pull a segment from any other copy (replica, export drive, DR fragment) and accepts it only if it matches the signed `R_i`. Good segments from several damaged copies can be combined.
- **AEAD chunk granularity knob** `aead.chunk = segment | frame`. Per-frame chunks mean one bad bit loses a frame, not a whole segment.
- **Key revocation records** are appended to the custody/anchor log. The verifier checks revocation status against signing time.
- **Offline operation.** If no TSA or log is reachable, queue checkpoint anchors and submit them on reconnect. The verifier reports the anchor delay.
- **Independent verifiability for decades.**
  - Publish an open, documented bundle format.
  - Provide a separable minimal-dependency reference verifier (`evseal-verify`), so a defence expert can verify without our UI or the original authors.
  - The seal path never re-encodes; the original bitstream is preserved.
- **Legacy acquisition hashes.** If the input arrives with an MD5/SHA-1 acquisition hash, record and check it, but flag those algorithms as classically broken. Never use them inside the protocol.
- **Large-archive EC mode** (later): two-level local + global parity, Azure LRC style.
- **Ultra-light camera mode** (later):
  - The camera computes hash + chain + `Tag_i = HMAC(K_i, C_i)`, then ratchets `K_{i+1} = H(K_i)` and deletes `K_i`.
  - The gateway verifies the tags, then adds PQ signatures (per minute), checkpoints and encryption.
  - `K_0` is escrowed with a neutral authority (court/FSL) at install, so tags are independently checkable.
  - This is based on Schneier–Kelsey forward-secure logging.
- **IoT performance rules:**
  - hash the encoded bitstream or slices, never raw decoded pixels
  - never run SLH-DSA on the camera
  - camera/gateway split as in the design session
  - ML-DSA-44 signing takes ms-range time on Cortex-A class hardware, tens of ms on ESP32/Cortex-M class — still fits a 1-second budget, but tune checkpoint frequency down on the smallest MCUs

## 11. Alternatives considered and rejected

Don't re-propose these without a new reason.

| Rejected | Why | Chosen instead |
|---|---|---|
| Quantum hash functions (quantum fingerprinting, quantum-walk hashes) | Quantum states can't be copied or stored; unstandardized | Classical dual hashes |
| Merkle tree across seconds | User decision: hash list + chain is enough | Signed chain; Merkle only *inside* a segment for tiles |
| Signing only the final / whole-file hash | Power cuts leave footage unsigned; damage cascades | Sign every `R_i` and `C_i`, plus a final seal |
| Hash-derived key without signature check | Attacker re-seals edited content consistently | Verify signature before deriving the key |
| Hash-derived key as confidentiality | Key is effectively public | Outer ML-KEM layer |
| 3× replication | Too expensive | Reed–Solomon stripes + interleave (+10–20%) |
| Stateful LMS/XMSS as main signature | State reuse risk on power loss | ML-DSA + key rotation; SLH-DSA for checkpoints |
| Reversible watermarking | Doesn't survive re-encoding | Not used. A robust watermark + vault lookup is a possible future add-on for re-encoded copies |
| DES | Broken | AES-256 (also matches India's AES-128→256 guidance) |

## 12. Research framing (for the paper)

**Prior art to position against:**
- Axis Signed Video (2021, open source) and ONVIF Media Signing (final spec expected end-2026) — classical, per-GOP signatures in SEI frames; Axis's own documentation acknowledges that dropping SEI frames silently strips the signature
- C2PA (classical; ML-DSA C2PA-style packages exist)
- PKI Consortium PQC Conference 2025 talk on PQ-signed video
- Ampex 2026 video attestation paper
- PQ evidence-layer / audit-log papers (2025)
- Blockchain custody (Kinesense, Hyperledger IoT research)
- Post-hoc authentication (Amped Authenticate PRNU/GOP analysis, ENF)
- SWGDE/NIST acquisition practice
- Schneier–Kelsey secure logging
- RFC 4998

**Contribution claims:**
- PQ per-segment sealing of **legacy DVR footage at collection**
- **Strip-proof verify-to-open** sealing
- Non-cascading signed chain with **standalone clips**
- **Corruption-vs-tampering** classification with erasure-coded repair
- Decades-long validity: checkpoints, rotation, re-sealing
- Government DR profile
- Measured overheads and stress results

**India context:** DST PQC migration roadmap — critical information infrastructure by 2029, broader adoption by 2033, cryptographic asset inventory and risk assessment due by end of 2026. CERT-In CBOM/QBOM guidelines (July 2025), BSA Section 63 certificates.

## 13. Parked ideas from the same research session (not EviSeal scope)

These came from the research discussion before EviSeal was chosen. Status matters — don't re-propose a rejected idea without a new reason, and don't treat a rejected idea as still open.

### Recommended for a future paper/tool (genuinely open, not pursued elsewhere)

- **PQ key memory forensics.** Scan process memory for intact ML-KEM decapsulation keys using the FIPS 203 structure `dk = dk_PKE ‖ ek ‖ H(ek) ‖ z` — the 32-byte hash just before `z` is a near-zero-false-positive signature. Study how OpenSSL 3.5, liboqs, BoringSSL, and Go's `crypto/mlkem` actually hold keys (Go keeps only a 64-byte seed — no scannable structure, a genuine negative result worth stating). Research core: recovering keys from decayed/partial memory (small lattice coefficients make error correction possible — cf. Albrecht et al. 2018 on cold-boot attacks on NTT-form lattice keys, not yet applied as forensic recovery) and recovering hybrid TLS session secrets to decrypt captured traffic. Deliverable: a Volatility 3 plugin. Target venue: DFRWS.
- **Client-side forensics of quantum cloud SDKs.** Catalogue what Qiskit, Braket, and PennyLane leave on disk/in memory: saved API tokens (e.g. `~/.qiskit/qiskit-ibm.json`), cached job IDs, circuit files, logs — "browser forensics, applied to quantum SDKs." Goal: attribute usage to a person and reconstruct which jobs ran. Workshop-level depth; current investigative demand is low, but no one has done it first.
- **Quantum cryptanalysis circuit forensics.** Three sub-problems: (1) detection — is a submitted circuit cryptanalysis or benign chemistry/optimization work; (2) victim attribution — recover the target RSA modulus N or EC public key from a Shor/ECDLP circuit; (3) robustness — do both after transpilation, which scrambles the clean arithmetic via SWAP insertion, rotation merging, and optimization (core technical contribution: recognize Toffoli-style gate patterns post-transpilation, e.g. via a graph neural network on the gate graph). Value: export-control job screening, victim notification once harvest-now-decrypt-later data starts getting decrypted. Positions against existing IP-theft/Trojan-detection work (different goal: victim identity, not code theft).
- **AI agent forensics.** Two parts: (1) a forensic-readiness spec for agent/MCP runtimes with tamper-evident, hash-chained, signed records (this project's PQ signature design fits directly here for long retention); (2) counterfactual attribution — replay the same logged context N times (handles non-determinism), remove one input at a time, and find which removal collapses the harmful-action rate. Worked example: a user asks to summarize 3 emails; the agent forwards an attachment. Replay 20× with all 3 emails: 17/20 forward. Remove email C: 0/20 forward → C is the cause; repeat sentence-by-sentence inside C to isolate the injected instruction. Open problems: causes that only trigger in combination, replay cost scaling with context length, and model updates breaking replay entirely — which is why logging must capture model version, sampling settings, and full context as a hard requirement, not an afterthought.

### Liked but deprioritized ("more useful for current" need won out)

- **QSentry — quantum job security gateway.** Four modules: (1) compiler-integrity check — equivalence-check pre/post-transpilation circuits via MQT QCEC, producing a signed compilation receipt (deterministic, no ML guesswork, unlike published Trojan-detection classifiers at 66–98.8% accuracy); (2) misuse detection for Shor/ECDLP/Grover-vs-hash circuits, extracting the targeted key where possible; (3) multi-tenant abuse rules (dense repeated CNOTs aimed at inducing crosstalk on co-located users, reset-and-measure state-leakage probes); (4) tamper-evident, ML-DSA-signed audit log of every job. Output as SARIF for native GitLab/GitHub code-scanning integration. Honest risks: equivalence checking slows on very large circuits (fall back to randomized-input simulation testing beyond that point); misuse rules are evadable via circuit obfuscation (positioned like antivirus signatures — raises attacker cost, doesn't guarantee detection).
- **CBOM/QBOM generator for binaries and firmware.** One tool, shared engine, two output modes. CBOM mode: 5-layer pipeline — extraction (unblob/binwalk), library fingerprinting (OpenSSL/mbedTLS/wolfSSL/BoringSSL + version), crypto-constant scanning (AES S-box, SHA-2 round constants, EC params P-256/Curve25519/secp256k1, RSA bignum routines, PQC constants Kyber q=3329 + NTT tables, Dilithium q=8380417), embedded key/cert extraction, config parsing (sshd_config, openssl.cnf). Output: CycloneDX 1.6 (native crypto-asset types) + SARIF; each finding rated quantum-vulnerable/weakened/safe against CERT-In's CBOM fields; diff mode compares two firmware versions to verify a vendor's "now post-quantum" claim. QBOM mode: schema mapping CERT-In's QBOM fields (device model/version/vendor-origin, comms protocols, hardware, software deps/SDKs/firmware, energy/environmental impact, known vulnerabilities, signature attestation) to CycloneDX; a quantum-software generator scanning Qiskit/PennyLane/Cirq/Braket repos for SDK versions, CVEs, exposed API tokens, backend configs, PQC library use; a validator that checks a vendor QBOM against required fields, verifies its ML-DSA signature, and runs NIST SP 800-22/800-90B statistical tests against sampled QRNG output to independently test randomness claims. Context: government/public-sector/essential-services bodies will be required to demand a QBOM on quantum-system procurement — CBOM serves today's universal RSA/ECC-inventory need, QBOM is the unclaimed, narrower, government-facing half.

### Explicitly rejected (don't re-propose without a new reason)

- **Fourier-based exact SHAP for parameterized quantum circuits** (exact Shapley values via Schuld et al.'s Fourier-series structure of angle-encoded circuits, analogous to TreeSHAP). Rejected: *"Nah I want to build something not just apply and analyse why it happened."*
- **Quantum ML for forensic classification** (malware/image/anomaly classification via quantum models). Rejected twice: crowded field, no demonstrated quantum advantage over classical baselines on simulators.
- **Quantum search for evidence** (Grover-accelerated search over forensic data). Rejected: loading real data into a quantum state wipes out Grover's speedup; a simulator study would only reproduce a known negative result.

### Open, undecided (not pursued, not rejected — needs resources this project doesn't have)

- **Harvest-now-decrypt-later (HNDL) risk assessment.** Assessing which already-captured/archived traffic is exposed to future decryption once a cryptographically relevant quantum computer exists — closer to risk assessment than forensics; distinct from the PQ-TLS readiness census (which measures *current* negotiated algorithms, not *past* captured traffic).
- **QKD / quantum-network forensic readiness.** What can be logged from QKD/quantum-network devices without undermining their security, and how to validate device state/events while respecting privacy. Blocked on real QKD hardware access — simulated results wouldn't be credible.
- **PQ-TLS readiness census of `.gov.in`/`.nic.in`.** Scan public endpoints for hybrid key exchange (`X25519MLKEM768`), TLS versions, cert algorithms, key sizes — a measurement study with no exploitation, repeatable annually, ideally coordinated with CERT-In before publishing.
