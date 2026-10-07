# EviSeal

Post-quantum sealed multimedia evidence. EviSeal seals video, audio and image sets so that any edit, deletion, insertion or reordering is **detected and localized**, damaged data is **repaired from parity**, and the evidence stays **verifiable for decades**.

> Status: research prototype (v0.1). Not a certified forensic product. See [Known limitations](#known-limitations).

## What it does

1. **Tamper detection, localized.** Media is cut into *units* (a time segment for video/audio, one image in an ordered set). Each unit has a dual content hash, chained to the previous unit, and signed. A verifier reports exactly which unit failed and why.
2. **Standalone clips.** A clip (or a sub-range of an image set) verifies on its own, with no access to the source recording.
3. **Verify-to-open.** Units are AEAD-encrypted under a key derived from the *signed* chain value, so sealed data cannot be played or opened without passing verification. This is integrity enforcement, not confidentiality.
4. **Repair vs. tamper.** Reed-Solomon parity (RAID-6 / ZFS style) rebuilds bit-rot and bad sectors. Signed hashes locate bad shards, so faults are erasures. A repaired unit is accepted only if it matches its signed hash. Corruption is reported separately from tampering.
5. **Tile-level image localization.** Images are sealed as a Merkle tree of tiles (JPEG DCT coefficients, or raw pixels), so an edit is pinned to a region, with a heatmap. Perceptual hashing is advisory only and never overrides a cryptographic verdict.
6. **Long-term validity.** Post-quantum signatures (ML-DSA, SLH-DSA), RFC 3161 timestamps, forward-secure key rotation, signed checkpoints, and re-sealing (RFC 4998-style) when algorithms age.
7. **Disaster recovery.** Optional ML-KEM-wrapped outer encryption and k-of-n geo-split across untrusted sites, with signed chain-of-custody records.
8. **Access control.** Key-based login, five roles (admin, collector, examiner, custodian, auditor), a signed hash-chained user directory, and a signed access log.

## Protocol in one screen

For unit `S_i`:

```
R_i = H1(S_i) || H2(S_i)                    default SHA-256 || SHA3-256
C_0 = Hc("evseal-v1" || rid || profile_hash)
C_i = Hc(i || R_i || C_{i-1})               default SHA3-256
sigma = Sign_eph(rid || i_start || i_end || [R_i] || [C_i] || timing)
(K_i, n_i) = HKDF(ikm = C_i, salt = rid, info = "evseal-unit" || i)
E_i = AEAD(K_i, n_i, S_i, aad = rid || i)
```

Every `R_i` and `C_i` is signed, so one damaged unit never breaks verification of later units. Periodic checkpoints (SLH-DSA by default) and a final seal over the whole input close the recording; a missing final seal is reported as `UNSEALED_TAIL`, never silently accepted. Unreadable input produces a signed `GAP` record. The full specification is in [SPEC.md](SPEC.md).

### Verdicts

| Status | Meaning |
|---|---|
| `VERIFIED` | all checks pass, original |
| `REPAIRED` | rebuilt from parity, then all checks pass |
| `CORRUPT` | AEAD tag fails, beyond parity (random damage) |
| `TAMPERED` | decrypts cleanly but hash differs from signed value |
| `SEQUENCE_ERROR` | chain/index mismatch: deleted, inserted or reordered |
| `GAP_DECLARED` | documented, signed loss |
| `UNSEALED_TAIL` | no final seal after the last checkpoint |

A recording is `VERIFIED` only if every unit is `VERIFIED` or `REPAIRED`. Verification fails closed: any failed or skipped check is not `VERIFIED`.

## Repository layout

```
evseal/
  core/         protocol: crypto registry, profile, hashing, chain, seal, verify, open, clip, tile Merkle
  media/        format-specific segmentation (video, audio, image, transcode); never inside core/
  resilience/   Reed-Solomon erasure coding and repair (zfec)
  longterm/     key rotation, RFC 3161 timestamps, anchor log, re-sealing
  dr/           ML-KEM outer layer, k-of-n geo-split, custody log
  stresslab/    seeded fault-injection / attack scenarios with expected verdicts (expected.toml)
  bench/        benchmark sweeps and synthetic media
  api/          FastAPI service (auth, roles)
  ui/           React + Vite front end
  access.py     users, roles, signed directory and access log
  report.py     court report / BSA s.63 draft
  cli.py        `evseal` CLI;  verify_cli.py  `evseal-verify`
tests/          unit, property, fuzz (Atheris), e2e API and stress-matrix tests
SPEC.md         source of truth for the protocol
DEVIATIONS.md   known deviations from the spec and their status
FINDINGS.md     failure-mode and admissibility audit
```

`core/verify.py` imports nothing from the API or UI. It is the standalone reference verifier behind `evseal-verify`, so a defence expert can check a bundle without the rest of the tool.

## Install

Requires Python 3.12. The project uses [pixi](https://pixi.sh) for the environment (Python, ffmpeg, cmake, and Python dependencies).

```bash
pixi install -e dev
```

Real post-quantum algorithms need native **liboqs**. Build it from source with cmake (WSL2 / Ubuntu is the primary dev and benchmark environment). Without it, EviSeal falls back to pure-Python `dilithium-py` / `kyber-py`, which is **dev-only**: slow, not timing-hardened, never to be used for real evidence. Sealing on the fallback is refused unless `EVSEAL_ALLOW_DEV_CRYPTO=1` is set.

Check your environment:

```bash
pixi run evseal doctor
```

This reports available liboqs algorithms, ffmpeg and zfec, and labels the fallback backend as dev-only.

## Quick start

```bash
# create a root key (ML-DSA-87 by default)
evseal keygen collector1

# seal a recording (presets: court-grade, low-storage, max-security, or a TOML profile)
evseal seal footage.mp4 footage.evseal --key collector1 --profile court-grade

# verify; exit status reflects the verdict
evseal verify footage.evseal

# export a self-verifying clip of units 10..20
evseal clip footage.evseal clip.evseal --start 10 --end 20

# open (decrypt) the sealed data. Only works for verified units.
evseal open footage.evseal footage-restored.mp4

# repair from parity or replica copies
evseal repair footage.evseal --replica /mnt/usb/footage.evseal

# court report (Markdown + JSON)
evseal report footage.evseal --out report.md

# standalone reference verifier, minimal dependencies
evseal-verify footage.evseal
```

Other commands: `reseal`, `compare` (check a loose copy against a sealed unit), `pack`, `stamp-queue` (flush offline timestamp requests), `dr-split` / `dr-recover`, `dr-wrap` / `dr-unwrap`, `user-init` / `user-add` / `user-role` / `user-revoke` / `users` / `access-log`, `stress`, `bench`, `serve`.

### Web UI and API

```bash
pixi run ui-build
pixi run serve          # http://127.0.0.1:8000, demo workspace in .evseal-demo
```

Pages: Seal, Verify, Clip/Open, Repair, Keys, Profiles, Audit, Stress Lab, Benchmarks, Doctor. The server refuses to run unauthenticated on a non-loopback address.

## Configuration

Every tunable lives in a **profile** (TOML) that is embedded in the signed manifest, so verification always uses the settings the bundle was sealed with, and downgrade attempts are caught. Algorithm names appear only in the crypto registry (`evseal/core/crypto.py`). Main knobs: segment duration and mode, image tile size, content/chain hash families, signature algorithm and block size, key rotation and checkpoint intervals, AEAD and KDF, erasure-coding `k`/`m`/interleave, and DR `k_sites`/`n_sites`. See SPEC.md section 4 for the full table.

## Testing

```bash
pixi run -e dev pytest              # fast set
pixi run -e dev pytest -m slow      # stress and benchmark tests
evseal stress                       # run the stress lab scenarios
```

Fault injection is seeded and the seed is recorded in results. Stress scenarios and their expected verdicts live in `evseal/stresslab/expected.toml`; a mismatch is a bug, not a flaky test. Fuzzing uses Atheris on Linux.

## Documents

- [SPEC.md](SPEC.md): protocol and requirements (source of truth)
- [DEVIATIONS.md](DEVIATIONS.md): deviations from the spec and their status
- [FINDINGS.md](FINDINGS.md): security, reliability and admissibility audit
- [CLAUDE.md](CLAUDE.md): working rules for AI-assisted development

## Known limitations

- **Mode A only.** EviSeal seals at collection time. It cannot detect edits made before the footage reached the sealer.
- **Dev-only fallback crypto.** Without native liboqs the pure-Python backend is slow and not side-channel hardened. Do not seal real evidence with it.
- **Keys are file-based.** Root keys can be passphrase-encrypted at rest, but there is no HSM/TPM-held key yet, so no hardware non-repudiation. Ephemeral key wiping in Python cannot guarantee removal from swap or core dumps.
- **Classical TSAs.** Public RFC 3161 timestamp authorities sign with RSA/ECDSA, which is not post-quantum. A post-quantum timestamp witness exists, but no PQ public TSA does.
- **No confidentiality by default.** Per-unit keys derive from signed values stored in the manifest; confidentiality needs the optional ML-KEM outer layer.
- **Storage overhead is high for low-bitrate sources.** Measured 108-252% on 0.5 Mbps synthetic TS (the spec estimated 10-20%), because each unit stores a fixed ~17 KB of signature and hash data. Larger `sign.block_segments` and `ec.k` reduce it; a binary manifest encoding is not done yet.
- **Loss beyond the parity budget is `CORRUPT`.** Repair cannot recover more than `m` bad shards per stripe.
- **Re-encoding is detectable, not preventable.** Cloud or DEMS pipelines that transcode media break byte-level verification (reported as `TAMPERED`/`CORRUPT` or via `compare`). Keep evidence in `.evseal` containers.
- **Perceptual hashing is advisory.** `LIKELY_EDITED` and `DERIVED_COPY` are heuristics (a simple 8x8 thumbnail hash), never cryptographic verdicts.
- **Court certificate needs a human.** The BSA s.63 / FRE 902 report is a draft; it requires a qualified custodian's signature.
- **Not independently audited.** liboqs is itself a research library, and this code has had no external security review.
- **Scope gaps.** Real DVR proprietary samples are untested; Mode B (seal on the NVR) and Mode C (seal on the camera), video-frame tiling and redaction are future work.
