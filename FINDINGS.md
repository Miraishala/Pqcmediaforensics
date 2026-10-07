# EviSeal Security, Reliability & Forensic Admissibility Audit (FINDINGS)
**Audit Timestamp:** 2026-10-07T01:55:00+05:30 (Asia/Kolkata)  
**System:** EviSeal (Post-Quantum Multimedia Evidence Sealer & Verifier)  
**Repository:** `D:\Projects\Pqcmediaforensics`  
**Reference Document:** SPEC.md (§1–§11), CLAUDE.md  

---

## 1. Executive Summary

EviSeal is designed to produce court-admissible, post-quantum sealed multimedia evidence across video, audio, and ordered image sets. Its core architecture combines:
1. **Hash Chaining & Dual-Hashing**: $C_i = H_c(i \parallel R_i \parallel C_{i-1})$ bound to an initial root context.
2. **Post-Quantum Digital Signatures & KEMs**: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and ML-KEM (FIPS 203) with hybrid classical (Ed25519) fallback.
3. **Forward Security & Resilient Ephemeral Key Rotation**: Periodic key rollover ($keys.rotation\_s$) and checkpoints.
4. **Resilience & Localization**: Reed–Solomon erasure coding ($k+m$), tile-Merkle tree decomposition, and advisory perceptual hashes.

This audit evaluates critical failure vectors across the entire evidence lifecycle:
- **Phase 1: Sealing** (acquisition, timing, process durability, bitstream ingestion)
- **Phase 2: Storing** (long-term preservation, parity exhaustion, cold storage, cloud migrations)
- **Phase 3: Proving** (forensic validation, cross-examination vulnerabilities, legal admissibility)

---

## 2. Sealing Failure Modes (Acquisition & Pipeline)

### 2.1 Time & Clock Anomalies
*   **Vector 1.1 — Clock Slew & Skew at Seal Time:**
    *   *Failure Mechanism:* If the host system clock drifts significantly between block seals, or jumps backward (e.g. NTP step synchronization, VM time rollback), the unit timestamp $t$ advances erratically. While $C_i$ relies strictly on monotonic unit indexing $i$, backward timestamps can trigger sanity failures in external playback engines or trip checkpoint timestamp constraints.
    *   *Forensic Impact:* Opposing counsel can argue clock manipulation or unreliable acquisition hardware.
    *   *Mitigation:* Derive unit timestamps directly from media presentation timestamps (PTS) where available, cross-checking host monotonic clocks (`time.monotonic_ns()`) against external TSA tokens.
*   **Vector 1.2 — TSA Unreachability & Network Partitions:**
    *   *Failure Mechanism:* If external RFC 3161 TSA URLs are unreachable during live sealing (e.g., body-cam in remote area or field recorder without uplink), sealing either blocks indefinitely or must queue timestamp requests.
    *   *Forensic Impact:* A delayed timestamp introduces a "window of suspicion" between recording completion and public notarization.
    *   *Mitigation:* Strict offline timestamp queueing (`anchors/queue.jsonl`) recording the synchronization delay, backed by local trusted hardware (TPM/secure element) attestation.

### 2.2 Media Demuxing & Bitstream Edge Cases
*   **Vector 2.1 — Variable Frame Rate (VFR) & Non-Monotonic DTS:**
    *   *Failure Mechanism:* Modern smartphone cameras frequently record VFR video where GOP lengths fluctuate unpredictably. If keyframe intervals exceed the target `segment.duration_s`, units grow disproportionately large, straining AEAD chunking and memory buffers.
    *   *Forensic Impact:* Uneven unit sizes increase vulnerability to burst packet loss.
    *   *Mitigation:* Dynamic adaptive chunking with upper bounds on unit byte-lengths.
*   **Vector 2.2 — Audio PES Straddling Cut Boundaries (Deviation D1):**
    *   *Failure Mechanism:* In MPEG-TS, cutting on video keyframes splits in-flight audio PES packets on separate PIDs. Bit-exact restore reproduces the full file, but standalone sub-clip playback can drop initial audio frames before the next sync header.
    *   *Forensic Impact:* Extracted video clips presented in court may experience audio stutter or missing words in the first 50–100 ms of a clipped statement.
    *   *Mitigation:* Implement PID/PUSI packet parser in `media/video.py` or use container-level `remux` mode for evidentiary sub-clips.
*   **Vector 2.3 — Mid-Stream SPS/PPS Parameter Set Changes:**
    *   *Failure Mechanism:* Surveillance systems (CCTV/DVR) frequently inject mid-stream SPS/PPS changes upon resolution or day/night infrared mode transitions. A standalone clip spanning across parameter set boundaries may fail playback without preceding parameter sets.
    *   *Mitigation:* Demuxers must capture and prepend out-of-band parameter sets into header units or clip metadata.

### 2.3 Host Crash, Power Loss & Memory Hygiene
*   **Vector 3.1 — Power Loss Mid-Block (Torn Tail Writes):**
    *   *Failure Mechanism:* Sudden power interruption during camera battery detachment. While `journal.jsonl` uses `os.fsync()` per batch, non-volatile cache reordering on low-grade flash media can corrupt the final partially written journal record.
    *   *Forensic Impact:* The tail of the recording is lost or marked `UNSEALED_TAIL`.
    *   *Mitigation:* Atomic write patterns (`write_atomic`) with double-buffered journal headers.
*   **Vector 3.2 — Ephemeral Key Remanence in Memory:**
    *   *Failure Mechanism:* `keys.KeyPair.wipe()` zeroes memory in Python bytearrays, but C-level allocations in `liboqs` or Python heap artifacts prior to zeroing may persist in operating system swap space or core dumps.
    *   *Forensic Impact:* Subpoena or forensic seizure of the recording device could recover supposedly wiped ephemeral keys, breaking forward security.
    *   *Mitigation:* Secure heap allocations via `mlock()`, disabling swap on recording appliances, or integrating hardware secure enclaves (TPM 2.0 / Apple Secure Enclave).

---

## 3. Storing Failure Modes (Preservation & Cold Archive)

### 3.1 Reed–Solomon Parity Budget Overshoot
*   **Vector 4.1 — Clustered Bit-Rot & Sector Decay:**
    *   *Failure Mechanism:* If media is archived on spinning disks or cold optical/flash media, sector degradation often occurs in clustered runs. If bit-rot destroys $> m$ shards within a single Reed–Solomon stripe, the stripe becomes unrecoverable.
    *   *Forensic Impact:* Verification drops from `VERIFIED` to `NOT_VERIFIED` with unit status `CORRUPT`.
    *   *Mitigation:* Stripe interleaving depth (`ec.interleave >= 2`) distributes adjacent unit damage across distinct stripes; multi-replica cross-bundle repair (`replicas` parameter) must be maintained in cold archives.
*   **Vector 4.2 — Multi-Copy Manifest Desynchronization:**
    *   *Failure Mechanism:* A bundle contains three layers of manifest protection: `manifest.json`, `manifest.copy.json`, and RS-encoded `manifest_rs`. If storage repair updates one copy but fails before updating others, hash mismatches occur.
    *   *Mitigation:* Atomic manifest replacement (`manifest.py:write_manifest`) and strict quorum rules during bundle verification.

### 3.2 Cloud Ingestion & Transcoding Tampering
*   **Vector 5.1 — Unannounced Cloud "Optimization":**
    *   *Failure Mechanism:* Cloud storage providers or evidence management systems (DEMS) often run automated pipelines that strip EXIF metadata, rotate images, recompress JPEGs, or re-encode MP4 containers to save bandwidth.
    *   *Forensic Impact:* Byte-level cryptographic checks fail (`TAMPERED` / `CORRUPT`). Although `compare_copy` can detect `RECOMPRESSED` or `METADATA_CHANGED`, the file loses its primary `VERIFIED` status.
    *   *Mitigation:* Evidence must always be stored in sealed `.evseal` container packages (ZIP stored mode) with cryptographic manifests preserved, rather than exposed as loose media files.
*   **Vector 5.2 — Long-Term Codec Obsolescence:**
    *   *Failure Mechanism:* 20 years in the future, post-quantum signatures verify bit-exact bytes, but proprietary DVR codecs or legacy container formats cannot be decoded by modern operating systems.
    *   *Forensic Impact:* Evidence is cryptographically authentic but visually unviewable.
    *   *Mitigation:* Implement reproducible transcoding (§10) with signed transformation manifests preserving the parent chain.

---

## 4. Proving & Admissibility Failure Modes (Legal & Forensic Scrutiny)

### 4.1 Cross-Examination Vulnerabilities
*   **Vector 6.1 — Unsigned Unit Timestamps ($t$ Metadata / Deviation D6):**
    *   *Vulnerability:* The unit presentation time $t$ in `manifest.json` is unsigned metadata. While the cryptographically signed block records cover $R_i$ and $C_i$, an attacker who can modify `manifest.json` could rewrite unit timestamps without invalidating block signatures.
    *   *Forensic Counter-Attack in Court:* A defense attorney will argue: *"The timestamp showing my client was at the scene was edited; your cryptographic hashes only prove the pixel content, not the time it was captured."*
    *   *Defense Defense:* Attack 11 demonstrates that signing period $p$ with a leaked key from period $q$ is rejected by the certificate validity window (`valid_from..valid_until`), NOT by $t$. Checkpoints and TSA tokens independently anchor the timeline.
    *   *Recommended Hardening:* Include $t$ in the signed `unit` hash payload or bind $t$ to $R_i$ in future protocol revisions (see SPEC amendment proposal).
*   **Vector 6.2 — Subjectivity of the Perceptual Hash Advisory Layer:**
    *   *Vulnerability:* The `thumb8` perceptual hash is advisory only (averaging an 8×8 RGB thumbnail). An opponent could argue that `LIKELY_EDITED` on an uncompressed or recompressed copy is a statistical heuristic with false positive rates.
    *   *Forensic Impact:* Confusion in front of a jury between absolute cryptographic certainty (`VERIFIED` vs `TAMPERED`) and advisory heuristics (`LIKELY_EDITED`).
    *   *Mitigation:* Clear visual separation in forensic reports and UI between cryptographic proofs (SHA3 / ML-DSA) and advisory perceptual metrics.

### 4.2 Legal Compliance & Jurisdictional Hurdles
*   **Vector 7.1 — Indian Bharatiya Sakshya Adhiniyam (BSA) 2023 Section 63 (formerly Section 65B):**
    *   *Requirement:* Electronic records require an automated, un-tampered certificate signed by a person in official charge of the device, certifying continuous lawful operation and absence of interference.
    *   *Failure Mode:* If the key hierarchy relies on anonymous developer keys (`.key.json`) without signed device onboarding or chain-of-custody logging, the Section 63 certificate will be challenged.
    *   *Mitigation:* Automated generation of Section 63 compliant certificates using the bundle's `custody.log`, linking the device's certified root key (`certs/root.pub.json`) to the lawful custodian.
*   **Vector 7.2 — US Federal Rules of Evidence (FRE 902(13) & 902(14)):**
    *   *Requirement:* Self-authenticating electronic data generated by a process or system that produces an accurate result, certified by a qualified person.
    *   *Failure Mode:* Pure-Python fallback backends produce valid crypto, but cannot resist side-channel key extraction or prove hardware non-repudiation.
    *   *Mitigation:* Enforce `evseal doctor` checks in evidence production pipelines, mandating hardware-rooted keys (PKCS#11 / TPM) and native `liboqs` backends for production evidence seals.
*   **Vector 7.3 — Standalone Air-Gapped Courtroom Verification:**
    *   *Requirement:* Courtroom environments rarely permit outbound internet connections to TSA timestamp servers or external anchor logs.
    *   *Failure Mode:* If verification requires live TSA callbacks or online CRL/OCSP endpoints, verification fails or stalls.
    *   *Mitigation:* Self-contained verification: EviSeal bundles embed the RFC 3161 DER tokens, local anchor logs, and certificate chains directly inside `certs/` and `anchors/`, requiring zero network access for 100% verification.

---

## 5. Summary Matrix & Hardening Priority

| Failure Vector | Category | Severity | Detection Point | Recommended Remediation |
|---|---|---|---|---|
| **D1: TS Audio PES Straddle** | Sealing | Medium | Sub-clip playback | Implement PUSI packet aligner; remux mode for sub-clips |
| **D6: Unsigned $t$ Metadata** | Proving | High | Cross-examination | Propose protocol diff binding $t$ into signed unit record |
| **D4: CMS Signature Verification** | Sealing/Proving | High | Verification | OpenSSL TS verification path active; mandate TSA cert embedding |
| **Offline Timestamp Queueing** | Sealing | High | Field acquisition | Record queue delay in `anchors/queue.jsonl` (§10) |
| **VFR Frame Rate Spikes** | Sealing | Low | Chunk segmentation | Upper-bound AEAD chunk size per unit |
| **Multi-Stripe Burst Loss** | Storing | Critical | Verification (`CORRUPT`) | Retain multi-site replicas; enforce $ec.interleave \ge 2$ |
| **Memory Key Remanence** | Sealing | Medium | Physical seizure | `mlock()` and hardware TPM key storage |
| **BSA Sec 63 / FRE 902 Admissibility** | Proving | High | Court filing | Generate standardized self-authentication certificates |

---

## 6. Audit Conclusion

The architectural foundations of EviSeal (dual-hashing, strict unit index chaining, Reed–Solomon recovery, and native ML-DSA/ML-KEM quantum-resistant cryptography) are mathematically sound and resilient. 

The primary risks do not stem from cryptographic breaks, but from **operational bitstream edge cases (audio PES cut alignment), unsigned presentation metadata under legal cross-examination, and offline field acquisition conditions**. Addressing these through the roadmap prioritized above will ensure unassailable evidentiary integrity.

---

## 7. Remediation status (2026-10-07, verified on native liboqs 0.16 in WSL2: full suite incl. slow, all green)

| Finding | Status |
|---|---|
| Verifier crash on hostile input (bad zip, huge chunk length) | Fixed: any exception is `REJECTED` |
| Backwards unit time makes a bundle unverifiable | Fixed: seal refuses with a clear error |
| No timestamp source makes a bundle unverifiable | Fixed: seal refuses |
| TSA clock vs key window | Fixed: window `rotation_s + 1 day`, `Trust.slack_s` policy, offset reported |
| Real RFC 3161 never verifies; no offline queue (D4) | Fixed: `openssl ts -verify` + `stamp-queue` (classical TSA signatures remain a disclosed limit) |
| Revocation judged against cert `not_before` | Fixed: judged against verified timestamp proof of signing time |
| Unsigned unit time `t` (D6) | Fixed: format v2 signs `[t, dur]`; v1 bundles still verify (SPEC §14 A1) |
| D1 audio PES straddle | Fixed for TS: clean-cut search; keyframe cut kept if none exists |
| D7 sparse clip preview | Fixed: compact copy with rewritten offsets |
| VFR / long-GOP huge units | Fixed: `segment.max_unit_mb` (default 64) |
| Seal on DEV-ONLY backend | Fixed: refused unless `EVSEAL_ALLOW_DEV_CRYPTO=1` |
| Root key plaintext on disk | Mitigated: passphrase-encrypted at rest (`EVSEAL_KEY_PASSPHRASE`); HSM/TPM still needed for hardware non-repudiation |
| New profile knob breaks old bundles | Fixed: `profile.OPTIONAL` (SPEC §14 A3) |
| Court report / s.63 draft; standalone `evseal-verify` | Added (`evseal report`, `evseal-verify`) |
| Test seeds not reproducible; crash hook in production path; skipped raw H.264/5 tests | Fixed |
| Benchmarks lacked environment, ran with tracemalloc, allowed fallback backend | Fixed |

**Measured (WSL2, i5-10200H, liboqs 0.16.0, ML-DSA-44, 120 s synthetic TS at about 0.5 Mbps):** 7.8 to 9.5x real time; storage overhead 108 to 252 percent depending on profile.
This is far above the SPEC §4 estimate of 10 to 20 percent. Cause: the per-unit cost (one ML-DSA signature of 2.4 KB plus R and C, stored as hex in
three manifest copies) is fixed at about 17 KB per second of footage, so low-bitrate sources pay a large relative cost. `sign.block_segments` and
`ec.k` are the levers (block=5 gave 108 percent). Open optimisation: binary or base64 signatures (a format change).

**Remaining, outside what software alone can close:** HSM/TPM-held keys; a post-quantum TSA; a human custodian's signature on the s.63 certificate;
Mode A cannot see pre-collection edits; loss beyond the parity budget is `CORRUPT`; cloud re-encoding can be detected but not prevented.

### 7.1 Access and non-repudiation (added 2026-10-07)

New finding: the API had no authentication, yet could delete bundles, create keys and tamper with copies, and `evseal serve --host` accepted any address.
Fixed: key-based login, five roles, a signed hash-chained user directory, signed access log, operator seal attestation bound to the final seal,
throttled logins, and a refusal to serve unauthenticated on a non-loopback address. Covered by `tests/test_access.py`, `tests/test_cli_access.py`,
`tests/test_api_auth.py`. External signers (HSM/TPM-style) and a post-quantum timestamp witness were added alongside.
Remaining: real HSM/TPM hardware, a PQ-capable public TSA, anchoring the access-log head externally, and a human custodian's signature on the court certificate.
