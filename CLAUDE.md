# CLAUDE.md — EviSeal

Read `SPEC.md` before doing anything. It is the source of truth.

## Non-negotiables

- **§2 Core protocol is fixed.** This covers:
  - the dual content hash
  - chain `C_i = Hc(i ‖ R_i ‖ C_{i-1})`
  - signing every `R_i` and `C_i`
  - convergent verify-to-open AEAD keyed from the *signed* `C_i`
  - checkpoints, final seal, key rotation, gap records

  If something seems wrong, stop and propose the change. Never change it silently.
- **§10 and §11 are part of the requirements.** §10 lists requirements recovered from the design chat. §11 lists rejected alternatives; don't re-propose them without a new reason.
- **Fail closed.** Any failed or skipped check means not `VERIFIED`. There is no "unsigned but OK" path.
- **Every tunable lives in the profile (§4).** No algorithm name or size is hardcoded outside `core/crypto.py`'s registry.
- **Never write private keys** into bundles, logs, or test snapshots.
- **Use seeded randomness** in all fault injection, and record the seed in results.

## How to work

- Go phase by phase (SPEC §8). For each phase:
  1. Write a short plan.
  2. Wait for approval.
  3. Implement.
  4. Get tests green.
  5. Report deviations in 3–5 lines.
- Keep it minimal: stdlib first, one package, no speculative abstractions. Mark deliberate shortcuts with `# ponytail:` and name the upgrade path.
- Every non-trivial path (parser, crypto, repair) gets a test.
- Stress scenarios go in `stresslab/expected.toml` with their expected verdict. A mismatch is a bug, not a flaky test.
- Mark slow tests `@pytest.mark.slow`. CI runs the fast set.

## Commands

The CLI is `evseal` (typer). `evseal doctor` checks the environment: liboqs algorithms, ffmpeg, zfec.

## Environment notes

- `liboqs-python` needs the liboqs shared library. Build it from source with cmake, and fail with a clear message if it is missing.
- Develop cross-platform (Windows + Linux).
