You are continuing the EviSeal build in D:\Projects\Pqcmediaforensics (or the WSL path of the same checkout).

## 0. Read first
1. `CLAUDE.md` and `SPEC.md` (source of truth; §2 protocol is fixed, §10/§11 are requirements/rejected options).
2. `git status` and `git log`. Much code is uncommitted: `evseal/core/*`, `media/*`, `resilience/*`, `longterm/*`, `stresslab/*`, `dr/custody.py`, `api/app.py`, `ui/*`, `workspace.py`. Nothing is committed past P0.
3. Every `# ponytail:` comment (`grep -rn "ponytail:" evseal`). Each is a deliberate shortcut and a candidate deviation.

## 1. Environment: switch to WSL2 (Ubuntu)
WSL is now the primary env. Real PQ crypto only; no pure-Python fallback for benchmarks or sealing.
1. Confirm `wsl -l -v` shows Ubuntu on WSL2. If not, stop and tell the user to run `wsl --install -d Ubuntu` and reboot.
2. In WSL, work from a Linux-side clone or `/mnt/d/Projects/Pqcmediaforensics`. Prefer a Linux-side copy for speed. Do not edit the Windows copy and the WSL copy independently.
3. Install the toolchain: `build-essential cmake ninja-build libssl-dev git ffmpeg python3-dev` plus pixi (or venv + `pip install -e .[dev]`).
4. Build liboqs from source with cmake (shared lib), install it, set `LD_LIBRARY_PATH`/`OQS_INSTALL_PATH`, install `liboqs-python`, then install `zfec`.
5. `evseal doctor` must show ML-DSA, SLH-DSA, ML-KEM as native liboqs (not the DEV-ONLY fallback), plus ffmpeg and zfec. Fix until it does.
6. Run the full suite: `pytest -q` and `pytest -q -m slow`. Record the baseline (pass/fail/skip counts) before changing anything.

## 2. Fix deviations
No deviation list was saved. Build it:
- Compare each implemented module against SPEC §2, §4, §5, §9.1, §10, §11 and the phase "Done when" column in §8.
- Collect every `ponytail:` shortcut and every skipped or xfail test.
- Write the list to `DEVIATIONS.md`: item, SPEC ref, severity, fix or accept-with-reason.

Then fix, in this order:
1. Anything that breaks a CLAUDE.md non-negotiable:
   - Algorithm names or sizes hardcoded outside the `core/crypto.py` registry.
   - Any "unsigned but OK" or skipped-check path that does not fail closed.
   - Private keys written into bundles, logs or snapshots.
   - `core/verify.py` importing UI/API code.
   - Format-specific logic inside `core/`.
   - Unseeded randomness in fault injection, or the seed not recorded in results.
2. Any protocol drift from §2. If the SPEC seems wrong, STOP and propose the change. Never change §2 silently.
3. Remaining `ponytail:` items that the spec requires at the current phase. Leave legitimate later-phase shortcuts, and list them in `DEVIATIONS.md`.
4. Tests that only passed because of the pure-Python fallback or Windows quirks. Re-verify on native liboqs.

## 3. Verify phase by phase (SPEC §8)
For each phase P1, P1b, P2, P3, P4, P5, P6, in order:
1. Check its "Done when" criteria against the actual test results.
2. Make sure `stresslab/expected.toml` covers every listed scenario with its expected verdict. A mismatch is a bug, not flakiness.
3. Mark slow tests `@pytest.mark.slow`.
4. Report status as pass / partial / missing, with evidence (test names and counts).

Do not claim a phase done on the basis of code existing. Only green tests with the stated attacks and faults count.

## 4. Next steps after the above is green
1. Commit in small, per-phase commits (conventional messages). Do not commit anything containing key material.
2. Fill gaps in the earliest incomplete phase. Then move to the next phase using plan, approval, implement, test, report.
3. Run benchmarks only on native liboqs under WSL. Record the environment (CPU, liboqs version, algorithms) with each result.
4. After P3, schedule §10 reproducible transcoding (derivation records).

## 5. Working rules
- Plan first, wait for approval before each phase's implementation. Deviations report: 3-5 lines.
- Stdlib first, one package, no speculative abstractions. Mark shortcuts with `# ponytail:` and name the upgrade path.
- Every parser, crypto and repair path gets a test.
- Stay cross-platform: Windows UI dev (P4) must still work without native liboqs.
- Never re-propose anything in §11 without a new reason.

Report back with: the baseline test counts, `DEVIATIONS.md` contents, and the fix plan for approval before large changes.
