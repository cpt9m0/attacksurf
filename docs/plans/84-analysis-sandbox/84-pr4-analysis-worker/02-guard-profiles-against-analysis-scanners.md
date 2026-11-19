# Plan: PR 4, commit 2: `test(scanners): guard scan profiles against analysis scanners`

Branch `84-analysis-worker` · `Refs #84` · follows `docs(adr): record opening the analysis queue
before an analyzer exists` (commit 1 of PR 4; see `84-pr4-analysis-worker-overall-plan.md`).

## Purpose

**In plain words.** A "scan profile" is the list of checks a user's scan runs. Once the analysis
queue is open, someone could add an analysis check to a profile before a real analyzer exists. Every
scan would then wait on work that can't run. This commit adds a test that fails if any profile
includes such a check. It changes no app behaviour; it only stops a future mistake.

**Technical.** Adds `test_no_profile_selects_an_analysis_scanner` to
`tests/unit/scanners/test_profiles.py`. It checks every scanner named in `discover` or `checks` of
each `PROFILES` entry:
- it is resolved through `registry.get(name)`;
- its `queue` must not be `"analysis"`;
- its `grant.sandbox_analyzers` must be empty.

The test imports nothing new; it reuses the plugin imports the file already has. It implements
the guard rule of ADR 0029 (commit 1).

## Context
`PROFILES` (`src/attacksurf/scanners/profiles.py`) has only `dns_passive`. `CODE_PROFILE` and
`BINARY_STATIC_PROFILE` are kept out of it on purpose; integration tests in
`tests/integration/services/test_repos.py` and `test_binaries.py` already assert that. Those tests
check named profiles, not "any scanner in any profile". A new profile, or a new check added to
`dns_passive`, would get past them.

This commit comes before commit 3 (opening the queue), so the guard is in place before anything
can run there. It is a separate commit because it is a pure test with no production change.

## Decisions
1. **Check the scanner, not the profile name.** The danger is an analysis scanner reaching any
   profile, so the test walks every scanner a profile selects.
2. **Two conditions, OR-ed.** `queue == "analysis"` catches the queue route.
   `grant.sandbox_analyzers` catches a scanner on another queue that still asks for the sandbox.
   Either one means "needs a real analyzer".
3. **Unit test, no database.** `PROFILES` and `registry` are in-memory. This keeps the guard
   fast and runnable without Postgres.
4. **The failure message names the profile and scanner.** It should point the reader to ADR 0029
   and #92, so whoever trips it knows the rule is deliberate.
5. **Left out.** No runtime check in `services/scans.py`: ADR 0029 decided a test is enough.
6. **Docs in this commit.** None. Commits 7 and 8 carry the docs.

## Requirements
- [ ] One new test function in `tests/unit/scanners/test_profiles.py`. No other files change.
- [ ] It iterates `PROFILES.values()` and, for each name in `profile.discover + profile.checks`,
      calls `registry.get(name)`.
- [ ] It asserts `scanner.queue != "analysis"` and `not scanner.grant.sandbox_analyzers`.
- [ ] The assertion message contains the profile name, the scanner name and "ADR 0029 / #92".

## Acceptance criteria
- [ ] **Guard:** the test passes on today's `PROFILES`.
- [ ] **Guard (mutation):** in a scratch copy, add a fake scanner with `queue="analysis"` to a test
      profile and the test fails. Do the same with `grant=ScannerGrant(sandbox_analyzers=…)`. Revert.
- [ ] **Isolation:** `uv run lint-imports` passes. The test imports nothing from `sandbox_*`.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%. The commit passes the hooks without `--no-verify`.

## Changes

### 1. Source
None.

### 2. Tests, `tests/unit/scanners/test_profiles.py` (written first, ~15 lines)
Style follows the existing `test_dns_passive_profile_is_valid_and_selects_the_ct_discovery_scanner`
in the same file. Reuse its plugin imports.

#### A. Happy path
| Test | Given | Expect |
|---|---|---|
| `test_no_profile_selects_an_analysis_scanner` | every real `PROFILES` entry | no selected scanner is on `analysis` or has `sandbox_analyzers` |

#### B. Boundary cases
None. The real catalog is the only input.

#### C. Invalid inputs
None. The scratch mutation check in Verification shows the failing side.

#### D. Neighbor rejection and drift guards
The test itself is the drift guard: any future profile change is checked against ADR 0029.

## Order of work (red → green)
1. Write the test. Run `uv run pytest tests/unit/scanners/test_profiles.py`.
   - It passes immediately, which is expected for a guard.
   - Prove it can fail with the scratch mutation (Verification) before committing.
2. No implementation.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. `finish-task` deferred to commit 8.
5. Commit with the subject above. Body: "the analysis queue opens next; no profile may depend on
   an analyzer that does not exist yet (ADR 0029)". Footer `Refs #84`, Co-Authored-By trailer.

## Reused code
- `src/attacksurf/scanners/profiles.py`: `PROFILES`.
- `src/attacksurf/scanners/registry.py`: `registry.get`.
- `src/attacksurf/domain/scanners.py`: `Scanner.queue`, `ScannerGrant.sandbox_analyzers`.

## Verification
- `uv run pytest tests/unit/scanners/test_profiles.py -q` green.
- Scratch mutation (revert afterwards): temporarily point a scanner in `dns_passive` at the queue
  `analysis` (or give it `sandbox_analyzers=frozenset({"x"})`). The new test fails with the
  ADR 0029 message.

## Notes for later commits
- **Commit 3:** opens the queue. This guard is why that is safe.
- **#92:** the first analyzer profile must change this test, ideally to an allowlist of profiles
  that may use analysis, in the same PR that adds the prod services.
