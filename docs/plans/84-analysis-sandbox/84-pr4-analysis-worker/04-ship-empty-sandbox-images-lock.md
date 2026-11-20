# Plan: PR 4, commit 4: `build(infra): ship an empty sandbox images lock`

Branch `84-analysis-worker` · `Refs #84` · follows `feat(workers): move the analysis queue out of
the reserved list` (commit 3 of PR 4; see `84-pr4-analysis-worker-overall-plan.md`).

## Purpose

**In plain words.** The proxy and the launcher each read a small file at startup. The file lists
the exact analyzer images that may run. If the file is missing, both refuse to start, which is the
safe choice. No analyzer image exists yet, so this commit adds the file with an empty list, `{}`,
and puts it inside the app's Docker image. The services can then start, and they will still refuse
to run anything, because the list allows nothing.

**Technical.** Adds a root-level `sandbox-images.lock` containing `{}` and a newline. Both
`Dockerfile` stages (`dev` and `prod`) copy it to `/app/sandbox-images.lock`. Both services find it
there through their default setting:
- `_SandboxServiceSettings.sandbox_images_lock = "sandbox-images.lock"`, resolved against
  `WORKDIR /app`;
- read by `sandbox_proxy.policy.load_images`, which gives `(frozenset(), None)`;
- and by `sandbox_launcher.catalog.load_catalog`, which gives `{}`.

Two unit tests load the committed file through both loaders, so a malformed edit fails in CI. The
commit does not change the loaders and imports no sandbox code into the app.

## Context
`docs/development.md:189-196` currently tells developers to `echo '{}' > /tmp/sandbox-images.lock`
by hand, and `STATE.md` notes that local runs need a `{}` lock. Without the file:
- `sandbox_launcher/__main__.py` exits with "the images lock is missing or invalid";
- `sandbox_proxy/__main__.py` raises from `load_images`.

Commit 5's dev services need it to start. The umbrella plan had PR 5 add the lock; ADR 0029 and
the PR 4 overview move the empty version here. PR 5 adds the first digest.

This is a separate commit because it is a build change (Dockerfile plus a data file) with its own
tests, independent of Compose.

## Decisions
1. **Bake it into the image; don't bind-mount it.** The lock decides which images may run, so it
   ships and is reviewed with the code. Every deploy then carries exactly the reviewed list.
   A bind mount would let a host edit change it silently.
2. **Root of the repo, default path.** The settings default is the relative `sandbox-images.lock`.
   Putting the file at `/app` means Compose needs no `SANDBOX_IMAGES_LOCK` variable.
3. **The prod stage gets it too, though prod runs no sandbox service yet.** The image is shared,
   and #92 would otherwise have to remember a Dockerfile edit. `COPY` keeps root ownership and
   mode 0644, so the non-root `app` user can read it but not change it.
4. **Tests read the real file.** The repo-root pattern `Path(__file__).resolve().parents[3]` is
   already used in `tests/unit/scanners/test_network_boundary.py`.
5. **Left out.** Real digests and the image build workflow (PR 5).
6. **Docs in this commit.** None. Commit 7 replaces the `echo '{}'` step in
   `docs/development.md`.

## Requirements
- [ ] `sandbox-images.lock` at the repo root, content exactly `{}\n`.
- [ ] `Dockerfile` `dev` stage: `COPY README.md LICENSE alembic.ini sandbox-images.lock ./`.
      The `prod` stage gets the same line.
- [ ] No change to `config.py`, `sandbox_proxy/` or `sandbox_launcher/` source.
- [ ] The file is valid JSON for any `check-json` style hook (none currently checks `*.lock`).

## Acceptance criteria
- [ ] **Contract (proxy):** `load_images(ROOT / "sandbox-images.lock") == (frozenset(), None)`.
- [ ] **Contract (launcher):** `load_catalog(ROOT / "sandbox-images.lock") == {}`.
- [ ] **Build:** `docker build --target prod -t attacksurf:prod .` succeeds, and
      `docker run --rm --entrypoint cat attacksurf:prod /app/sandbox-images.lock` prints `{}`.
- [ ] **Isolation:** `uv run lint-imports` passes. The tests sit in the existing
      `tests/unit/sandbox_*` folders, which may import those packages.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%. Hooks pass without `--no-verify`.

## Changes

### 1. `sandbox-images.lock` (1 line)
- `{}`.

### 2. `Dockerfile` (2 lines)
- Add `sandbox-images.lock` to the existing `COPY README.md LICENSE alembic.ini ./` line in both
  stages. No new `COPY` layer.

### 3. Tests (written first, ~12 lines)
- In `tests/unit/sandbox_proxy/test_policy.py`, next to
  `test_load_images_reads_digests_and_finds_the_osv_image`.
- In `tests/unit/sandbox_launcher/test_catalog.py`, next to `test_catalog_starts_empty`.

#### A. Happy path
| Test | Given | Expect |
|---|---|---|
| `test_the_committed_images_lock_allows_no_image` (proxy) | repo-root `sandbox-images.lock` | `(frozenset(), None)` |
| `test_the_committed_images_lock_runs_no_analyzer` (launcher) | the same file | `{}` |

#### B. Boundary cases
None. Empty is the only state this commit ships.

#### C. Invalid inputs
None new. Existing tests (`test_load_images_refuses_anything_but_digests`,
`test_load_catalog_rejects_a_malformed_lock_without_echoing_it`,
`test_load_catalog_lets_a_missing_lock_file_fail_startup`) cover malformed and missing locks.

#### D. Neighbor rejection and drift guards
The two tests above pin the shipped allowlist as empty. PR 5 updates them when it adds the
first digest, so changing the allowlist forces a reviewed test change.

## Order of work (red → green)
1. Write both tests. `uv run pytest tests/unit/sandbox_proxy/test_policy.py
   tests/unit/sandbox_launcher/test_catalog.py` fails with `FileNotFoundError` (no lock yet).
2. Add the lock file. The tests pass.
3. Edit the `Dockerfile`, build both targets, and run the `cat` check from Acceptance criteria.
4. Full gate (as in commit 2).
5. `finish-task` deferred to commit 8.
6. Commit. Body: "both sandbox services refuse to start without a lock; an empty one allows no
   image, so the dev stack can run them before PR 5 adds the first analyzer". Footer `Refs #84`,
   Co-Authored-By trailer.

## Reused code
- `src/attacksurf/sandbox_proxy/policy.py`: `load_images` (tests only).
- `src/attacksurf/sandbox_launcher/catalog.py`: `load_catalog` (tests only).
- `tests/unit/scanners/test_network_boundary.py`: the repo-root `parents[3]` pattern.

## Verification
- The two test files are green, then the full suite.
- `docker build --target dev .` and `--target prod .` both succeed. CI's prod build step and its
  `id -u = 10001` check still pass.
- Scratch check (revert): change the lock to `[]`. Both new tests fail with "invalid images lock".

## Notes for later commits
- **Commit 5:** the services rely on the baked-in default path, with no `SANDBOX_IMAGES_LOCK` in
  Compose.
- **PR 5:** replaces `{}` with the fixture analyzer's digest. A rebuild of the image carries it.
- **Commit 7:** removes the manual `echo '{}'` step from `docs/development.md`.
