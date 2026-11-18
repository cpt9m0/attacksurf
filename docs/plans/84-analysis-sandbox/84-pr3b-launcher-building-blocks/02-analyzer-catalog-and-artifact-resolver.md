# Plan: PR 3b, commit 2: `feat(infra): add sandbox analyzer catalog and artifact resolver`

Branch `84-sandbox-launcher-core` · `Refs #84` · follows `54c1f1b feat(security): add sandbox
launcher settings` (commit 1 of PR 3b; see `../84-pr3-sandbox-launcher-split-4-prs.md`).

## Context
Commit 1 added `SandboxLauncherSettings`. The launcher package does not exist yet. This commit
creates it and adds the two pure pieces that decide *what may run* and *on what*, before any
container or HTTP code exists:

- **Analyzer catalog:** the caller names an analyzer; the launcher maps that name to a fixed
  command, fixed limits and an image digest from `sandbox-images.lock`. The caller never picks
  images, args, mounts or limits (ADR 0016). The catalog starts **empty**; the fixture analyzer
  arrives in PR 5.
- **Artifact resolver:** turns an artifact UUID into its directory under the artifact root, and
  refuses anything that is not a real directory directly inside that root.

Both are side-effect free apart from reading one file / one `lstat`, so each is easy to test. No
docs in this commit: commit 5 of this PR carries `AGENTS.md`, `docs/architecture.md`,
`CHANGELOG.md` and `STATE.md`.

## Decisions
1. **The launcher never imports `sandbox_proxy`** (ADR 0016: a compromised launcher must not
   share code with the policy that checks it). So the digest regex and the hard limit ceilings
   are **duplicated** in the launcher, and a unit test proves they match the proxy's.
2. **Lock entries without a spec are ignored, specs without a lock entry are unavailable.** Both
   fail closed: the launcher can only run what it has code *and* a digest for. A malformed lock
   raises `ValueError("invalid images lock")` (no value echoed), same as the proxy.
3. **The resolver returns the unresolved `{root}/{uuid}`** after checking it, not
   `Path.resolve()`'s output. The proxy's bind check is a string prefix on the artifact root, so
   the bind must stay in that form. Docker follows symlinks on the host, so the "not a symlink"
   check is the one that matters.
4. **No per-analyzer wall-time override.** Wall time stays the single launcher setting (commit 1).
   Per-analyzer overrides can come with a real analyzer that needs one.

## Changes

### 1. New package `src/attacksurf/sandbox_launcher/`
- `__init__.py`: docstring only (role, and that it never touches Docker or app secrets).
- `catalog.py`
  - `ANALYZER_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")`. Commit 3d's server reuses it.
  - `MAX_*` ceilings copied from `sandbox_proxy/policy.py:20-25`, commented as a deliberate copy
    guarded by a test.
  - `@dataclass(frozen=True) SandboxLimits`: `nano_cpus`, `memory_bytes`, `pids`,
    `scratch_bytes`, `open_files`, `file_bytes`. Defaults are the ADR 0016 table (1 core, 1 GiB,
    256, 1 GiB, 1024, 1 GiB). `__post_init__` raises `ValueError` unless each value is an int
    (not bool), `> 0` and `<=` its ceiling.
  - `@dataclass(frozen=True) AnalyzerSpec`: `name` (must match `ANALYZER_NAME`), `command:
    tuple[str, ...]` (non-empty, non-empty strings; becomes `Cmd`), `limits: SandboxLimits`.
  - `@dataclass(frozen=True) Analyzer`: `spec`, `image` (the digest reference from the lock).
  - `CATALOG: tuple[AnalyzerSpec, ...] = ()`.
  - `load_catalog(lock_path: Path, specs=CATALOG) -> Mapping[str, Analyzer]`. Reads the lock
    JSON (`dict[str, digest]`; digest regex as in `policy._DIGEST`), rejects duplicate spec
    names, and returns only analyzers present in both. `OSError` propagates (startup fails), as
    in `policy.load_images`.
- `artifacts.py`
  - `class ArtifactNotFound(Exception)`: generic message, never contains a path (3c maps it to
    404).
  - `resolve_artifact(root: Path, artifact_id: UUID) -> Path`: reject a non-absolute `root`
    (`ValueError`); `candidate = root / str(artifact_id)`; raise `ArtifactNotFound` if
    `candidate.is_symlink()`, not `candidate.is_dir()`, any `OSError`, or
    `candidate.resolve(strict=True).parent != root.resolve()`; else return `candidate`.
    `str(UUID)` is lowercase and hyphenated, so it satisfies the proxy's `_SEGMENT` rule.

### 2. `pyproject.toml` import-linter
- New contract "sandbox launcher stays isolated from the app and Docker": source
  `attacksurf.sandbox_launcher`; forbidden `web`, `workers`, `services`, `infra`, `scanners`,
  `ai`, `sandbox_proxy`, `celery`, `flask`, `httpx`, `psycopg`, `redis`, `sqlalchemy`
  (modeled on the proxy contract at `pyproject.toml:167`).
- Add `attacksurf.sandbox_launcher` to the proxy contract's forbidden list, so the two stay
  independent in both directions.
- `domain` stays allowed (3c needs `SandboxResult`).

### 3. Tests (written first), `tests/unit/sandbox_launcher/`
`__init__.py`, `test_catalog.py`, `test_artifacts.py`. Style follows
`tests/unit/sandbox_proxy/test_policy.py`; use `tmp_path` for files.

`test_catalog.py`
- `CATALOG` is empty, and `load_catalog` on a valid lock returns `{}`.
- Spec in the lock → `Analyzer` with the lock's digest and the spec's command/limits.
- Spec not in the lock → unavailable. Lock entry without a spec → ignored.
- Lock errors, parametrized: not JSON, not an object, non-string digest, tag instead of digest,
  short digest → `ValueError("invalid images lock")`, message has no lock content.
- Missing lock file → `FileNotFoundError`.
- Duplicate spec names → `ValueError`.
- `SandboxLimits`: defaults equal the ADR 0016 table; each field rejects `0`, negative, `True`,
  above-ceiling, accepts exactly the ceiling.
- `AnalyzerSpec`: rejects bad names (uppercase, leading digit, `../x`, too long, empty), empty
  command, non-string/empty command items.
- **Parity with the proxy:** launcher ceilings equal `sandbox_proxy.policy.MAX_*`; the same set of
  good/bad lock files is accepted/rejected by both `load_catalog` and `policy.load_images`.
  (Tests may import both; only source modules are isolated.)

`test_artifacts.py`
- Real directory → `{root}/{uuid}`, unresolved.
- Missing; a regular file; a symlink to a directory inside the root; a symlink escaping the
  root; root itself a symlink (allowed, result still under the given root) → expected result.
- Relative root → `ValueError`.
- `ArtifactNotFound` message and `str(exc)` contain neither the root nor the UUID.
- Result satisfies the proxy's path rule: build a create body bind with it and call
  `policy._check_artifact_source` through `validate_create` (the full contract test is commit 3;
  here just the path form).

## Order of work (red → green)
1. Add the tests and the lint contract; run `uv run pytest tests/unit/sandbox_launcher`. They fail
   on import errors (no package) as expected.
2. Implement `catalog.py`, `artifacts.py` until they pass.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. Commit on `84-sandbox-launcher-core` with `Refs #84` and the Co-Authored-By trailer. Never
   `--no-verify`.

## Reused code
- `sandbox_proxy/policy.py`: `_DIGEST`, `MAX_*`, `_SEGMENT`, `load_images` (patterns copied; used
  directly only in the parity tests).
- `config.py` `SandboxLauncherSettings.sandbox_artifact_root` / `sandbox_images_lock`
  (consumed by `__main__` in 3c, not here).
- `domain/sandbox.py` is not touched.

## Verification
- `uv run pytest tests/unit/sandbox_launcher -q` green, then the full suite with coverage ≥ 80%.
- `uv run lint-imports` passes. Negative check (scratch only, not committed): add
  `import sqlalchemy` to `catalog.py`, confirm the new contract fails, then revert.
- Manual smoke in a Python shell with a temp lock: `load_catalog` returns `{}` for the real empty
  `CATALOG`; `resolve_artifact` accepts a fresh UUID dir and rejects a symlink to it.

## Notes for later commits
- **3 (create body):** `build_create_body` takes `Analyzer` + `resolve_artifact`'s path; the
  contract test checks `SandboxLimits` → body → `validate_create`.
- **3c (server):** parse `artifact_id` strictly (`str(UUID(v)) == v`), since `UUID()` also
  accepts braces and `urn:` forms.
- **PR 4 (compose):** mount the artifact root read-only into the launcher at the **same absolute
  path** as on the host, because Docker resolves the bind on the host. The check-then-bind gap is
  acceptable only while nothing but the fetcher/worker can write under the root.
