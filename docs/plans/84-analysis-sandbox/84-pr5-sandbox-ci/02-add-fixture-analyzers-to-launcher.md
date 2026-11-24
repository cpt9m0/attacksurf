# Plan: PR 5, commit 2: `feat(infra): add fixture analyzers to the launcher for dev and CI`

Branch `84-sandbox-ci` · `Refs #84` · follows `2ab6311 build(infra): add the sandbox fixture
analyzer image` (commit 1; see `84-pr5-sandbox-ci-overall-plan.md`).

## Purpose

**In plain words.** Commit 1 built a harmless test image, but the launcher only runs analyzers it
knows by name, and it knows none. This commit teaches the launcher four test-only analyzer names,
one for each thing the image can do: answer, report what the sandbox allows, hang, or print too
much. They are off unless a new setting turns them on, and that setting is refused in production,
so the test image can never run there. Nothing runs them yet; commit 3 does.

**Technical.** Adds `FIXTURE_SPECS` (four `AnalyzerSpec`s: `fixture-ok`, `fixture-probe`,
`fixture-sleep`, `fixture-flood`) to `sandbox_launcher/catalog.py`, a
`SandboxLauncherSettings.sandbox_fixture_analyzers` flag that fails validation when `ENV=prod`, and
a pure `select_specs()` in `sandbox_launcher/__main__.py` that adds the fixtures to the catalog only
when the flag is on and not in prod. The new env var is wired into `compose.yaml` and documented in
`.env.example`.

## Context
- `catalog.CATALOG` is `()` (`catalog.py:79-80`); `load_catalog(lock_path, specs=CATALOG)` joins
  specs to lock entries by name and drops everything missing from either side (`catalog.py:83-96`).
- `__main__.main()` calls `load_catalog(Path(settings.sandbox_images_lock))` with the default specs
  (`__main__.py:49`), and repeats the prod check in `select_runtime` rather than trusting the
  settings (`__main__.py:30-38`). The new gate follows the same pattern.
- `_SandboxServiceSettings` (`config.py:400-425`) refuses `SANDBOX_ALLOW_RUNC` in prod; it reads
  the process environment only, never `.env`. `SandboxLauncherSettings` is at `config.py:440-458`.
- The proxy allowlists **every digest** in the lock, by value, whatever the name
  (`sandbox_proxy/policy.py:88-99`). So the proxy needs no change: a test lock that lists the
  fixture image is enough for it. The names only matter to the launcher.
- The create body sets no `Env`, so the image's `PATH` applies; in the pinned base, `python` is
  `/usr/local/bin/python` (checked with `docker run … command -v python`).
- `tests/unit/sandbox_launcher/test_container.py:185-192` already runs every `CATALOG` spec through
  the real `validate_create`; it is parametrized over an empty tuple today, so it runs nothing.
- Compose passes the sandbox env through the `&sandbox-env` anchor (`compose.yaml:62-73`), shared by
  `sandbox-proxy` and `sandbox-launcher` (`compose.yaml:214-226`).

## Decisions
1. **Fixture specs live in `catalog.py`, beside `CATALOG`, never inside it.** `CATALOG` stays the
   production menu and stays `()`. A guard test keeps every `fixture-*` name out of `CATALOG` and
   out of the committed `sandbox-images.lock`.
2. **Three locks on the door, each tested.** (a) `SANDBOX_FIXTURE_ANALYZERS=true` with `ENV=prod`
   fails settings validation; (b) `select_specs(prod=True, fixtures=True)` still returns only
   `CATALOG`, so the gate doesn't rely on the settings check (as `select_runtime` does for `runc`);
   (c) even with the flag on, a fixture is runnable only if the lock names it, and the committed
   lock never does. The fixture image is also never pushed (overview Decision 7).
3. **The flag is on `SandboxLauncherSettings` only,** not the shared base. The proxy has no notion
   of analyzer names, so giving it the flag would suggest a control that doesn't exist there.
4. **Commands are `("/usr/local/bin/python", "/opt/fixture/probe.py", "<mode>")`.** Absolute
   interpreter path, so the command doesn't depend on the image's `PATH`. (Commit 1's notes said
   `"python"`; the absolute path is the stricter choice and the runtime test in commit 3 proves it
   exists.) No `-I`: it would also ignore `PYTHONDONTWRITEBYTECODE` from the image, and the
   environment is the image's own anyway.
5. **Default limits for all four.** `fixture-sleep` and `fixture-flood` must be stopped by the wall
   time and the 2 MiB output cap, not by a tighter per-analyzer limit, or commit 3 would test the
   wrong mechanism.
6. **A warning log when fixtures are on**, `sandbox_launcher_fixture_analyzers_enabled`, like
   `sandbox_launcher_runc_fallback`, so a misconfigured non-prod host is visible in its logs.
7. **The fixture names are checked against `probe.py`, not copied.** A test reads the modes from
   the probe's own usage line (`usage: probe.py {flood|ok|probe|sleep}`) and checks that
   `FIXTURE_SPECS` covers exactly those, so a new mode or a renamed one can't drift silently.
8. **Compose and `.env.example` get the variable** (the `AGENTS.md` rule for new env vars), on the
   launcher only, default `false`. Turning it on in the dev stack has no effect by itself because the
   committed lock is `{}`; making the dev stack run fixtures is out of scope (the runtime tests run
   the services in-process, overview Decision 1). The `.env.example` comment says so.

## Requirements
- [ ] `catalog.py`:
  - `FIXTURE_SPECS: tuple[AnalyzerSpec, ...]`, four specs in mode order `ok`, `probe`, `sleep`,
    `flood`, named `fixture-<mode>`, command as in Decision 4, default limits.
  - A short comment: test-only, never in `CATALOG`, added only by `__main__.select_specs`.
  - The `CATALOG` comment updated (it currently says the fixture analyzer arrives here).
- [ ] `config.py`, `SandboxLauncherSettings`:
  - `sandbox_fixture_analyzers: bool = False`, with a one-line why comment.
  - `@model_validator(mode="after")` raising
    `ValueError("SANDBOX_FIXTURE_ANALYZERS is not allowed when ENV=prod")`.
- [ ] `__main__.py`:
  - `select_specs(*, prod: bool, fixtures: bool) -> tuple[AnalyzerSpec, ...]`: `CATALOG +
    FIXTURE_SPECS` only when `fixtures and not prod`, else `CATALOG`. Docstring: the gate is
    repeated here on purpose.
  - `main()` passes `select_specs(prod=settings.env == "prod",
    fixtures=settings.sandbox_fixture_analyzers)` to `load_catalog`.
  - When the selection includes fixtures, log `sandbox_launcher_fixture_analyzers_enabled` at
    warning level before `sandbox_launcher_started`.
- [ ] `compose.yaml`, `sandbox-launcher` only:
  ```yaml
  environment:
    <<: *sandbox-env
    # Test-only analyzers (ADR 0016 runtime tests); refused when ENV=prod.
    SANDBOX_FIXTURE_ANALYZERS: ${SANDBOX_FIXTURE_ANALYZERS:-false}
  ```
- [ ] `.env.example`: a commented-out `# SANDBOX_FIXTURE_ANALYZERS=false` next to
      `SANDBOX_ALLOW_RUNC`, with a comment: test-only, refused in prod, needs a lock naming the
      fixtures (see commit 6 docs).
- [ ] Only those five non-test files change, plus tests.

## Acceptance criteria
- [ ] **Off by default:** `SandboxLauncherSettings().sandbox_fixture_analyzers is False`, and
      `main()` with a lock listing every fixture name serves an empty catalog.
- [ ] **On outside prod:** with the flag on and that lock, `main()` serves exactly the four
      fixture analyzers and logs the warning.
- [ ] **Never in prod:** the settings refuse the flag with `ENV=prod`; `select_specs(prod=True,
      fixtures=True) == CATALOG`.
- [ ] **Proxy accepts them:** every fixture spec builds a create body that passes the real
      `validate_create`, under both `runsc` and `runc`.
- [ ] **Compose:** `docker compose --profile sandbox config` shows `SANDBOX_FIXTURE_ANALYZERS:
      "false"` on `sandbox-launcher` and not on `sandbox-proxy`; the launcher keeps `ENV`,
      `SANDBOX_ALLOW_RUNC` and `SANDBOX_ARTIFACT_ROOT`.
- [ ] **Gate:** ruff, ruff format, pyright, lint-imports and pytest green; coverage not lower.

## Changes

### 1. `src/attacksurf/sandbox_launcher/catalog.py` (~15 lines)
`_FIXTURE_PYTHON = "/usr/local/bin/python"`, `_FIXTURE_PROBE = "/opt/fixture/probe.py"`, then
`FIXTURE_SPECS`, written out as four lines (clearer than a comprehension for a security list).

### 2. `src/attacksurf/config.py` (~10 lines)
Field and validator as in Requirements, after `sandbox_max_concurrent_runs`.

### 3. `src/attacksurf/sandbox_launcher/__main__.py` (~15 lines)
`select_specs` next to `select_runtime`; `main()` uses it and logs the warning. The module
docstring gains one sentence on the fixture gate.

### 4. `compose.yaml` (4 lines) and `.env.example` (~4 lines)
As in Requirements.

### 5. Tests

#### A. Happy path
- `tests/unit/sandbox_launcher/test_main.py`:
  - `test_select_specs_adds_the_fixtures_outside_prod_when_asked`: `CATALOG + FIXTURE_SPECS`.
  - `test_main_serves_the_fixture_analyzers_when_enabled`: the `configure` fixture with a lock
    `{name: "sha256:" + "c" * 64 for every fixture}` and `SANDBOX_FIXTURE_ANALYZERS="true"`;
    `started.servers[0].catalog` has exactly the four names, and the warning event is logged with
    `log_level == "warning"`.
- `tests/unit/test_config.py`:
  - `test_sandbox_launcher_settings_allow_fixture_analyzers_outside_prod` (`dev` and `test`).
  - `test_sandbox_launcher_settings_read_fixture_analyzers_from_environment` (`clean_env`).
- `tests/unit/sandbox_launcher/test_container.py`: widen
  `test_every_catalog_spec_builds_an_accepted_body` to `CATALOG + FIXTURE_SPECS`, and parametrize
  the runtime (`runsc`, `runc`).

#### B. Boundary cases
- `test_main.py`:
  - `test_select_specs_is_the_catalog_by_default` (`fixtures=False`, both `prod` values).
  - `test_main_ignores_fixtures_in_the_lock_when_disabled`: same fixture lock, flag unset; catalog
    `{}` and no warning event.
  - `test_main_serves_only_fixtures_named_in_the_lock`: lock lists `fixture-ok` only; catalog is
    `{"fixture-ok"}`.
- `tests/unit/sandbox_launcher/test_catalog.py`:
  - `test_fixture_specs_use_the_default_limits` (Decision 5).
  - `test_fixture_specs_run_the_probe_with_one_mode`: each command is
    `(_FIXTURE_PYTHON, "/opt/fixture/probe.py", mode)` and the name is `f"fixture-{mode}"`.

#### C. Refusals
- `test_config.py`:
  - `test_sandbox_launcher_settings_refuse_fixture_analyzers_in_prod`
    (`match="SANDBOX_FIXTURE_ANALYZERS"`).
  - Extend `test_sandbox_launcher_settings_ignore_dotenv_file`'s `.env` with
    `SANDBOX_FIXTURE_ANALYZERS=true`; the flag stays `False`.
- `test_main.py`:
  - `test_select_specs_never_adds_the_fixtures_in_prod`.
  - `test_main_refuses_fixture_analyzers_in_prod`: `ENV=prod`, the flag on, a `runsc` proxy;
    `main()` raises `pydantic.ValidationError` and `started.servers == []`.

#### D. Neighbor rejection and drift guards
- `test_catalog.py`:
  - `test_catalog_has_no_fixture_analyzer`: no `CATALOG` name starts with `fixture-`.
  - `test_fixture_specs_are_all_named_fixture`: every `FIXTURE_SPECS` name does, and none clashes
    with `CATALOG` (`load_catalog(lock, CATALOG + FIXTURE_SPECS)` doesn't raise).
  - `test_the_committed_images_lock_names_no_fixture`: no key of `sandbox-images.lock` starts with
    `fixture-` (kept next to `test_the_committed_images_lock_runs_no_analyzer`).
  - `test_fixture_specs_cover_every_probe_mode`: run `probe.py` with no argument
    (`sys.executable -I -S`), parse the modes from the usage line, compare to the fixture modes
    (Decision 7).
  - `test_fixture_probe_path_matches_the_image`: the fixture `Dockerfile`'s `COPY` destination is
    the probe path in the commands.
- `test_config.py`: `test_sandbox_proxy_settings_have_no_fixture_flag` (the field exists on the
  launcher settings only, Decision 3).

## Order of work (red → green)
1. Write the tests above; run them, watch them fail (`FIXTURE_SPECS`, `select_specs` and the field
   don't exist).
2. Add `FIXTURE_SPECS`; the catalog and container tests go green.
3. Add the setting and validator; the config tests go green.
4. Add `select_specs` and wire `main()`; the `test_main.py` tests go green.
5. Edit `compose.yaml`, run `docker compose --profile sandbox config` and check the acceptance
   item. Edit `.env.example` (this session can't read that file: permission is denied for it, so
   either allow the read or make that edit by hand from the text in Requirements).
6. Gate: `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run
   lint-imports && uv run pytest` (with `TEST_DATABASE_URL` set so DB tests run, not skip).
7. Commit only when asked. Subject above; body: why the fixtures are a separate tuple behind a
   prod-refused flag, and why the gate is repeated in `select_specs`. Footer `Refs #84`, then the
   Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `select_runtime` in `__main__.py`: the shape of `select_specs` (pure, keyword-only, prod check
  repeated).
- `tests/unit/sandbox_launcher/test_main.py`: `configure`, `started`, `list_runtimes`,
  `capture_logs`, and the conftest's real proxy in front of `FakeDocker`.
- `tests/unit/sandbox_launcher/test_container.py`: `proxy_policy`, `ARTIFACT_DIR`, and the existing
  every-spec policy test.
- `tests/unit/test_config.py`: the `SANDBOX_ALLOW_RUNC` prod-refusal and `.env`-ignored tests.
- `tests/unit/test_sandbox_images.py` (commit 1): the `-I -S` probe runner pattern and `PROBE` path.

## Verification
- `git diff --stat`: five non-test files, four test files.
- `docker compose --profile sandbox config` as in Acceptance criteria.
- Mutation checks, scratch only, reverted afterwards:
  - drop the prod check from `select_specs`: `test_select_specs_never_adds_the_fixtures_in_prod`
    fails;
  - drop the validator: `test_sandbox_launcher_settings_refuse_fixture_analyzers_in_prod` and
    `test_main_refuses_fixture_analyzers_in_prod` fail;
  - put `fixture-ok` into `CATALOG`: `test_catalog_has_no_fixture_analyzer` and
    `test_catalog_starts_empty` fail;
  - give `fixture-flood` a 1 MiB `file_bytes` limit: `test_fixture_specs_use_the_default_limits`
    fails.

## Notes for later commits
- **Commit 3:** the launcher fixture builds settings with `sandbox_fixture_analyzers=True` (or calls
  `select_specs(prod=False, fixtures=True)` and passes the result to `load_catalog` directly, since
  the servers run in-process). The tmp lock is `{f"fixture-{mode}": image_id}` for the four modes;
  the proxy policy is built from the same lock.
- **Commit 5:** the compose guard can also assert `SANDBOX_FIXTURE_ANALYZERS` appears on
  `sandbox-launcher` only, defaulting to `false`.
- **Commit 6:** `docs/development.md` explains the flag, the lock it needs, and that it is refused
  in prod; `docs/security.md` lists the three locks from Decision 2.
