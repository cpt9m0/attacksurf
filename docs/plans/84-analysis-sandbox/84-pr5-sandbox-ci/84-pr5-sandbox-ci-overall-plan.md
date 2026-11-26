# Plan: PR 5 of #84, build the sandbox fixture image and test under `runsc` (overview)

Branch `84-sandbox-ci` (new, from `origin/main`) · PR title `ci(security): build sandbox images and
test under runsc` · `Refs #84` on commits 1 to 4, **`Closes #84`** on the last commit.

## Context
#84 builds the sandbox that will run analyzers on untrusted uploads (ADR 0016, 0018). PRs 1 to 4
are merged: the port and grants (#134), the proxy (#135, #157), the launcher (#158, #172), the
worker client (#183) and the analysis worker with the dev stack (#188). Every piece is unit-tested
against a **fake Docker daemon** (`tests/docker_fakes.py`). Nothing has yet run a real container
under gVisor, so these acceptance criteria of #84 are still unproven:

- no network, read-only input, read-only root, `/scratch` the only writable path;
- a timeout kills the container, and output over 2 MiB kills the run and fails it;
- the launcher refuses to start in prod without `runsc`;
- only `sandbox-proxy` mounts the Docker socket; the launcher holds no DB/Redis credentials.

This PR closes that gap with a harmless fixture image, a CI job that installs `runsc`, and
integration tests that drive the real chain (client, launcher, proxy, Docker, `runsc`). It ships
no real analyzer (#92 onward) and changes nothing in prod.

## Findings that shape the plan
- `catalog.CATALOG` is `()` and `load_catalog(lock, specs)` already takes specs, so the fixture
  analyzers can be a second tuple that is added only outside prod.
- The proxy policy accepts a bare `sha256:<64 hex>` image reference (`_DIGEST` in
  `sandbox_proxy/policy.py`). A locally built image therefore works by its **image ID**, as the
  epic plan says. No registry and no push is needed for the fixture.
- A catalog analyzer has a **fixed** command, and callers cannot pass arguments. One fixture
  image with several fixed commands (ok, probe, sleep, flood) tests every behavior without
  widening the interface.
- The committed `sandbox-images.lock` is `{}` and must stay free of fixture entries. The test
  lock is generated at test time from the locally built image ID.
- `.github/workflows/ci.yml` pins every action to a commit SHA with a version comment. New
  workflow files copy those exact pins (`actions/checkout@3d3c42e5...`).
- The `STATE.md` handoff is stale (it still describes #76). `finish-task` overwrites it.

## Decisions
1. **Tests run the real services in-process, not through Compose.** The test fixture starts the
   real `sandbox_proxy.server.make_server` on the runner's `/var/run/docker.sock` and the real
   `sandbox_launcher.server.make_server` in front of it, and calls them through
   `infra.sandbox.LauncherSandboxRunner`. This covers the whole chain with no new service wiring,
   and the same code path the unit tests already use (`tests/unit/sandbox_launcher/conftest.py`)
   with the fake daemon swapped for the real one. Compose isolation is checked separately
   (commit 5) by reading `docker compose config`, as `tests/unit/test_production_workers.py` does.
2. **Fixture analyzers are a launcher setting, refused in prod.** New
   `SandboxLauncherSettings.sandbox_fixture_analyzers: bool = False`, rejected when `ENV=prod`
   (same shape as `SANDBOX_ALLOW_RUNC`). Four fixture specs live in `catalog.py` beside `CATALOG`;
   `__main__` adds them only when the setting is on. This is how "the fixture is allowed only in
   dev and CI" is enforced in code, with a test, not by convention.
3. **Four fixed commands on one image**, all under the allowlist name prefix `fixture-`:
   `fixture-ok` (prints one JSON object), `fixture-probe` (reports what the sandbox allows),
   `fixture-sleep` (outlives any wall time), `fixture-flood` (prints more than 2 MiB).
4. **The image is built by one script used by CI, the Makefile and the tests**
   (`scripts/build-sandbox-images.sh`). It builds with plain `docker build`, so there is no
   third-party build action to pin, and prints the image ID. Base image pinned by digest, the
   same Python base as the root `Dockerfile` so Dependabot proposes both updates together.
5. **`runsc` is installed from a pinned release.** Version and SHA-512 are constants in
   `scripts/install-runsc.sh`, with a release at least two weeks old (the ADR 0018 rule), the
   checksum checked before the binary is installed, then `runsc install` and a Docker restart.
   No `curl | sh`, no `:latest`.
6. **CI never skips the runtime tests.** Mirrors the DB tests: locally the marker is opt-in
   (`RUN_SANDBOX_TESTS=1`), but in the `sandbox` CI job the fixture **fails** when Docker or
   `runsc` is missing, and the job sets `SANDBOX_ALLOW_RUNC=false`, so a silent fall back to
   plain `runc` is impossible. A test also proves the sandbox really was gVisor.
7. **Workflow permissions.** The new `sandbox-images.yml` has `permissions: contents: read` only.
   The fixture is never pushed. ADR 0018's "permission needed to push images" arrives with the
   first real analyzer (#92), which adds `packages: write` to a main-only job.
8. **Docs ride in the last commit**, except where a commit changes a setting (`.env.example`).

## Commits
Size rule from memory: at most 5 non-test files per commit (about 8 with tests), one idea each.
Each commit leaves ruff, pyright, lint-imports and pytest green, and tests come first.

| # | Subject | Non-test files |
|---|---|---|
| 1 | `build(infra): add the sandbox fixture analyzer image` | `sandbox/images/fixture/Dockerfile`, `.../probe.py`, `scripts/build-sandbox-images.sh`, `Makefile` target, `.github/dependabot.yml` |
| 2 | `feat(infra): add fixture analyzers to the launcher for dev and CI` | `sandbox_launcher/catalog.py`, `config.py`, `sandbox_launcher/__main__.py`, `compose.yaml` (launcher env), `.env.example` |
| 3a | `fix(security): keep /tmp read-only in the sandbox` | `sandbox_launcher/container.py`, `sandbox_proxy/policy.py`, ADR 0034, ADR 0016 (pointer), `docs/security.md` |
| 3b | `test(infra): run the sandbox end to end under a real runtime` | `sandbox/images/fixture/probe.py`, `pyproject.toml` (marker), `Makefile` |
| 4 | `ci(security): build sandbox images and run runsc tests` | `.github/workflows/sandbox-images.yml`, `.github/workflows/ci.yml`, `scripts/install-runsc.sh`, `pyproject.toml` |
| 5 | `test(infra): guard sandbox service isolation in compose` | tests only (compose config + lock guards) |
| 6 | `docs(infra): record the sandbox CI and close issue 84` | `docs/development.md`, `docs/security.md`, `CHANGELOG.md`, `AGENTS.md` (commands), `STATE.md`; footer `Closes #84` |

### 1. Fixture image
- `sandbox/images/fixture/Dockerfile`: `FROM python:3.15-slim@sha256:<same digest as Dockerfile>`,
  copies `probe.py` as `/opt/fixture/probe.py`, no package installs, no `CMD` (the launcher sets
  it). `probe.py` is standard library only and takes one mode argument.
- Modes: `ok`; `sleep` (loops forever); `flood` (writes 3 MiB of text to stdout); `probe`, which
  prints one JSON object of facts:
  - a TCP connect to `1.1.1.1:53` and a DNS lookup both fail;
  - opening a file under `/input` for writing, and creating a new one there, fail;
  - writing to `/etc` fails; writing to `/scratch` works; executing a copied binary in
    `/scratch` fails (`noexec`);
  - `os.getuid()` is `65532`, `CapEff` in `/proc/self/status` is all zero, `NoNewPrivs` is `1`;
  - `/var/run/docker.sock` does not exist, and the environment holds no secret-looking names;
  - the number of files seen under `/input`, and a kernel marker that tells gVisor apart.
- `scripts/build-sandbox-images.sh`: `set -euo pipefail`, builds every directory under
  `sandbox/images/`, tags `attacksurf-sandbox-<name>:ci`, prints `<name> <image id>` lines.
- Test: `tests/unit/test_sandbox_images.py` checks the Dockerfile base is digest-pinned and equal
  to the root `Dockerfile` base, and that `probe.py` imports only the standard library.

### 2. Fixture analyzers in the launcher
- `catalog.py`: `FIXTURE_SPECS` with the four names above and commands such as
  `("python", "/opt/fixture/probe.py", "probe")`. Names start with `fixture-`; `sleep` and
  `flood` keep default limits, so the wall time and output cap are what stops them.
- `config.py`: `sandbox_fixture_analyzers`; validator error when `ENV=prod`
  (`"SANDBOX_FIXTURE_ANALYZERS is not allowed when ENV=prod"`).
- `__main__.py`: `load_catalog(lock, CATALOG + FIXTURE_SPECS if setting else CATALOG)`.
- `.env.example`: the new setting, commented out, false by default.
- Tests (`tests/unit/sandbox_launcher/test_catalog.py`, `test_main.py`, `tests/unit/test_config.py`):
  fixtures absent by default; present when on and in the lock; absent when on but not in the lock;
  setting refused in prod; **guard:** the committed `sandbox-images.lock` has no `fixture-` key,
  and `CATALOG` has no `fixture-` name; every fixture create body passes the real proxy policy.

### 3. End-to-end runtime tests
**Superseded in part by `03-run-sandbox-end-to-end.md`:** the work is two commits (3a locks
`/tmp`, 3b adds the tests), and the skip rule, wall times and checks below changed there.

- `tests/integration/sandbox/conftest.py`: skip unless `RUN_SANDBOX_TESTS=1`, except in CI
  (`CI=true`), where a missing Docker or `runsc` is a failure. Fixtures: `fixture_image_id` (runs
  the build script or reads `SANDBOX_FIXTURE_IMAGE`), `artifact_root` (a real directory under
  `tmp_path` holding one `<uuid>/hello.txt`; the daemon is on the same host, so the bind source
  resolves), a tmp lock `{ "fixture-ok": id, ... }`, the real proxy and launcher servers, and a
  `LauncherSandboxRunner`. The launcher wall time is 3 s, so the timeout test is quick.
- `tests/integration/sandbox/test_runtime.py`, one behavior per test:
  - `test_ok_analyzer_returns_its_json_and_exit_zero`
  - `test_probe_reports_no_network` / `..._input_and_root_read_only` /
    `..._scratch_writable_but_noexec` / `..._non_root_without_capabilities` /
    `..._no_docker_socket_and_clean_environment` (one assertion group each over the probe JSON)
  - `test_probe_runs_under_gvisor_when_runsc_is_required` (gates on `SANDBOX_EXPECT_RUNTIME`)
  - `test_sleeping_analyzer_is_killed_at_the_wall_time` (`timed_out`, and no container left:
    `docker ps -a --filter ancestor=<id>` is empty)
  - `test_flooding_analyzer_fails_with_output_exceeded` (same cleanup check)
  - `test_artifact_outside_the_root_is_refused` (symlink and unknown ID give "not found")
  - `test_launcher_refuses_to_start_in_prod_without_runsc` (real proxy reports `runc` only;
    `select_runtime(..., prod=True, ...)` raises, and `main()` exits non-zero)
- `pyproject.toml`: marker `sandbox_runtime: needs Docker and the built fixture image
  (RUN_SANDBOX_TESTS=1)`. Collected tests excluded from the default `pytest` run unless enabled,
  and `--no-cov` in the CI job, like `web-e2e`.

### 4. CI
**Superseded in part by `04-run-runsc-tests-in-ci.md`:** the release ships as one tarball with
sidecar binaries, and the job's step order changed there.

- `scripts/install-runsc.sh`: pinned release, SHA-512 verified, `runsc install`,
  `sudo systemctl restart docker`, then `docker info` must list `runsc`.
- `.github/workflows/sandbox-images.yml`: `on: pull_request` and `push: main`, with a `paths`
  filter on `sandbox/images/**`, the script and the workflow itself; `permissions: contents: read`;
  runs `scripts/build-sandbox-images.sh`. A `workflow_dispatch` entry for manual runs.
- `.github/workflows/ci.yml`: new job `sandbox` (`timeout-minutes: 15`): checkout (pinned), setup-uv
  (pinned), `uv sync --locked`, `scripts/install-runsc.sh`, build the fixture, then
  `RUN_SANDBOX_TESTS=1 SANDBOX_ALLOW_RUNC=false SANDBOX_EXPECT_RUNTIME=runsc uv run pytest
  tests/integration/sandbox -m sandbox_runtime --no-cov`. Show `docker ps -a` and daemon logs on
  failure.
- Test: `tests/unit/test_workflows.py` checks every `uses:` in the changed workflows is a 40-hex
  SHA and that `sandbox-images.yml` declares only `contents: read`.

### 5. Compose isolation guard
`tests/unit/test_sandbox_compose.py`, reading `docker compose --profile sandbox config
--no-env-resolution --format json` (skipped without Docker, like `test_production_workers.py`):
- only `sandbox-proxy` has `/var/run/docker.sock` among its volumes;
- `sandbox-launcher` and `sandbox-proxy` have no `DATABASE_URL`, `REDIS_URL`, `SECRET_KEY`,
  `APP_ENCRYPTION_KEY` or `env_file`, and the launcher mounts the staging root read-only;
- `worker-analysis` has no Docker socket and is on `sandbox` and `default`; the `sandbox` network
  is `internal`; no sandbox service publishes a port.

### 6. Docs and close-out
`docs/development.md` (running the runtime tests locally: `make sandbox-test`, `SANDBOX_FIXTURE_ANALYZERS`),
`docs/security.md` (the runtime tests prove the ADR 0016 flags; the fixture can never run in prod),
`CHANGELOG.md`, the `AGENTS.md` commands list, and `STATE.md` (overwrite; next step #87, #92).
Then `finish-task` and `pre-pr-check`.

## Open issues to flag in the PR
- **Acceptance criterion vs ADR 0028.** #84 says "`worker-analysis` has no ... artifact mount", but
  ADR 0028 has it stage decrypted artifacts into `SANDBOX_ARTIFACT_ROOT` read-write
  (`compose.yaml:176`). The guard test asserts what ADR 0028 intends (no socket, staging root only,
  read-only in the launcher). The PR description says so, and #84's checkbox wording should be
  corrected when closing it.
- **gVisor on GitHub-hosted runners.** `runsc` needs a working platform (the default `systrap`
  should run on `ubuntu-latest`). If the first run fails for platform reasons, investigate it:
  gVisor no longer supports `ptrace`, so it is not a fallback (see the 04 plan).
- **Proxy bind source on the runner.** The artifact root is under `tmp_path`, which exists on the
  same host as the Docker daemon, so Docker can bind it. This would break on a remote daemon.
- **Known and left alone:** the proxy has no caller authentication (`STATE.md` open thread, #92).

## Git steps (after approval)
```bash
git fetch origin
git switch -c 84-sandbox-ci origin/main     # the two untracked docs/plans/*.md files stay untracked
```
The tip of `main` is `2487c90` and contains #188, so the dependencies (#83, #11, #133, PR 4) are
met. Commits use the `Refs #84` footer and the Co-Authored-By trailer; the last says `Closes #84`.
Never `--no-verify`. Open the PR as a draft until the `sandbox` job is green.

## Verification
- After every commit:
  ```bash
  uv run ruff check . && uv run ruff format --check . && uv run pyright \
    && uv run lint-imports && uv run pytest
  ```
- Locally (needs Docker): `scripts/build-sandbox-images.sh`, then
  `RUN_SANDBOX_TESTS=1 SANDBOX_ALLOW_RUNC=true uv run pytest tests/integration/sandbox --no-cov`
  (runs under `runc` here; the gVisor assertion is skipped without `SANDBOX_EXPECT_RUNTIME`).
- Mutation checks, scratch only, reverted afterwards: drop `"NetworkMode": "none"` in
  `sandbox_launcher/container.py` (the probe network test must fail, though the real proxy refuses
  the body first, so also check the fake-daemon path); lower the wall time so the flood test's
  output check is exercised; remove `ReadonlyRootfs` and confirm the proxy refuses the create.
- CI: the `sandbox` job is green on the PR and its log shows `runsc` as the runtime; `compose` and
  the other jobs are unchanged.
- Before opening the PR: `finish-task`, then `pre-pr-check`.
