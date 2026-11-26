# Plan: PR 5, commit 4: `ci(security): build sandbox images and run runsc tests`

Branch `84-sandbox-ci` · `Refs #84` · follows `cc921db test(infra): run the sandbox end to end
under a real runtime`.

## Context

**In plain words.** Commit 3b added tests that start real sandbox containers, but this machine only
has `runc`, so they have never run under gVisor (`runsc`), the runtime production requires. This
commit adds a CI job that installs a pinned gVisor release on the GitHub runner and runs those
tests under it. It is the first real check that the walls hold under gVisor, including the `/tmp`
lock from 3a. It also adds the image-build workflow that ADR 0018 asks for (it builds only; it
never pushes).

**Technical.** One script (`scripts/install-runsc.sh`), one new workflow
(`.github/workflows/sandbox-images.yml`), one new job in `.github/workflows/ci.yml`, and unit tests
that read the workflow files and run the install script against stubs.

## Findings (gVisor source and release files read at tag `release-20261109.0`)

1. **Pinned release:** `release-20261109.0`, published 2026-11-11 (15 days old today, so the
   two-week rule holds). No published gVisor security advisories. Newer tags (20261116, 20261123)
   are too young.
2. **What to download:** one tarball, `gvisor.tar.zstd`, from
   `https://storage.googleapis.com/gvisor/releases/release/20261109/x86_64/`. It holds `runsc`, the
   containerd shim and a `gvisor-bin/` folder of sidecar binaries that `runsc` needs next to it.
   Its SHA-512 (read from the release's `.sha512` file, 128 hex):
   `0a0041fd862f4ea3042a9db8d41c742f48a01f909699adc2a0256e46d85e53f97b82b9fd154b3dce636f62b8d557677639f91c77d13f3f875ff9fa535275393c`.
   The script carries this value as a constant and never trusts a downloaded checksum file.
3. **`runsc install` can download binaries by itself** when sidecars are missing. Passing
   `--download-sidecars=NEVER --require-sidecars=ALWAYS` means it never fetches anything and fails
   if a sidecar is missing. It keeps the other keys in `daemon.json` and registers the runtime as
   `runsc`.
4. **The `/tmp` lock works as 3a assumed, on paper:** at this tag an explicit `/tmp` mount in the
   spec makes `runsc` skip its own tmpfs. `ro`, `noexec` and `nosuid` are parsed, `size` is passed
   through, `nodev` is ignored with a warning, and none of them stops the container from starting.
5. **Not confirmed in the source:** where `noexec` is enforced on exec, and the uname release
   string (`"4.4.0"` in the tests). The CI run settles both; the tests already check them
   (`scratch_exec_allowed`, `writable_dirs`, `kernel_release`).
6. **The overview's fallback is wrong:** the default platform is `systrap`, and gVisor's docs say
   `ptrace` is no longer supported. If gVisor can't start on the runner, that is investigated, not
   patched with `--platform=ptrace`.
7. All existing workflows already pin every `uses:` to a 40-hex SHA with a `# vX` comment, so the
   pin test can cover every workflow, not just the new ones.
8. PyYAML is in `uv.lock` only through `pre-commit`. The workflow test needs it, so it becomes an
   explicit dev dependency (`uv add --dev pyyaml`, same locked version, no new package).

## Decisions

1. **x86_64 only.** GitHub's `ubuntu-latest` is x86_64, and only that checksum is pinned. The
   script stops with a clear message on any other architecture (this host is aarch64, and its
   Docker daemon is not touched: the script is for CI).
2. **Order inside the job:** build the fixture image → run the prod-refusal test while only `runc`
   exists (`SANDBOX_EXPECT_RUNTIME=runc`, so it fails rather than skips) → install `runsc` → one
   plain `docker run --runtime=runsc` of `fixture-ok` (it tells "gVisor can't start here" apart
   from "a wall failed") → the full suite with `SANDBOX_EXPECT_RUNTIME=runsc`.
3. **`RUN_SANDBOX_TESTS=1` and `SANDBOX_ALLOW_RUNC=false` at job level**, so no step can fall back
   to `runc` quietly. The fixture image ID is built once and passed to later steps through
   `SANDBOX_FIXTURE_IMAGE` (`$GITHUB_ENV`).
4. **`sandbox-images.yml` builds and never pushes.** `permissions: contents: read` only, checkout
   with `persist-credentials: false`. #92 adds `packages: write` to a main-only push job.
5. **A failed run is a finding.** If the `runsc` run shows another writable directory, an
   exec-able one, a different errno or kernel string, I stop and report it before any assertion
   changes. Results go into ADR 0034 (which says "still to be seen") in commit 6.

## Changes

**`scripts/install-runsc.sh`** (`set -euo pipefail`, like `build-sandbox-images.sh`)
- Constants: `GVISOR_RELEASE=20261109` (comment: tag `release-20261109.0`, published 2026-11-11),
  `GVISOR_SHA512=<value above>`.
- Refuse unless `uname -m` is `x86_64`; require `curl`, `sha512sum`, `zstd`, `sudo`, `docker`.
- Download into a `mktemp -d` folder (removed on exit) with
  `curl --fail --location --proto '=https' --tlsv1.2`.
- Check `"$GVISOR_SHA512  gvisor.tar.zstd"` with `sha512sum --check --strict` **before** anything is
  extracted or installed.
- Extract into the temp folder; install `runsc`, `containerd-shim-runsc-v1` and `gvisor-bin/` into
  `/usr/local/bin` with `sudo`.
- `runsc --version` must name `release-20261109.0`.
- `sudo runsc install --download-sidecars=NEVER --require-sidecars=ALWAYS`,
  `sudo systemctl restart docker`, then `docker info --format '{{json .Runtimes}}'` must list
  `runsc`, else fail.

**`.github/workflows/ci.yml`**: new job `sandbox` (name `sandbox (runsc)`, `ubuntu-latest`,
`timeout-minutes: 15`), with the same checkout and setup-uv pins as the other jobs, then
`uv sync --locked` and the steps in Decision 2. On failure it runs `docker ps -a` and
`sudo journalctl -u docker --no-pager -n 200`.

**`.github/workflows/sandbox-images.yml`**: `pull_request` and `push: main` with a `paths` filter
(`sandbox/images/**`, `scripts/build-sandbox-images.sh`, the workflow itself), `workflow_dispatch`;
`concurrency` per ref; one job that runs `scripts/build-sandbox-images.sh`.

**`pyproject.toml` / `uv.lock`**: `pyyaml` in the dev group.

## Tests (written first)

**`tests/unit/test_workflows.py`** (PyYAML reads `on:` as the key `True`; the helper handles it)
- `test_every_action_is_pinned_to_a_commit_sha`: every `uses:` in every workflow is
  `owner/repo[/path]@<40 hex>`, and its line has a `# v…` comment.
- `test_sandbox_images_workflow_can_only_read`: top-level `permissions == {"contents": "read"}`,
  no job sets its own `permissions`, and no step logs in, pushes or sets `push: true`.
- `test_sandbox_images_workflow_runs_when_images_change`: the three triggers and the three paths.
- `test_sandbox_job_never_falls_back_to_runc`: job env `RUN_SANDBOX_TESTS == "1"` and
  `SANDBOX_ALLOW_RUNC == "false"`; the full-suite step expects `runsc`; `timeout-minutes <= 15`.
- `test_prod_refusal_runs_before_runsc_is_installed`: the refusal step expects `runc` and comes
  before the `install-runsc.sh` step, which comes before the full suite.

**`tests/unit/test_install_runsc.py`** (stub `PATH` like `tests/unit/test_backup_scripts.py`)
- `bash -n` passes.
- The release is an 8-digit date at least 14 days before today, and the SHA-512 is 128 hex.
- No `| sh` / `| bash`, no `latest`, and `runsc install` carries both sidecar flags.
- With a stub `curl` that writes junk: the script fails, says the checksum didn't match, and the
  stub log shows **no `sudo` call** (nothing installed).
- With a stub `uname` printing `aarch64`: the script fails before `curl` is called.

## Verification

- Gate: `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run
  lint-imports && uv run pytest`; pre-commit `check-yaml` on the workflows.
- Proof the new tests can fail (scratch edits, reverted): unpin one action to `@v7`; add
  `packages: write` to `sandbox-images.yml`; move the install step before the refusal step; drop
  `SANDBOX_ALLOW_RUNC=false`; change one checksum character (the stub test still fails safely).
- Locally I can't run `install-runsc.sh` (aarch64, and it restarts Docker). Its real proof, and
  the gVisor proof, is the `sandbox` job on GitHub, which needs the branch pushed. When commit 4
  is done I'll ask whether to push and open the draft PR then, so the `runsc` results arrive
  before commits 5 and 6.

## Risks to settle on the first `runsc` run
The errno for no network; the `writable_dirs` set and exec on `/dev/shm`; `noexec` really blocking
exec in `/scratch`; that `/tmp` stays read-only; `kernel_release`; startup within the 60 s wall
time; `systrap` working on the runner. Each failure is reported before anything is loosened.

## Notes for later commits
- **Commit 6:** record the `runsc` results in ADR 0034's consequences; document
  `scripts/install-runsc.sh` and how to bump the pin (new release ≥ 14 days old, new SHA-512,
  reviewed PR).
