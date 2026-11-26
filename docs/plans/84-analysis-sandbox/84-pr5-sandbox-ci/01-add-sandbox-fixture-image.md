# Plan: PR 5, commit 1: `build(infra): add the sandbox fixture analyzer image`

Branch `84-sandbox-ci` (new, from `origin/main`) · `Refs #84` · follows `2487c90 feat(scanners):
check TLS certificates and configuration of web hosts (#200)` (the tip of `main` when this was
planned; see `84-pr5-sandbox-ci-overall-plan.md`).

## Purpose

**In plain words.** Before CI can prove the sandbox really blocks the network, keeps the upload
read-only and kills runaway jobs, it needs something harmless to run inside it. This commit adds
that: a tiny container image holding one small Python script. The script can print a fixed answer,
report what the sandbox lets it do, sleep forever, or print far too much. It also adds one script
that builds the image and prints its ID, so CI, the Makefile and the tests all build it the same
way. Nothing runs the image yet, and nothing in the app changes.

**Technical.** Adds `sandbox/images/fixture/` (a `Dockerfile` and `probe.py`),
`scripts/build-sandbox-images.sh`, a `make sandbox-images` target and a Dependabot entry for the
new base image. `probe.py` is standard library only and takes one mode: `ok`, `probe`, `sleep` or
`flood`. Commit 2 maps four fixed analyzer commands onto these modes; commit 3 runs them for real.

## Context
- `catalog.CATALOG` is `()`, and `sandbox-images.lock` is `{}`. No analyzer image exists, and
  there is no `sandbox/` directory yet.
- The proxy accepts a bare `sha256:<64 hex>` image reference (`_DIGEST` in
  `sandbox_proxy/policy.py` and `sandbox_launcher/catalog.py:19`), so a locally built image works
  by its image ID with no registry.
- The root `Dockerfile` pins `python:3.15-slim@sha256:65a65fc7…` and Dependabot's `docker` entry
  scans only `/` (`.github/dependabot.yml`).
- ADR 0016 fixes the sandbox flags: `/input` read-only, read-only root, `/scratch` tmpfs
  `noexec,nosuid,nodev`, `--network=none`, UID 65532, `cap-drop ALL`, `no-new-privileges`.
  ADR 0018: base images pinned by digest, one image per analyzer, no package managers beyond need.

## Decisions
1. **One image, four modes.** A catalog command is fixed and callers can't pass arguments, so
   each behavior needs its own command. One image with a mode argument keeps it to a single build
   (overview Decision 3).
2. **Same base digest as the root `Dockerfile`.** No new base to vet; the two-week rule is already
   satisfied. A test keeps the two digests equal, and Dependabot scans both directories so it
   proposes both updates at once.
3. **The probe reports facts, the tests judge them.** Every check is a boolean named `*_allowed`
   (did the attempt succeed?) or a raw value (`uid`, `cap_eff`, `kernel_release`). The probe has
   no idea what "correct" is, so commit 3's assertions stay readable and one place owns them.
4. **The probe never prints values from the environment,** only variable names, so it can't leak a
   secret that wrongly reached the sandbox into CI logs.
5. **Paths are module constants** (`INPUT_DIR`, `SCRATCH_DIR`, `ROOT_PROBE_PATH`, `DOCKER_SOCKET`)
   and the network checks go through `socket.create_connection` / `socket.getaddrinfo`, so unit
   tests can point them at `tmp_path` and stub the network. No unit test writes to `/etc` or makes
   a live connection (`AGENTS.md`: no live network in tests).
6. **`USER 65532:65532` in the image as well.** The launcher already sets the user; the image does
   too, as defense in depth if the fixture is ever run by hand.
7. **The build script prints `<name> <image id>` and checks the ID's shape.** With the containerd
   image store the ID is a manifest digest, which is still `sha256:<64 hex>`; the script fails if
   it isn't, so a surprise shows up at build time, not as a proxy refusal in commit 3.
8. **Plain `docker build`, no buildx action.** Nothing new to pin in CI; works on any Docker host.
9. **Docs deferred** to commit 6 (`docs/development.md`, `CHANGELOG.md`, `AGENTS.md` commands).

## Requirements
- [ ] `sandbox/images/fixture/Dockerfile`:
      `# syntax=docker/dockerfile:1`, `FROM python:3.15-slim@sha256:<root Dockerfile digest>`,
      `ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1` (read-only root), `COPY --chmod=0755
      probe.py /opt/fixture/probe.py` (not 0644: BuildKit applies the mode to the directories it
      creates, and user 65532 must be able to enter `/opt/fixture`; a test guards this),
      a `LABEL` saying it is a CI fixture and never an analyzer,
      `USER 65532:65532`. No `RUN`, no package installs, no `CMD` change (the launcher sets `Cmd`).
- [ ] `sandbox/images/fixture/probe.py`, standard library only, `main(argv) -> int`:
  - `ok`: prints `{"status": "ok"}` on one line, exit 0.
  - `probe`: prints one JSON object on one line, exit 0, with keys:
    `network_connect_allowed` (TCP to `1.1.1.1:53`, 2 s timeout),
    `dns_resolve_allowed` (`getaddrinfo("example.com", 443)`),
    `input_files` (count under `INPUT_DIR`, capped at 1000),
    `input_write_allowed` (open the first input file `O_WRONLY`; `null` when there is none),
    `input_create_allowed` (`O_CREAT|O_EXCL` a new file in `INPUT_DIR`),
    `root_write_allowed` (`O_CREAT|O_EXCL` at `ROOT_PROBE_PATH`, default `/etc/.attacksurf-probe`),
    `scratch_write_allowed`, `scratch_exec_allowed` (write a `#!/bin/sh` script into `SCRATCH_DIR`,
    `chmod 0755`, run it; `PermissionError` means blocked),
    `uid`, `gid`, `cap_eff` and `no_new_privs` (from `/proc/self/status`; `null` if absent),
    `docker_socket_present`, `env_names` (sorted names only), `kernel_release`
    (`os.uname().release`; gVisor reports `4.4.0`).
    Any file it creates is removed again. Every check catches `OSError` and reports `false`.
  - `sleep`: `while True: time.sleep(60)`; prints nothing.
  - `flood`: writes 3 MiB of `A` to `sys.stdout.buffer` in 64 KiB chunks, then exits 0.
  - Unknown or missing mode: one line to stderr, exit 2.
- [ ] `scripts/build-sandbox-images.sh`: header comment like `scripts/backup.sh`,
      `set -euo pipefail`, runs from the repo root (`cd "$(dirname "$0")/.."`). Builds every
      directory under `sandbox/images/`, or only the names given as arguments (unknown name:
      error, exit 1). Each image: `docker build --tag attacksurf-sandbox-<name>:ci
      sandbox/images/<name>` (build output to stderr), then `docker image inspect --format
      '{{.Id}}'`, check it matches `^sha256:[0-9a-f]{64}$`, print `<name> <id>` to stdout.
- [ ] `Makefile`: `sandbox-images: ## Build the sandbox fixture image(s) and print their IDs`,
      running `./scripts/build-sandbox-images.sh`; added to `.PHONY`.
- [ ] `.github/dependabot.yml`: the `docker` entry uses
      `directories: ["/", "/sandbox/images/*"]` instead of `directory: /`.
- [ ] Only those five non-test files change, plus tests.

## Acceptance criteria
- [ ] **Builds:** `scripts/build-sandbox-images.sh` prints `fixture sha256:<64 hex>` locally.
- [ ] **Runs under the sandbox flags by hand:** with `docker run --rm --network=none --read-only
      --user 65532:65532 --cap-drop=ALL --security-opt no-new-privileges --tmpfs
      /scratch:rw,noexec,nosuid,nodev,size=64m -v <dir>:/input:ro <id> python
      /opt/fixture/probe.py probe`, every `*_allowed` is `false` except `scratch_write_allowed`.
- [ ] **Gate:** ruff, ruff format, pyright, lint-imports and pytest green; coverage unchanged
      (`probe.py` is outside `src/`).
- [ ] **Tight fit:** `git diff --stat` shows the five files above plus two test files.

## Changes

### 1. `sandbox/images/fixture/probe.py` (~110 lines)
Module docstring: harmless CI fixture for the ADR 0016 runtime tests, never a real analyzer,
standard library only. One small function per check, `probe() -> dict[str, object]`, `main()`.

### 2. `sandbox/images/fixture/Dockerfile` (~12 lines)
As in Requirements.

### 3. `scripts/build-sandbox-images.sh` (~40 lines)
As in Requirements.

### 4. `Makefile` (3 lines) and `.github/dependabot.yml` (1 line)
As in Requirements.

### 5. Tests

#### A. Happy path (`tests/unit/test_sandbox_images.py`)
- `test_fixture_ok_prints_one_json_line`: run `probe.py ok` with `sys.executable -I -S`
  (as `tests/unit/sandbox_tools/test_detect.py:run_cli` does); stdout is exactly one line,
  `{"status": "ok"}`, exit 0.
- `test_fixture_flood_prints_more_than_the_output_cap`: run `flood`; stdout > 2 MiB (the
  `stream.py` cap, imported, not copied).
- `test_fixture_probe_reports_every_key`: load the module with
  `importlib.util.spec_from_file_location`, monkeypatch the path constants to `tmp_path`
  subfolders and the two socket functions to raise `OSError`; `probe()` returns exactly the
  documented keys and JSON-serialises.
- `test_build_script_builds_each_image_and_prints_its_id`: stub `docker` on `PATH` (the
  `tests/unit/test_backup_scripts.py` technique) that logs its args and answers `inspect` with a
  fixed `sha256:` ID; stdout is `fixture sha256:…`, and the logged build has the tag and context.

#### B. Boundary cases
- `test_fixture_probe_reports_scratch_writable_and_input_blocked_by_permissions`: `INPUT_DIR` a
  `0o555` dir holding a `0o444` file, so `input_*_allowed` is `false` and `scratch_write_allowed`
  `true` without any container. Skip when running as root (root ignores modes).
- `test_fixture_probe_never_prints_environment_values`: set `PROBE_SECRET=s3cr3t`; output holds
  the name, never the value.
- `test_fixture_probe_cleans_up_what_it_created`: `tmp_path` scratch and root-probe locations are
  empty afterwards.

#### C. Invalid inputs
- `test_fixture_rejects_an_unknown_mode`: `nope` and no argument both exit 2 with empty stdout.
- `test_build_script_rejects_an_unknown_image_name`: exit non-zero, `docker` never called.
- `test_build_script_fails_when_the_image_id_is_malformed`: stub `inspect` prints `abc`; exit
  non-zero, nothing on stdout.
- `test_build_script_fails_when_docker_build_fails`: stub `build` exits 1; exit non-zero.

#### D. Neighbor rejection and drift guards
- `test_fixture_base_image_matches_the_app_base`: both `FROM` lines carry the same `@sha256:`
  digest.
- `test_every_sandbox_image_pins_its_base_by_digest`: every `sandbox/images/*/Dockerfile` `FROM`
  has `@sha256:<64 hex>` (covers #92's images later).
- `test_fixture_probe_imports_only_the_standard_library`: `ast` walk of `probe.py`; every
  top-level import name is in `sys.stdlib_module_names`.
- `test_fixture_image_runs_as_the_sandbox_user`: the Dockerfile's `USER` is `65532:65532`, equal
  to the UID in `sandbox_launcher/container.py` (imported, not copied).
- `test_dependabot_watches_the_sandbox_images`: the `docker` entry lists `/sandbox/images/*`
  (text check; PyYAML is only a transitive dependency).
- `tests/unit/test_makefile.py`: `test_make_sandbox_images_runs_the_build_script` via
  `make -n sandbox-images`.

## Order of work (red → green)
1. Write the tests above; run them, watch them fail (missing files).
2. Add `probe.py` and the `Dockerfile`; fixture tests go green.
3. Add the build script, Makefile target and Dependabot entry; the rest go green.
4. Check whether `pyproject.toml`'s pyright `include` reaches `sandbox/`; if not, run
   `uv run pyright sandbox/images/fixture/probe.py` once by hand (no config change in this commit).
5. Build for real and run the acceptance `docker run` by hand (needs Docker).
6. Gate: `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run
   lint-imports && uv run pytest`.
7. Commit with the subject above. Body: why one image with fixed modes and why the image ID is
   enough (no registry). Footer `Refs #84`, then the Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `tests/unit/sandbox_tools/test_detect.py:run_cli`: the `-I -S` subprocess pattern.
- `tests/unit/test_backup_scripts.py:_write_executable` / `_install_stub_bin`: the stub-`docker`
  pattern (copied locally; it is a private helper).
- `tests/unit/test_makefile.py`: the `make` harness.
- `sandbox_launcher/stream.py` (output cap) and `sandbox_launcher/container.py` (sandbox UID):
  imported by the tests so the values can't drift.

## Verification
- `scripts/build-sandbox-images.sh` then `make sandbox-images`: same `fixture sha256:…` line.
- The acceptance `docker run … probe` by hand under `runc`; with gVisor installed, repeat with
  `--runtime=runsc` and confirm `kernel_release` is `4.4.0`.
- `git diff --stat HEAD~1`: five non-test files and two test files.

## Notes for later commits
- **Commit 2:** `FIXTURE_SPECS` commands are `("python", "/opt/fixture/probe.py", "<mode>")`;
  names `fixture-ok`, `fixture-probe`, `fixture-sleep`, `fixture-flood`.
- **Commit 3:** asserts on the probe keys from Decision 3. If `kernel_release` isn't a reliable
  gVisor marker on the CI runner, read `/proc/version` there instead, in that commit.
- **Commit 4:** the `sandbox-images.yml` `paths` filter includes `sandbox/images/**` and
  `scripts/build-sandbox-images.sh`.
- **Commit 6:** documents `make sandbox-images`.
