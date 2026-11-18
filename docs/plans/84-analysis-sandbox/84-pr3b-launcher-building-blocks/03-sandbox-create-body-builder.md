# Plan: PR 3b, commit 3: `feat(infra): build sandbox create bodies the proxy accepts`

Branch `84-sandbox-launcher-core` · `Refs #84` · follows `2fd8ab1 feat(infra): add sandbox analyzer
catalog and artifact resolver` (commit 2 of PR 3b; see `../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** To analyze an uploaded file safely, we start a throwaway locked-down box
(a "sandbox") and put the file inside it, read-only. A separate guard in front of Docker checks
every request to start such a box and says no to anything that is not *exactly* the approved
recipe. This commit writes the recipe-maker: given "which analyzer" and "which folder", it fills
in the one approved recipe, with no network, no write access, hard memory/CPU/time-style limits
and nothing else. Nobody can pass in their own settings, so the recipe-maker can't be talked into
making a looser box. A test hands every recipe to the real guard to prove they agree.

**Technical.** Adds `sandbox_launcher/container.py` with the pure function
`build_create_body(analyzer, artifact_dir, runtime) -> dict` that renders the ADR 0016 Docker
`POST /containers/create` body from an `Analyzer` (fixed command, `SandboxLimits`, lock digest)
and the directory returned by `resolve_artifact`. The body must satisfy
`sandbox_proxy.policy.validate_create` field for field (exact key sets, `NetworkMode: none`,
read-only rootfs, `AutoRemove`, `CapDrop: ["ALL"]`, `no-new-privileges`, `LogConfig: none`, swap
= memory, both ulimits, `/scratch` tmpfs, one `:ro` bind at `/input`). It does no I/O and imports
nothing outside `sandbox_launcher` (ADR 0016: the launcher never shares code with the proxy's
policy). A contract test runs every body through the **real** `validate_create`, so a drift on
either side fails CI.

## Context
Commit 2 produced `Analyzer(spec, image)` and `resolve_artifact(root, uuid) -> {root}/{uuid}`.
Nothing yet turns those into the request the proxy will accept; commit 3c's `runner.py` needs it
as its first call. Keeping it a separate pure module means the proxy contract is tested here, with
no HTTP or Docker involved.

## Decisions
1. **Signature takes `Analyzer`, not `(spec, digest, ...)`** as the split plan sketched: commit 2
   already bundles the lock digest into `Analyzer.image`. Signature:
   `build_create_body(analyzer: Analyzer, artifact_dir: Path, runtime: str) -> dict[str, Any]`.
2. **Duplicated constants, guarded by tests.** `SANDBOX_USER = "65532:65532"`,
   `OSV_ANALYZER = "osv-scanner"` and `OSV_BIND = "attacksurf_osv:/data/osv:ro"` are copied into
   `container.py` (launcher must not import `sandbox_proxy`); a parity test compares them to
   `sandbox_proxy.policy`, as commit 2 did for the ceilings.
3. **Only the command comes from the catalog: `Cmd`, never `Entrypoint`.** The image's own
   entrypoint stays. Stdout is attached; stderr/stdin/tty are left off (the proxy requires it;
   the `attach` call is also stdout-only), so stderr never reaches the launcher.
4. **The OSV bind is keyed on the analyzer name `osv-scanner`**, mirroring the proxy, which only
   accepts that bind when the image equals the lock's `osv-scanner` digest.
5. **Defensive checks in the builder** (the proxy would refuse these anyway, but a clear local
   error beats a 403): `artifact_dir` must be absolute and contain no `:` (a colon would let a
   path smuggle extra bind options such as `:rw`); `runtime` must be `runsc` or `runc`.
6. **Wall time is not in the body.** The launcher enforces it by killing the container (3c).
7. **No docs in this commit.** Commit 5 of PR 3b carries `AGENTS.md`, `docs/architecture.md`,
   `CHANGELOG.md` and `STATE.md`.

## Requirements
- [ ] `src/attacksurf/sandbox_launcher/container.py` exists, pure (no I/O, no network, no Docker
      client), and imports only stdlib plus `sandbox_launcher.catalog`.
- [ ] `build_create_body` returns a JSON-serializable body with exactly these top-level keys:
      `Image` (= `analyzer.image`), `User` (`65532:65532`), `Cmd` (= `list(spec.command)`),
      `AttachStdout: true`, `HostConfig`.
- [ ] `HostConfig` has exactly: `Runtime`, `NetworkMode: "none"`, `ReadonlyRootfs: true`,
      `AutoRemove: true`, `CapDrop: ["ALL"]`, `SecurityOpt: ["no-new-privileges"]`,
      `Binds`, `Tmpfs`, `NanoCpus`, `Memory`, `MemorySwap` (= `Memory`), `PidsLimit`, `Ulimits`,
      `LogConfig: {"Type": "none"}`.
- [ ] Limits map from `SandboxLimits`: `nano_cpus`→`NanoCpus`, `memory_bytes`→`Memory`/`MemorySwap`,
      `pids`→`PidsLimit`, `scratch_bytes`→`Tmpfs["/scratch"]` `size=`, `open_files`→`nofile`
      soft=hard, `file_bytes`→`fsize` soft=hard.
- [ ] `Tmpfs` is `{"/scratch": "rw,noexec,nosuid,nodev,size=<scratch_bytes>"}` and nothing else.
- [ ] `Binds` is `["<artifact_dir>:/input:ro"]`, plus `attacksurf_osv:/data/osv:ro` **only** when
      `analyzer.spec.name == "osv-scanner"`.
- [ ] `ValueError` (message without the path) for a relative `artifact_dir`, a path containing
      `:`, or a runtime other than `runsc`/`runc`.
- [ ] Each call returns fresh nested objects (mutating one body never changes another or the
      spec's `command` tuple).
- [ ] Constants copied from the proxy are covered by a parity test.
- [ ] No change to `sandbox_proxy`, `catalog.py`, `artifacts.py`, `config.py` or `pyproject.toml`
      (the existing launcher isolation contract already covers the new module).

## Acceptance criteria
- [ ] **Contract:** for the default limits and for limits set exactly to each proxy ceiling, the
      body passes the real `sandbox_proxy.policy.validate_create` under a policy built from the
      same image, runtime and artifact root, for both `runsc` and `runc`.
- [ ] **Contract (OSV):** an `osv-scanner` body passes when the policy's `osv_image` is that
      digest, and is rejected when it is not (proves the bind is conditional on the right image).
- [ ] **Contract (non-OSV):** a non-OSV body never contains the OSV bind.
- [ ] **Tight fit:** an exact-body (golden) test for the default analyzer pins every key and
      value, so any added or changed field is a visible test diff.
- [ ] **Catalog guard:** every spec in `CATALOG` (vacuous while empty) builds a body that passes
      `validate_create`; this keeps future analyzers honest.
- [ ] **Negative:** relative path, `/root/x:rw`-style path and unknown runtime raise `ValueError`;
      the message does not contain the path.
- [ ] **Isolation:** `uv run lint-imports` passes, so `container.py` imports nothing the contract
      forbids; no import of `sandbox_proxy` in source (tests only).
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage ≥ 80%; the commit passes the hooks without `--no-verify`.

## Changes

### 1. `src/attacksurf/sandbox_launcher/container.py` (~60 lines)
- Module docstring: the one place the ADR 0016 body is spelled out; why constants are copied.
- `SANDBOX_USER`, `OSV_ANALYZER`, `OSV_BIND`, `_RUNTIMES = frozenset({"runsc", "runc"})`.
- `build_create_body(...)` as above, composed of small helpers (`_binds`, `_ulimits`, `_scratch`)
  so each field is traceable to a limit. Reuses `Analyzer`/`SandboxLimits` from
  `sandbox_launcher/catalog.py`; no new dataclasses.

### 2. Tests, `tests/unit/sandbox_launcher/test_container.py` (written first)
Style follows `tests/unit/sandbox_proxy/test_policy.py` (its `create_body()` fixture is the
reference for the golden body). The file is split into four sections by scenario type, each under
a comment banner, so a reader can see what is covered at a glance. Policy under test is built as
`SandboxPolicy(images=frozenset({image}), runtimes=frozenset({runtime}),
artifact_root=PurePosixPath(root), osv_image=...)`.

#### A. Happy path (valid input → the exact body, accepted by the proxy)
| Test | Given | Expect |
|---|---|---|
| `test_default_analyzer_builds_the_exact_adr_body` | echo analyzer, default limits, `runsc` | full dict equals the golden body (pins every key and value) |
| `test_body_is_accepted_by_the_proxy_policy` (param `runsc`, `runc`) | same, policy allows that runtime | `validate_create` does not raise |
| `test_each_limit_lands_in_its_own_field` (param, one per `SandboxLimits` field) | one custom value | only the mapped field(s) change (`Memory` and `MemorySwap` together; `nofile`/`fsize` soft = hard; `size=` in tmpfs) |
| `test_cmd_and_image_come_from_the_analyzer` | spec command `("/analyze", "/input")` | `Cmd == [..]` (a list), `Image == analyzer.image`, no `Entrypoint` key |
| `test_osv_scanner_gets_the_osv_bind` | analyzer named `osv-scanner`, policy `osv_image` = its digest | both binds present, `validate_create` passes |
| `test_other_analyzers_never_get_the_osv_bind` | echo analyzer | `Binds` is only the `/input:ro` bind |
| `test_body_is_json_serializable` | any valid body | `json.loads(json.dumps(body)) == body` |
| `test_each_call_returns_fresh_objects` | two calls, mutate one | other body and `spec.command` unchanged |
| `test_resolved_artifact_path_feeds_the_builder` | `resolve_artifact(tmp_root, uuid)` result | body passes `validate_create` with `artifact_root` = that root |
| `test_every_catalog_spec_builds_an_accepted_body` (param over `CATALOG`) | each real spec | passes; vacuous while `CATALOG` is empty, guards future analyzers |

#### B. Boundary cases (edges of what is allowed)
| Test | Given | Expect |
|---|---|---|
| `test_limits_at_each_proxy_ceiling_are_accepted` (param per field + all at once) | `SandboxLimits` set exactly to the ceiling | `validate_create` passes (includes the 8 GiB `size=` string) |
| `test_limits_at_the_minimum_of_one_are_accepted` (param per field) | each limit = 1 | body built and accepted |
| `test_single_item_command_is_kept` | `command=("/run",)` | `Cmd == ["/run"]` |
| `test_osv_bind_matches_the_name_exactly` (param `osv`, `osv-scanner2`, `my-osv-scanner`) | near-miss names | no OSV bind |
| `test_artifact_dir_with_dots_hyphens_underscores_is_accepted` | root like `/srv/art.if_acts-1/<uuid>` | bind is that exact string; passes `validate_create` |
| `test_deep_artifact_root_is_accepted` | root several levels deep | passes with matching `artifact_root` |

One above a ceiling is not a builder case: `SandboxLimits` already rejects it (commit 2's
`test_catalog.py`), so such a value can never reach `build_create_body`.

#### C. Invalid inputs (must raise `ValueError`, message never echoes the input)
| Test | Given | Expect |
|---|---|---|
| `test_relative_artifact_dir_is_rejected` (param `Path("a/b")`, `Path("./x")`) | non-absolute path | `ValueError` |
| `test_artifact_dir_with_a_colon_is_rejected` (param `/srv/a:rw`, `/srv/a:/etc:rw`, `/srv/a:`) | path that could add bind options | `ValueError` |
| `test_unknown_runtime_is_rejected` (param `""`, `"kata"`, `"RUNSC"`, `"runsc "`) | runtime outside `{runsc, runc}` | `ValueError` |
| `test_error_messages_do_not_echo_inputs` | each case above | `str(exc)` contains neither the path nor the runtime value |

#### D. Proxy rejection and drift guards (the contract, including its error side)
| Test | Given | Expect |
|---|---|---|
| `test_osv_body_is_refused_when_the_policy_has_no_osv_image` | `osv-scanner` body, `osv_image=None` or another digest | `PolicyViolation` (proves the bind depends on the right image) |
| `test_body_is_refused_for_an_image_not_on_the_allowlist` | policy lists a different digest | `PolicyViolation` |
| `test_body_is_refused_when_the_runtime_is_not_allowed` | `runc` body, policy allows only `runsc` | `PolicyViolation` |
| `test_body_is_refused_outside_the_artifact_root` | policy root differs from the dir's root | `PolicyViolation` |
| `test_copied_constants_match_the_proxy` | `SANDBOX_USER`, `OSV_ANALYZER`, `OSV_BIND` vs `sandbox_proxy.policy` | equal |

Section D shows the builder cannot silently widen the sandbox: the proxy keeps refusing anything
the builder is not meant to produce. Parity and contract tests may import both packages; only
source modules are isolated.

## Order of work (red → green)
1. Write `test_container.py`; run `uv run pytest tests/unit/sandbox_launcher/test_container.py`.
   Confirm it fails on the missing module (expected reason).
2. Implement `container.py` until the file passes.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. Commit on `84-sandbox-launcher-core` with subject
   `feat(infra): build sandbox create bodies the proxy accepts`, body explaining *why* (the proxy
   is exact-match, so a builder and a contract test), footer `Refs #84`, and the Co-Authored-By
   trailer. Never `--no-verify`.

## Reused code
- `sandbox_launcher/catalog.py`: `Analyzer`, `AnalyzerSpec`, `SandboxLimits`, `LIMIT_CEILINGS`,
  `CATALOG`.
- `sandbox_launcher/artifacts.py`: `resolve_artifact` (in one integration test).
- `sandbox_proxy/policy.py`: `validate_create`, `SandboxPolicy`, `SANDBOX_USER`, `OSV_*`, `MAX_*`
  (tests only; never imported by source).

## Verification
- `uv run pytest tests/unit/sandbox_launcher -q` green, then the full suite with coverage ≥ 80%.
- `uv run lint-imports` passes. Scratch-only negative check (revert afterwards): add
  `import httpx` to `container.py` and confirm the launcher contract fails.
- Mutation check (scratch only): change `NetworkMode` to `"bridge"` or drop `LogConfig` in the
  builder and confirm the contract test fails with a `PolicyViolation`.
- Optional shell smoke: build a body for a fake analyzer, `json.dumps` it, and `validate_create`
  it.

## Notes for later commits
- **Commit 4 (`stream.py`):** independent of this module.
- **3c `runner.py`:** `POST /containers/create` with `json.dumps(build_create_body(...))`; the
  proxy replies 403 with a generic message on a violation, which `runner` maps to a 503/failed
  run. `runtime` comes from the startup `/info` check (`runsc` in prod).
- **PR 4 (compose):** the artifact root must be mounted into the launcher at the same absolute
  path as on the host, since this body binds that exact string.
