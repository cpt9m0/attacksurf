# Plan: PR 3c, commit 4: `feat(security): refuse to start the launcher without runsc in prod`

Branch `84-sandbox-launcher-service` · `Refs #84` · follows `feat(infra): serve the sandbox
launcher api` (commit 3 of PR 3c; see `../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** The sandbox is only as strong as the container runtime under it. gVisor
(`runsc`) adds a second wall between a hostile tool and the server; plain `runc` does not. This
commit makes the launcher check, before it accepts any work, which runtimes Docker really has. In
production it refuses to start without gVisor. On a developer machine it may fall back to `runc`,
but only when someone has switched that on explicitly. If it can't ask the proxy at all, it
doesn't start either. It never quietly runs with a weaker sandbox than intended.

**Technical.** Adds `sandbox_launcher/__main__.py` with `select_runtime(names, *, prod,
allow_runc) -> str` and `main()`, the `python -m attacksurf.sandbox_launcher` entry point.
`main()` loads `SandboxLauncherSettings`, `load_catalog(Path(settings.sandbox_images_lock))`,
`ProxyClient.from_url(settings.sandbox_proxy_url.get_secret_value())`, asks `runtimes()` (the
proxy's `GET /info`, ADR 0023), picks the runtime, logs it, and serves `make_server(...)` with
`run_sandbox` bound to that runtime and `settings.sandbox_wall_time_seconds`. Any failure raises
`SystemExit` with a fixed message. Implements ADR 0016 "In prod it refuses to start unless `runsc`
is a registered Docker runtime" and ADR 0023's startup rule.

## Context
PR 3a made the proxy answer `GET /info` with runtime names only. PR 3b's settings already refuse
`SANDBOX_ALLOW_RUNC=true` with `ENV=prod`. Commit 2 added `ProxyClient.runtimes()`; commit 3 added
`make_server`. Nothing yet starts the launcher process. It is a separate commit because it is the
one security gate that runs before any request, and its rules are tested as a pure function.

## Decisions
1. **Pure `select_runtime`.** `select_runtime(names: Collection[str], *, prod: bool,
   allow_runc: bool) -> str`: `"runsc"` if listed; else `"runc"` when `not prod and allow_runc
   and "runc" in names`; else `RuntimeUnavailable`. `runsc` always wins when present, even with
   the fallback on. `prod and allow_runc` can't reach here (settings refuse it), but the
   function still never returns `runc` in prod.
2. **Exit, don't retry.** Proxy unreachable, a malformed `/info` reply, a bad lock, a bad proxy
   URL or no usable runtime → `SystemExit("sandbox launcher: <fixed reason>")`, non-zero. Compose
   restarts the service (PR 4, with `depends_on` the proxy's health). A retry loop here would hide
   a broken host behind a running-but-useless service.
3. **One startup log line.** `sandbox_launcher_started` with runtime, analyzer count, host and
   port; with `runc` it is a warning-level `sandbox_launcher_runc_fallback` too, so a dev
   fallback is visible. The proxy URL is never logged.
4. **The runtime is fixed for the process.** Chosen once at startup and bound into the `run`
   callable; the proxy still enforces its own runtime allowlist on every create. Re-checking per
   run was rejected: the proxy caches `/info` for 60 s anyway and the per-create check is the real
   guard.
5. **Empty catalog is allowed.** With `CATALOG = ()` the launcher starts and every `POST /runs`
   is 404 (PR 5 adds the fixture analyzer). Refusing to start would block the PR 4 compose wiring.
6. **No docs in this commit.** Commit 5 of PR 3c carries the docs, `CHANGELOG.md` and `STATE.md`.

## Requirements
- [ ] `src/attacksurf/sandbox_launcher/__main__.py` exists with `RuntimeUnavailable`,
      `select_runtime`, `main`, and `if __name__ == "__main__": main()`.
- [ ] `select_runtime` follows decision 1 exactly.
- [ ] `main()` order: settings → catalog → proxy client → `runtimes()` → `select_runtime` → log →
      `make_server(...).serve_forever()`.
- [ ] `run` bound as `run_sandbox(proxy, analyzer, artifact_dir, runtime=<chosen>,
      wall_time=settings.sandbox_wall_time_seconds)`.
- [ ] `SystemExit` with a fixed, value-free message for each failure in decision 2.
- [ ] The proxy URL and paths never appear in logs or exit messages.
- [ ] No change to `config.py`, `pyproject.toml`, `sandbox_proxy/` or other launcher modules.

## Acceptance criteria
- [ ] **Rule table:** `select_runtime` returns/raises as specified for every combination in the
      table below.
- [ ] **Startup:** `main()` against the real proxy + `FakeDocker` with `runsc` listed builds the
      server with runtime `runsc` (`serve_forever` patched to return).
- [ ] **Negative:** prod without `runsc`, dev without fallback, proxy unreachable and a malformed
      `/info` reply each end in `SystemExit` with a non-zero code.
- [ ] **No leakage:** a proxy URL marker never appears in logs or the exit message.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%; the commit passes the hooks without `--no-verify`.

## Changes

### 1. `src/attacksurf/sandbox_launcher/__main__.py` (~55 lines)
- Docstring: the entry point and the ADR 0016 / 0023 startup rule.
- `RuntimeUnavailable`, `select_runtime`, `_fail(reason) -> NoReturn`, `main`.

### 2. Tests, `tests/unit/sandbox_launcher/test_main.py` (written first)
Settings built with `settings_from_env()`/`clean_env` or by patching
`SandboxLauncherSettings` to return `make_settings`-style instances; `serve_forever` patched on
`LauncherServer`; a tmp images lock (`{}`).

#### A. Happy path
| Test | Given | Expect |
|---|---|---|
| `test_select_runtime_prefers_runsc` (param prod/dev × fallback on/off where valid) | `runsc` and `runc` listed | `"runsc"` |
| `test_main_serves_with_the_chosen_runtime` | real proxy, `runsc` listed | server built; bound runtime `runsc`; started log |

#### B. Boundary cases
| Test | Given | Expect |
|---|---|---|
| `test_select_runtime_falls_back_to_runc_only_when_allowed_outside_prod` | dev, `allow_runc`, only `runc` | `"runc"` |
| `test_main_logs_the_runc_fallback` | dev fallback | `sandbox_launcher_runc_fallback` event |
| `test_main_starts_with_an_empty_catalog` | lock `{}` | server built |

#### C. Refusals (`RuntimeUnavailable` / `SystemExit`, fixed messages)
| Test | Given | Expect |
|---|---|---|
| `test_select_runtime_refuses_without_runsc_in_prod` (param names `[]`, `["runc"]`) | prod | `RuntimeUnavailable` |
| `test_select_runtime_refuses_runc_without_the_fallback` | dev, fallback off, `["runc"]` | `RuntimeUnavailable` |
| `test_select_runtime_refuses_when_neither_is_listed` | dev, fallback on, `["io.containerd.runc.v2"]` | `RuntimeUnavailable` |
| `test_select_runtime_never_returns_runc_in_prod` | prod, `allow_runc=True`, `["runc"]` | `RuntimeUnavailable` |
| `test_main_exits_when_the_proxy_is_unreachable` | closed port | `SystemExit`, non-zero |
| `test_main_exits_on_a_malformed_info_reply` | fake info body without `Runtimes` (proxy 502) | `SystemExit` |
| `test_main_exits_without_runsc_in_prod` | prod, info lists `runc` only | `SystemExit` |

#### D. Leakage guard
| Test | Given | Expect |
|---|---|---|
| `test_exit_messages_and_logs_omit_the_proxy_url` | URL with a marker host, unreachable | marker absent from message and logs |

## Order of work (red → green)
1. Write `test_main.py`; run it; confirm it fails on the missing module.
2. Implement `__main__.py` until the file passes.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. `finish-task` deferred to commit 5; `pre-pr-check` self-review.
5. Commit with subject `feat(security): refuse to start the launcher without runsc in prod`, a
   body explaining *why* (a misconfigured host fails fast instead of running weaker sandboxes),
   footer `Refs #84`, and the Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `config.py`: `SandboxLauncherSettings`.
- `sandbox_launcher/catalog.py`: `load_catalog`; `proxy.py`: `ProxyClient`, `ProxyError`;
  `runner.py`: `run_sandbox`; `server.py`: `make_server`.
- `sandbox_proxy/__main__.py`: entry-point shape.
- `tests/docker_fakes.py`, `tests/helpers.py` (`settings_from_env`, `clean_env`).

## Verification
- `uv run pytest tests/unit/sandbox_launcher -q` green, then the full suite with coverage >= 80%.
- Mutation check (scratch only): drop `not prod` from the fallback rule → the prod test fails.
- Manual smoke (empty catalog): run `python -m attacksurf.sandbox_proxy` with
  `SANDBOX_ALLOW_RUNC=true` and the launcher with the same; `curl :8791/healthz` → 200,
  `POST /runs` with any analyzer → 404. Without Docker, the launcher must exit non-zero.

## Notes for later commits
- **Commit 5 (docs):** document the start-up rule and the exit behaviour in
  `docs/security.md` and `docs/development.md`.
- **PR 4 (compose):** `sandbox-launcher` runs `python -m attacksurf.sandbox_launcher`,
  `depends_on: sandbox-proxy: condition: service_healthy`, `restart: unless-stopped`; prod hosts
  need `runsc` in `daemon.json` before deploy.
