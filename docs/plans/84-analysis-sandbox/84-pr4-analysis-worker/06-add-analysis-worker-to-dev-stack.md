# Plan: PR 4, commit 6: `feat(workers): add the analysis worker to the dev stack`

Branch `84-analysis-worker` · `Refs #84` ·
follows `feat(infra): add the sandbox proxy and launcher to the dev stack` (commit 5 of PR 4; see
`84-pr4-analysis-worker-overall-plan.md`).

## Purpose

**In plain words.** This adds the last piece of the local setup: a worker that reads the analysis
queue and knows where the launcher is.
- **Like the AI worker:** it is built the same way as the existing AI worker.
- **Opt-in:** it starts only with the opt-in `sandbox` services.
- **The only one:** it is the only app service told the launcher's address.

Production still gets none of this. A comment in the production file says why, the same way the
AI worker's comment does.

Until the analysis tasks themselves exist (#87/#101), this worker throws away the upload jobs it
receives. They stay marked "queued", which is how they look today.

**Technical.**
- **`compose.yaml`:** adds `worker-analysis`:
  - `<<: *worker` with `profiles: [sandbox]`;
  - command `celery -A attacksurf.workers.app worker -Q analysis -c 2 -n analysis@%h --loglevel INFO`;
  - a healthcheck merged from `*worker-health` with `-d analysis@$$HOSTNAME`;
  - `networks: [default, sandbox]`;
  - `environment` merging `*app-env` with `SANDBOX_LAUNCHER_URL: http://sandbox-launcher:8791` and
    `SANDBOX_ARTIFACT_ROOT: ${SANDBOX_ARTIFACT_ROOT:-/tmp/attacksurf-sandbox}`;
  - `volumes` repeating the `x-app` list plus the same-path staging folder, read-write;
  - `depends_on` repeating `x-app`'s plus `sandbox-launcher: service_healthy`.
- **`x-app` comment from 3d:** "This stack has no sandbox launcher yet…" is rewritten.
- **`compose.prod.yaml`:** the `worker-passive` comment gains "`worker-analysis` and the sandbox
  services stay out until the first analysis task (#92, ADR 0029)".
- **`Makefile` `down`:** becomes `$(COMPOSE) --profile sandbox down`, so it also stops opt-in
  services. A new `tests/unit/test_makefile.py` test pins it.

This needs PR 3d: `Settings.sandbox_launcher_url` and `runtime.sandbox_runner()` exist only there.

## Context
PR 3d gives three things:
- `Settings.sandbox_launcher_url` (`SecretStr | None`, plain `http://host[:port]` only);
- `workers.runtime.sandbox_runner()`, which returns `LauncherSandboxRunner` when the URL is set;
- `_fresh_db_pool` clearing that cache after fork (`workers/app.py`).

Commit 5 gives the `sandbox` network and the running launcher. Commit 3 made `analysis` a consumed
queue.

The pattern to copy is `worker-ai` (`compose.yaml:90-97`): `<<: *worker`, its own `-Q` and `-n`,
and a healthcheck `<<: *worker-health` with its own `test`.

This is a separate commit because it is the only part of PR 4 that depends on 3d.

## Decisions
1. **Copy `worker-ai`, not a new pattern.** It uses the same anchor, flags and healthcheck shape.
   `-c 2` matches `worker-ai`; analysis runs are long and capped by the launcher's
   `sandbox_max_concurrent_runs` (default 2) anyway.
2. **The launcher URL only on this service.** Other workers keep the 3d default (empty, so every
   sandbox request is refused). Only the worker that runs analysis needs it.
   - The `x-app` line `SANDBOX_LAUNCHER_URL: ${SANDBOX_LAUNCHER_URL:-}` stays; its comment changes
     to say `worker-analysis` sets it.
   - Merging `environment` with `<<: *app-env` keeps everything else identical.
3. **Lists are repeated, not merged.** Compose's `<<` replaces lists. `volumes` and `depends_on`
   from `x-app` are therefore written out again, as the `x-app` comment ("a merge replaces
   lists") already warns.
4. **Two networks.** `default` for Postgres and Redis, `sandbox` for the launcher. The worker is
   the only service on both, matching ADR 0016's chain.
5. **Staging folder read-write here.** The worker stages decrypted artifacts (ADR 0028,
   `infra.storage.LocalArtifactStore`). The launcher mounts it read-only.
6. **The fate of upload jobs in dev.** Celery acknowledges and drops a message for an
   unregistered task, so `analysis.code_scan` and `analysis.binary_static` jobs sent while this
   worker runs are lost in dev (their rows stay `queued`). This is accepted and documented: it is
   dev-only and opt-in, and #87/#101 register the tasks. Prod is unaffected (Decision 1 of the
   overview).
7. **`make down` stops profile services.** Without `--profile sandbox`, `down` leaves
   `worker-analysis` running, so it can't remove the default network. The flag is harmless when
   no sandbox service runs. `make up` stays without the profile.
8. **Docs in this commit.** Only the comments in the two compose files. Everything else comes in
   commits 7 and 8.

## Requirements
- [ ] `compose.yaml` `worker-analysis` matches the Technical paragraph exactly.
- [ ] No other app service sets `SANDBOX_LAUNCHER_URL` to a non-empty value.
- [ ] The `x-app` comment no longer says the stack has no launcher.
- [ ] `compose.prod.yaml` changes only in a comment. `config --services` output is unchanged.
- [ ] `Makefile` `down` runs `$(COMPOSE) --profile sandbox down`.
- [ ] `.env.example`: the 3d `SANDBOX_LAUNCHER_URL` comment says Compose sets it for
      `worker-analysis`, and its example port is 8791 (fixes the leftover 8080 from 3d).
      This file is read-protected in this environment, so the edit needs your approval.

## Acceptance criteria
- [ ] **Contract (chain):** `docker compose --profile sandbox up -d --wait` ends with all services
      healthy, including `worker-analysis`.
- [ ] **Contract (client wired):** inside `worker-analysis`,
      `python -c "from attacksurf.workers import runtime; print(type(runtime.sandbox_runner()).__name__)"`
      prints `LauncherSandboxRunner`. The same command in `worker-passive` prints
      `UnconfiguredSandboxRunner`.
- [ ] **Contract (reachable):** inside `worker-analysis`,
      `python -c "import urllib.request; print(urllib.request.urlopen('http://sandbox-launcher:8791/healthz').status)"`
      prints 200.
- [ ] **Negative:** `docker compose config --services` (no profile) does not list
      `worker-analysis`. `compose.prod.yaml`'s `config --services` is unchanged.
- [ ] **Tight fit (Makefile):** `test_make_down_also_stops_opt_in_sandbox_services` pins
      `["--profile", "sandbox", "down"]`.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%. Hooks pass without `--no-verify`.

## Changes

### 1. `compose.yaml` (~30 lines)
- `worker-analysis` after `worker-ai`, with a comment: consumes `analysis` (ADR 0029); the only
  service with the launcher URL; unknown `analysis.*` tasks are dropped until #87/#101.
- Rewrite the `x-app` `SANDBOX_LAUNCHER_URL` comment.

### 2. `compose.prod.yaml` (1-2 comment lines)
- Extend the `worker-passive` comment at lines 99-101.

### 3. `Makefile` (1 line)
- The `down` recipe.

### 4. `.env.example` (comment and example value only)
- As in Requirements.

### 5. Tests, `tests/unit/test_makefile.py` (written first, ~12 lines)
Generalise `_run_up` into `_run_make(tmp_path, target, fail_command=None)`. The existing tests
call it with `"up"`.

#### A. Happy path
| Test | Given | Expect |
|---|---|---|
| `test_make_down_also_stops_opt_in_sandbox_services` | `make down` with the Compose stub | one command, `["--profile", "sandbox", "down"]` |
| `test_make_up_migrates_before_starting_application_services` (existing) | `make up` | unchanged `STARTUP_COMMANDS` (no profile) |

#### B. Boundary cases
None.

#### C. Invalid inputs
None.

#### D. Neighbor rejection and drift guards
| Check | Given | Expect |
|---|---|---|
| `make up` test (existing) | the stub | no `--profile` in any command, so CI never starts the sandbox |
| `docker compose config --services` | no profile | no `worker-analysis`, `sandbox-*` |

## Order of work (red → green)
1. Write the Makefile test. `uv run pytest tests/unit/test_makefile.py` fails (`down` has no
   profile).
2. Edit the `Makefile`, then `compose.yaml`, `compose.prod.yaml` and `.env.example`.
3. Run the Acceptance criteria commands against `docker compose --profile sandbox up -d --wait`.
4. Full gate (as in commit 2).
5. `finish-task` deferred to commit 8.
6. Commit. Body: "completes the dev chain worker → launcher → proxy (ADR 0016); prod stays
   without it until the first analysis task (ADR 0029)". Footer `Refs #84`, Co-Authored-By
   trailer.

## Reused code
- `compose.yaml`: `&worker`, `&worker-health`, `&app-env` anchors and the `worker-ai` service.
- `src/attacksurf/workers/runtime.py`: `sandbox_runner()` (from 3d; used in checks only).
- `src/attacksurf/infra/sandbox.py`: `LauncherSandboxRunner` (from 3d).
- `tests/unit/test_makefile.py`: the Compose stub approach.

## Verification
- Acceptance criteria commands, then `make down` stops everything (`docker compose --profile
  sandbox ps` is empty).
- `make up` alone: unchanged services, `/healthz` 200, `make test-worker` green.
- Scratch check (revert): drop `SANDBOX_LAUNCHER_URL` from `worker-analysis`. The "client wired"
  check prints `UnconfiguredSandboxRunner`.

## Notes for later commits
- **Commit 7:** documents the `sandbox` profile commands, the dropped-jobs limitation and the
  prod plan. **Commit 8:** the architecture, security, changelog and handoff updates.
- **#87 / #101:** register `analysis.code_scan` and `analysis.binary_static`. From then on, dev
  upload jobs complete through this worker.
- **#92:** copies these three services into `compose.prod.yaml` (with uid 10001 socket group and
  a host staging path), registers `runsc` on the VPS, and changes the commit 2 guard.
