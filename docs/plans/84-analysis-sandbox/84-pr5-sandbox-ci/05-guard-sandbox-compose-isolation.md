# Plan: PR 5, commit 5: `test(infra): guard sandbox service isolation in compose`

> **What approving this plan does:** it moves this file to
> `docs/plans/84-analysis-sandbox/84-pr5-sandbox-ci/05-guard-sandbox-compose-isolation.md` and
> makes one small edit to `84-pr5-sandbox-ci-overall-plan.md`: the commit 5 row drops "lock
> guards", because commit 2 already added them (see Findings). That is all. **No test code is
> written** until you ask for the implementation, and **nothing is committed until you approve
> the commit directly** (see "Approval gates").

Branch `84-sandbox-ci` · `Refs #84` · follows `6e87dd3 test(workers): let slow machines raise the
scale test time limit` (commit 4 is `40bea1e`; see `84-pr5-sandbox-ci-overall-plan.md`).

## Purpose

**In plain words.** The sandbox only stays safe if the dev stack keeps its walls. Only the proxy
may touch Docker. The launcher and proxy must never see the database, Redis or app secrets. The
sandbox network must stay internal and hold only the three sandbox services. Today `compose.yaml`
gets all of this right, but nothing checks it, so one careless edit (an `env_file` on the
`x-sandbox` anchor, a socket mount on the launcher) would pass CI. This commit adds tests that
read the rendered Compose config and fail on such an edit. They start no containers and read no
secrets.

**Technical.** One new test module, `tests/unit/test_sandbox_compose.py`. It renders
`docker compose -f compose.yaml --env-file <empty> --profile sandbox config --no-env-resolution
--format json` with a stripped process environment, then asserts the #84 isolation criteria and
ADR 0016/0028 on `sandbox-proxy`, `sandbox-launcher` and `worker-analysis`. Same approach as
`tests/unit/test_production_workers.py`. No source, compose or config change.

## Findings (checked on this machine)

1. **The lock guards already exist.** Commit 2 added them:
   - `tests/unit/sandbox_launcher/test_catalog.py:63-73`: the committed lock loads as `{}`, and
     neither it nor `CATALOG` has a `fixture-` name;
   - `tests/unit/sandbox_proxy/test_policy.py:333`: the proxy loads the committed lock as empty.

   Repeating them here would add nothing, so the overview row is corrected.
2. **A local, git-ignored `compose.override.yaml` exists** (`.git/info/exclude:7`). Compose loads
   it automatically and it changes network names and the web port. The test must pass
   `-f compose.yaml` so it checks the committed file only.
3. **`--no-interpolate` can't be used.** It turns the `${SANDBOX_ARTIFACT_ROOT:-...}` bind mounts
   into named volumes (`type: volume`), which hides the real mount. Interpolating is needed. To
   keep that hermetic, the test uses an empty `--env-file` (so `.env`, which can hold
   `APP_ENCRYPTION_KEY`, is never read) and `env={PATH, HOME[, DOCKER_CONFIG]}`, so shell or CI
   variables can't change the defaults.
4. A hermetic render was tried. It gives exactly what the tests need:
   - **Only one socket mount:** only `sandbox-proxy` mounts `docker.sock`.
   - **Sandbox network members:** `{sandbox-proxy, sandbox-launcher, worker-analysis}`, and
     `sandbox` has `internal: true`.
   - **Launcher staging mount:** a `bind` of `/tmp/attacksurf-sandbox` at the same path, with
     `read_only: true`.
   - **Proxy and launcher environment:** proxy keys are `{ENV, SANDBOX_ALLOW_RUNC,
     SANDBOX_ARTIFACT_ROOT}`; the launcher adds `SANDBOX_FIXTURE_ANALYZERS`. Neither has an
     `env_file`.
   - **No app secrets in the output:** `APP_ENCRYPTION_KEY` renders as `''`.
5. `compose.prod.yaml` has no sandbox services yet. #84 says "dev and prod compose", but the prod
   wiring belongs to #92 (a `STATE.md` open thread). This commit guards dev only, and the PR says
   so.

## Decisions

1. **Exact env-key allowlist, not a denylist.** For the proxy and the launcher, the environment
   keys must equal a fixed set, and `env_file` and `secrets` must be absent. Any new variable then
   shows up as a test diff. A failing test names the forbidden keys (`DATABASE_URL`, `REDIS_URL`,
   `APP_ENCRYPTION_KEY`, ...) so the reason is clear. Only keys are compared, never values.
2. **The socket check covers every service.** It looks at both source and target, for any path
   containing `docker.sock`, so a future service that mounts the socket fails too, not just the
   two named ones.
3. **`worker-analysis` is checked against ADR 0028, not against #84's wording.** #84 says "no
   artifact mount", but ADR 0028 has the worker stage decrypted artifacts read-write into
   `SANDBOX_ARTIFACT_ROOT`. The test pins:
   - no socket;
   - networks `{default, sandbox}`;
   - exactly the mounts `/app/src`, `artifact-store` and the staging root.

   The PR description flags the wording (already an open issue in the overview).
4. **Skips locally, fails in CI.** Without `docker` the module skips, as
   `test_production_workers.py` does. When `CI=true` it calls `pytest.fail`, so the guard can
   never pass quietly in CI (overview Decision 6). `docker compose config` doesn't contact the
   daemon, so the `test` job can run it.
5. **One rendered config per module** (`scope="module"` fixture, empty env file from
   `tmp_path_factory`). Rendering takes about 0.3 s, so doing it once keeps the suite fast.
6. **No docs in this commit.** Commit 6 carries `docs/development.md`, `docs/security.md`,
   `CHANGELOG.md`, `AGENTS.md` and `STATE.md`. Only the plan files ride along, as in commit 4.

## Requirements

- [ ] `tests/unit/test_sandbox_compose.py` exists and runs `docker` through `subprocess.run` with
      a list argv, `-f compose.yaml`, an empty `--env-file`, `--profile sandbox`,
      `--no-env-resolution`, `--format json`, a stripped `env`, `check=True`, and a `# noqa: S603`
      reason, like the prod test.
- [ ] No change to `compose.yaml`, `compose.prod.yaml`, `src/`, `.env.example` or CI workflows.
- [ ] Assertion messages name the service and the offending key or mount, never a value.

## Tests (one behavior each)

| Test | Expect |
|---|---|
| `test_only_the_sandbox_proxy_mounts_the_docker_socket` | services with a `docker.sock` source or target == `{"sandbox-proxy"}` |
| `test_sandbox_services_get_only_their_own_settings` (param proxy, launcher) | env keys == the allowlist; no `env_file`, no `secrets` |
| `test_sandbox_services_are_only_on_the_internal_sandbox_network` (param proxy, launcher) | networks == `{"sandbox"}`; `networks.sandbox.internal is True` |
| `test_sandbox_network_holds_only_the_sandbox_services` | services on `sandbox` == `{proxy, launcher, worker-analysis}` (so not postgres, redis or `worker-active`) |
| `test_launcher_mounts_the_artifact_root_read_only_at_the_same_path` | one bind, with source == target == its `SANDBOX_ARTIFACT_ROOT`, `read_only`; the only other mount is `/app/src` read-only |
| `test_proxy_mounts_only_the_socket_and_read_only_source` | volumes are `/app/src` (ro) and the socket, nothing else |
| `test_analysis_worker_stages_artifacts_without_the_docker_socket` | networks `{default, sandbox}`; mount targets == `{/app/src, artifact store, staging root}`; same root as the launcher |
| `test_only_the_analysis_worker_knows_the_launcher_url` | `SANDBOX_LAUNCHER_URL` is `""` on every other app service and `http://sandbox-launcher:8791` on `worker-analysis` |
| `test_sandbox_services_publish_no_ports_and_are_opt_in` (param the three) | no `ports`; `profiles == ["sandbox"]` |

## Order of work (red → green)

1. Write the module. These tests guard config that is already correct, so "red" comes from
   mutations. Each scratch edit below, made to `compose.yaml` and reverted right after, must fail
   the named test:
   - socket on the launcher → the socket test;
   - `env_file` on `x-sandbox` → the settings test;
   - `internal: true` dropped → the network test;
   - `worker-active` added to `sandbox` → the members test;
   - `:ro` dropped from the launcher staging mount → the launcher mount test;
   - `ports` added to the proxy → the ports test;
   - `SANDBOX_LAUNCHER_URL` set on `worker-passive` → the launcher URL test.

   `git diff compose.yaml` must be empty at the end.
2. Run `uv run pytest tests/unit/test_sandbox_compose.py -q`: green on the real file. Check that
   `CI=true PATH=<no docker>` fails instead of skipping.
3. Full gate: `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run
   lint-imports && uv run pytest` (coverage ≥ 80%).
4. `pre-pr-check` self-review of the diff.
5. **Stop.** Report the results and wait for commit approval (below).

## Approval gates (nothing is committed without your direct approval)

- Approving this plan (ExitPlanMode) only moves and saves the plan file and makes the overview
  edit. It is **not** approval to write code or to commit.
- After implementing, I stop and show `git status`, `git diff --stat`, the gate output, the
  mutation results and the full proposed commit message. Then I wait.
- I run `git commit` only after you say so directly, in a message after that report (for
  example, "commit it"). An earlier approval, a plan approval or a hook prompt doesn't count.
- No `git push`, no PR, no `--no-verify`, no amend of earlier commits.

**Proposed commit** (after your approval only). Staged files:

- `tests/unit/test_sandbox_compose.py`;
- `05-guard-sandbox-compose-isolation.md`;
- the `84-pr5-sandbox-ci-overall-plan.md` edit.

That is 2 non-test files, within the size rule. The message:

```
test(infra): guard sandbox service isolation in compose

<why: the dev stack's sandbox walls (socket only on the proxy, no app secrets in the
launcher or proxy, internal sandbox network) were unchecked, so one compose edit could
break them silently. Rendered hermetically: committed file only, no .env, no shell env.>

Refs #84

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

## Reused code

- `tests/unit/test_production_workers.py`: the `docker compose config --no-env-resolution
  --format json` fixture pattern, the skip rule and the `noqa` wording.
- `tests/integration/sandbox/conftest.py`: the `pytest.fail` wording style used when CI lacks
  Docker.

## Notes for later commits

- **Commit 6:** `docs/security.md` cites this guard; the PR body flags the #84 "no artifact
  mount" wording against ADR 0028 and says that prod compose isolation is left to #92.
- **#92:** when the sandbox services reach `compose.prod.yaml`, extend this module (or the prod
  test) with the same checks on the prod file.
- The `runsc` CI results from commit 4 are still pending: the branch isn't pushed yet. This commit
  doesn't depend on them.
