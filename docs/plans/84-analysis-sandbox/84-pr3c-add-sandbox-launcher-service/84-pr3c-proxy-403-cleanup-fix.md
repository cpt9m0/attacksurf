# Treat proxy ownership denials (403) as unconfirmed cleanup

## Context
`ProxyClient` (`src/attacksurf/sandbox_launcher/proxy.py:27-29`) counts 403 as "container gone" for
`kill` and `remove`. The proxy answers 403 for any container its in-memory `_TrackedContainers`
doesn't hold (`sandbox_proxy/server.py:258`), which is also the case for a still-running container
after a proxy restart. Nothing reaches Docker, yet `remove()` returns True and `_stop()` suppresses
`sandbox_cleanup_failed`, so the analyzer can run on unnoticed. A 403 must leave cleanup
unconfirmed so the existing alert fires.

## Where it goes
Branch 3c (`84-sandbox-launcher-service`), as its own `fix(infra)` commit on top of `6aa773f`. The
checkout is on 3d with uncommitted changes, so (as before) commit in a temporary worktree of 3c,
then `git rebase --autostash 84-sandbox-launcher-service` on 3d (backup branch exists).

## Changes
1. `sandbox_launcher/proxy.py`
   - `_GONE = (NOT_FOUND,)`; `_KILL_DONE = (NO_CONTENT, CONFLICT, *_GONE)`;
     `_REMOVE_DONE = (NO_CONTENT, *_GONE)` (403 drops out of both).
   - Fix the `kill` and `remove` docstrings: 403 is an ownership denial (proxy restarted or never
     tracked it), so cleanup is unconfirmed: `kill` raises `ProxyError("kill", 403)`, `remove`
     returns False.
2. `sandbox_launcher/runner.py` `_stop`
   - The proxy also forgets a container once the removed-wait succeeds, so a 403 can follow a
     legitimate exit that lands between `confirmed(0)` and `kill`. Before logging
     `sandbox_cleanup_failed`, re-check `waiter.confirmed(0)` and return if the exit was confirmed.
     This is the only real proof of removal; a bare 403 never is.
   - Update the module docstring only if it mentions 403 (it doesn't).

## Tests (regression first)
- `tests/unit/sandbox_launcher/test_proxy.py`
  - `test_remove_reports_whether_the_container_is_gone`: `(403, True)` → `(403, False)`.
  - `test_kill_accepts_a_container_that_is_not_running`: drop 403 from `[204, 403, 404, 409]`;
    add a kill 403 case to `test_malformed_replies_raise_proxy_error`.
  - New: against the real proxy fixture with a `FakeRun`, call `kill`/`remove` for an ID the
    proxy never created (stands in for a restarted proxy) → `kill` raises
    `ProxyError("kill", 403)`, `remove` is False, and no kill/DELETE reached `FakeDocker.calls`.
- `tests/unit/sandbox_launcher/test_runner.py`
  - New: a `ProxyClient` subclass (pattern of `test_failed_kill_falls_back_to_a_forced_remove`)
    whose `kill` raises `ProxyError("kill", 403)` and `remove` returns False, with the wait
    unconfirmed → `SandboxRunFailed` and exactly one `sandbox_cleanup_failed` event.
  - New: same subclass, but the wait is confirmed (exit code received) → no
    `sandbox_cleanup_failed`.
- Confirm the new tests fail on the old code (stash `src`), as done for the previous fix.

## Verify
`uv run pytest tests/unit/sandbox_launcher tests/unit/sandbox_proxy`, `uv run ruff check . &&
uv run ruff format --check .`, `uv run pyright`, `uv run lint-imports`; commit through the
pre-commit hooks (no `--no-verify`) with
`fix(infra): treat a proxy ownership denial as unconfirmed cleanup`.
Then rebase 3d onto 3c and run the launcher tests there.

## Notes
- Not pushed; no PR opened. CHANGELOG/docs don't mention the 403 behaviour (grep), so no doc edit
  unless review of `finish-task` finds otherwise.
- Residual: after a real proxy restart the stray container still isn't removed by this call; the
  alert is the signal. The follow-up sweep issue for leftover `attacksurf-*` containers (STATE.md)
  covers actual cleanup.
