# Plan: PR 4, commit 3: `feat(workers): move the analysis queue out of the reserved list`

Branch `84-analysis-worker` · `Refs #84` · follows `test(scanners): guard scan profiles against
analysis scanners` (commit 2 of PR 4; see `84-pr4-analysis-worker-overall-plan.md`).

## Purpose

**In plain words.** The app keeps two lists of queues:
- **Live:** queues that a worker reads.
- **Reserved:** queues that exist but nobody reads yet.

`analysis` is on the reserved list. This commit moves it to the live list, so the code itself says
that a worker reads it (commit 6 adds that worker). Messages are already allowed onto both lists,
so where things go does not change. What changes is what tests and tools treat as "a queue someone
consumes".

**Technical.** In `src/attacksurf/infra/queue.py`:
- `QUEUES = ("passive", "ai", "analysis")`;
- `RESERVED_QUEUES = ("active",)`;
- the trailing comment becomes `# no worker yet: active checks`.

`queue_for` and `celery_config` already build from `QUEUES + RESERVED_QUEUES`, so routing and
exchanges are unchanged. `tests/unit/infra/test_queue.py` adds an `("analysis.code_scan",
"analysis")` routing case and pins the reserved list. This implements ADR 0029.

## Context
After commit 2 no profile can select an analysis scanner, so making the queue live cannot pull
user scans into it.

What uses `QUEUES` alone:
- `test_every_registered_task_routes_to_a_known_queue`: no `analysis.*` task is registered yet,
  so this check is unaffected.
- `test_every_beat_entry_names_a_registered_task_on_a_consumed_queue`.
- `app.amqp.default_queue` (still `passive`).
- The `queue_for` error message.

This is a separate commit because it is the one code change that ADR 0029 is about. Its diff
should be readable in seconds.

## Decisions
1. **Order in `QUEUES`.** Append `"analysis"` after `"ai"`. `task_default_queue` stays `passive`,
   and nothing depends on tuple order.
2. **No new exchange code.** Each queue already gets its own exchange and routing key
   (`test_each_queue_has_its_own_exchange_and_routing_key`), so the queue keeps the same Redis
   key and anything already queued there is still picked up.
3. **The upload services don't change.** `services/repos.py` and `services/binaries.py` already
   enqueue onto `analysis`. Their docstring ("no worker until #84") is updated in commit 7 with
   the rest of the docs.
4. **The registry already allows the queue.** `scanners/registry.py:21` lists
   `{"passive", "active", "analysis"}`. No change.
5. **Left out.** The worker process itself (commit 6).
6. **Docs in this commit.** None; commits 7 and 8.

## Requirements
- [ ] `QUEUES == ("passive", "ai", "analysis")` and `RESERVED_QUEUES == ("active",)`.
- [ ] `queue_for("analysis.code_scan") == "analysis"` (unchanged behaviour, now also pinned).
- [ ] The comment on `RESERVED_QUEUES` no longer mentions sandboxed analysis.
- [ ] No change to `celery_config`, `queue_for`, `CeleryTaskQueue` or any service.

## Acceptance criteria
- [ ] **Contract:** `conf.task_queues` still equals `set(QUEUES + RESERVED_QUEUES)`, and each
      queue's exchange and routing key equal its name (existing tests stay green).
- [ ] **Tight fit:** a new test pins `RESERVED_QUEUES == ("active",)` and `"analysis" in QUEUES`.
      Any later move shows up as a test diff.
- [ ] **Registry guard:** `test_every_registered_task_routes_to_a_known_queue` still passes.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%. Hooks pass without `--no-verify`.

## Changes

### 1. `src/attacksurf/infra/queue.py` (2 lines)
- The two tuples and the comment.

### 2. Tests, `tests/unit/infra/test_queue.py` (written first, ~8 lines)
Style follows the existing parametrised `test_task_name_prefix_is_the_queue`.

#### A. Happy path
| Test | Given | Expect |
|---|---|---|
| `test_task_name_prefix_is_the_queue` (new param `("analysis.code_scan", "analysis")`) | the upload task name | routes to `analysis` |
| `test_analysis_is_consumed_and_only_active_checks_stay_reserved` | the module constants | `"analysis" in QUEUES` and `RESERVED_QUEUES == ("active",)` |

#### B. Boundary cases
| Test | Given | Expect |
|---|---|---|
| `test_each_queue_has_its_own_exchange_and_routing_key` (existing) | `analysis` now in `QUEUES` | exchange and routing key `analysis` |

#### C. Invalid inputs
| Test | Given | Expect |
|---|---|---|
| `test_unroutable_task_names_are_rejected` (existing) | `"analysis"`, `"Analysis.x"` could be added as params | `ValueError` |

#### D. Neighbor rejection and drift guards
| Test | Given | Expect |
|---|---|---|
| `test_every_beat_entry_names_a_registered_task_on_a_consumed_queue` (existing) | beat schedule | still only `passive` tasks |

## Order of work (red → green)
1. Add the param case and the new pinning test. `uv run pytest tests/unit/infra/test_queue.py`:
   the pinning test fails because `RESERVED_QUEUES` still has `analysis`.
2. Edit `queue.py` until the file passes.
3. Full gate (as in commit 2).
4. `finish-task` deferred to commit 8.
5. Commit. Body: "ADR 0029: the analysis queue is consumed from now on (by a dev-only worker,
   added later in this PR)". Footer `Refs #84`, Co-Authored-By trailer.

## Reused code
- `src/attacksurf/infra/queue.py`: `QUEUES`, `RESERVED_QUEUES`, `queue_for`.
- `tests/unit/infra/test_queue.py`: its existing parametrised style.

## Verification
- `uv run pytest tests/unit/infra/test_queue.py -q` green, then the full suite.
- Scratch check (revert): put `analysis` back into `RESERVED_QUEUES`. The pinning test fails.

## Notes for later commits
- **Commit 6:** the worker that consumes this queue (`-Q analysis`).
- **#87 / #101:** registering `analysis.code_scan` and `analysis.binary_static` tasks makes
  `test_every_registered_task_routes_to_a_known_queue` check them against `QUEUES`. That now
  passes, which it would not have before this commit.
