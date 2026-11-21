# 0031. Open the analysis queue before any analyzer exists

- Status: accepted (supersedes ADR 0016's reserved analysis queue consequence); renumbered from
  0029 after main claimed that number for the AI triage stage
- Date: 2026-11-19

## Context
[ADR 0016](0016-analysis-sandbox.md) kept the `analysis` queue reserved until the worker,
launcher, proxy and at least one analyzer all exist. Since then the upload services have started
sending work to it: `services/repos.py` enqueues `analysis.code_scan` and `services/binaries.py`
enqueues `analysis.binary_static`. Nothing consumes those messages yet.

Two constraints shape when the queue can open:
- Developers need the whole chain (worker, launcher, proxy) running locally to build the first
  analysis scanners (#87, #101, #92) against.
- Production is stricter. `scripts/deploy.sh` starts every service in `compose.prod.yaml` and
  waits for each to be healthy, and the launcher exits at start-up without `runsc` (gVisor)
  registered in Docker on the VPS. A prod worker that has no registered `analysis.*` task would
  also drop those messages, so uploads would never finish, even after the task is added later.

## Decision
1. The `analysis` queue is consumed in dev before any analyzer exists. A `worker-analysis`
   service, `sandbox-proxy` and `sandbox-launcher` run behind the opt-in Compose profile
   `sandbox`, so `make up` and the CI smoke job are unchanged.
2. Prod runs no sandbox service until the first analysis task is registered (#92). This copies
   the `worker-ai` precedent in `compose.prod.yaml`, and the three services arrive together
   with the VPS `runsc` change.
3. A unit test fails if any production scan profile selects an analysis scanner until #92, so
   none is wired in too early. It is a test, not runtime code: no profile selects one today.
4. The shipped `sandbox-images.lock` is empty. It allows no image, so the sandbox can run
   nothing until PR 5 adds the first one.

## Consequences
- A dev `worker-analysis` drops `analysis.*` messages it has no task for, and the job row stays
  `queued`, until #87 and #101 register them.
- Prod gets the proxy, launcher and analysis worker with the first analyzer (#92), together
  with registering `runsc` on the VPS.
- #92 must remove or change the guard test from decision 3.
- The `active` queue stays reserved.
- Everything else in ADR 0016 stands.
