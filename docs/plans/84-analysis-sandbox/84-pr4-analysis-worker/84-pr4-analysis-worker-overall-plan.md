# Plan: PR 4 of #84, the analysis worker and sandbox services (overview)

## Goal in plain words
Uploaded code and binaries are already put on a waiting list (the `analysis` queue). Nothing reads
that list yet. PR 4 does three things:
- It officially opens that list.
- It adds the two services that run analyzers safely (the proxy and the launcher) to the local
  development setup.
- It adds the worker that reads the list.

It does **not** analyze anything yet: no analyzer exists until PR 5 and #92. It also does **not**
change production (see Decision 1).

PR title: `feat(workers): add analysis worker and sandbox services`. Branch: `84-analysis-worker`.
Footer on every commit: `Refs #84` (PR 5 closes #84).

## Two phases

| Phase | Commits | Needs PR 3d? | Start |
|---|---|---|---|
| A | 01 to 05 | No | Now, on a new branch from `origin/main` |
| B | 06 to 08 | Yes (`SANDBOX_LAUNCHER_URL` exists only in 3d) | After 3d merges |

Why 06 needs 3d: the analysis worker finds the launcher through the `SANDBOX_LAUNCHER_URL`
setting, and 3d adds that setting. 3d also edits the `compose.yaml` lines that 06 changes.

Why 07 and 08 wait: the docs describe the whole chain, worker → launcher → proxy, including 3d's
client.

## Commit order

| # | File | Commit subject | Phase |
|---|---|---|---|
| 1 | `01-adr-open-analysis-queue.md` | `docs(adr): record opening the analysis queue before an analyzer exists` | A |
| 2 | `02-guard-profiles-against-analysis-scanners.md` | `test(scanners): guard scan profiles against analysis scanners` | A |
| 3 | `03-open-analysis-queue.md` | `feat(workers): move the analysis queue out of the reserved list` | A |
| 4 | `04-ship-empty-sandbox-images-lock.md` | `build(infra): ship an empty sandbox images lock` | A |
| 5 | `05-add-sandbox-services-to-dev-stack.md` | `feat(infra): add the sandbox proxy and launcher to the dev stack` | A |
| 6 | `06-add-analysis-worker-to-dev-stack.md` | `feat(workers): add the analysis worker to the dev stack` | B |
| 7 | `07-document-local-sandbox-setup.md` | `docs(workers): document running the analysis sandbox locally` | B |
| 8 | `08-record-analysis-worker-architecture.md` | `docs(workers): record the analysis worker in the architecture and changelog` | B |

Each commit stands alone: the gate (ruff, pyright, lint-imports, pytest) passes after every one.

**Size rule:** each commit touches at most 5 non-test files (about 8 files including tests) and
carries one idea. The largest are commit 6 (4 non-test files plus 1 test) and commits 7 and 8
(3 and 4 docs files).

## Git steps

**Phase A, now:**
```bash
git fetch origin
git switch -c 84-analysis-worker origin/main
# commits 01-05
git push -u origin 84-analysis-worker      # optional: open as a draft PR now
```
If you open the draft early, write in its description: "Merge order: 4 of 5. Merge after 3d (link
the 3d PR number). Phase B commits follow once 3d merges."

**Phase B, after 3d is squash-merged into `main`:**
```bash
git fetch origin
git switch 84-analysis-worker
git rebase origin/main          # a plain rebase: this branch never contained 3d's commits
git push --force-with-lease     # only your own branch, never a shared one
# commits 06-08
```
The only file both PRs touch is `compose.yaml`. Phase A adds services at the bottom, while 3d edits
the shared `x-app` block at the top. A conflict is therefore unlikely; if one happens, keep both
sides.

**Alternative**, if you want to do Phase B before 3d merges: branch Phase B from 3d instead (a
"stacked" PR). Once 3d merges, run `git rebase --onto origin/main 84-sandbox-runner-client
84-analysis-worker`. Only use this if 3d's review is slow.

## Decisions (already approved in the planning step)
1. **No sandbox services in prod in this PR.** Follows `compose.prod.yaml:99-101`, which keeps
   `worker-ai` out of prod until it has work. The deploy script starts every service in that file
   and waits for each to be healthy (`scripts/deploy.sh:46`, `:203`). The launcher won't start
   without gVisor (`runsc`) on the VPS. Prod gets the services with the first real analyzer
   (#92), together with the VPS change.
2. **Dev sandbox services are opt-in** through a Compose profile named `sandbox`. `make up` and
   the CI smoke job don't change.
3. **One shared image**, no new Dockerfile targets. This matches how `web`, the workers, `beat`
   and `migrate` already share it.
4. **The empty `sandbox-images.lock` lands here, not in PR 5.** Both services refuse to start
   without it. PR 5 adds the first real entry.

## Reused code (across the PR)
- `src/attacksurf/infra/queue.py`: `QUEUES`, `RESERVED_QUEUES`, `queue_for`, `celery_config`.
- `src/attacksurf/scanners/profiles.py`: `PROFILES`; `src/attacksurf/scanners/registry.py`: `registry`.
- `src/attacksurf/domain/scanners.py`: `Scanner.queue`, `ScannerGrant.sandbox_analyzers`.
- `src/attacksurf/sandbox_proxy/policy.py`: `load_images`; `src/attacksurf/sandbox_launcher/catalog.py`: `load_catalog`.
- `src/attacksurf/config.py`: `SandboxProxySettings` (port 8790), `SandboxLauncherSettings` (port 8791), `sandbox_images_lock`, `sandbox_allow_runc`, `sandbox_artifact_root`.
- `compose.yaml`: the `&worker` anchor and the `&worker-health` healthcheck.

## Verification for the whole PR
- After each commit:
  ```bash
  uv run ruff check . && uv run ruff format --check . && uv run pyright \
    && uv run lint-imports && uv run pytest
  ```
- After 05 and 06: `docker compose --profile sandbox up -d --wait`, then
  `docker compose --profile sandbox ps` shows every service healthy.
- `make up` still starts only the old services, and CI's `compose` job stays green.
- Before opening the PR: `finish-task`, then `pre-pr-check`.
