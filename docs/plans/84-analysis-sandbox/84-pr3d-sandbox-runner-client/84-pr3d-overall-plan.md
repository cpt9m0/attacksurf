# Plan: write the per-commit plan files for PR 3d of #84

## Context
PR 3c (launcher service) gives the sandbox an internal API: `POST /runs {analyzer, artifact_id}`
returns `{exit_code, stdout_b64, timed_out, output_exceeded}`, and there is also `GET /healthz`.
Nothing on the worker side calls this API yet. `ScopeGuard` still defaults to
`UnconfiguredSandboxRunner`, which refuses every run. PR 3d adds the worker-side client and
connects it to the scanner gate. It is about 70 non-test lines, in the three commits listed in
`docs/plans/84-analysis-sandbox/84-pr3-sandbox-launcher-split-4-prs.md`.

This task only produces the plan files, one per commit plus an overview. No source code is
written or committed.

## Output location
The request names `docs/plans/84-analysis-sandbox/84-pr3dd-sandbox-runner-client/`, but an empty
`docs/plans/84-analysis-sandbox/84-pr3d-sandbox-runner-client/` was created today. That name matches the existing
`84-pr3b-…` and `84-pr3c-…` folders, so "pr3dd" looks like a typo and the plans go in the
existing `pr3d` folder. `docs/plans/` is untracked, so these files never enter the PR.

| File | Contents |
|---|---|
| `84-pr3d-sandbox-runner-client.md` | overview: goal, branch and base, commit order, merge and rebase steps, reused code, verification |
| `01-add-launcher-runner-client.md` | `feat(infra): add the launcher sandbox runner client` |
| `02-wire-runner-into-scanner-gate.md` | `feat(workers): wire the sandbox runner into the scanner gate` |
| `03-document-sandbox-runner-client.md` | `docs(infra): document the sandbox runner client` |

Each commit file follows `docs/plans/plan-template.md` section by section:
- Header and Branch line: branch `84-sandbox-runner-client`, `Refs #84`.
  - Commit 1 "follows" the tip of the 3c branch.
  - Commits 2 and 3 follow the previous commit of 3d.
- Purpose (a plain-words paragraph and a technical one), Context, numbered Decisions, Requirements as checkboxes, and Acceptance criteria (Contract, Tight fit, Negative, Isolation, Gate).
- Changes per file, with test tables A to D (Test / Given / Expect).
- Order of work: red → green, then the full gate, then commit.
- Reused code, Verification (including scratch mutation checks), and Notes for later commits.
- No HTML comments or placeholders are left. A section that doesn't apply says "None".
- Style follows `../84-pr3c-add-sandbox-launcher-service/03-serve-launcher-api.md`.

## What each plan specifies

### 01: client (`src/attacksurf/infra/sandbox.py`, tests in `tests/unit/infra/test_sandbox.py`)
- **Class:** `LauncherSandboxRunner(base_url, *, timeout_seconds=900.0, transport=None)` implements `domain.sandbox.SandboxRunner`.
- **URL check:** the base URL must be `http://host[:port]` with no userinfo, path, query or fragment. Anything else raises `ValueError` with a fixed message.
- **httpx options:** `trust_env=False`, `follow_redirects=False`, `Timeout(900, connect=5)`.
  - The client does not use `SafeHttpClient`. That client is SSRF-guarded and would refuse the internal launcher address. The plan states why, so reviewers don't ask for it.
- **Request:** `POST /runs` with exactly `{"analyzer", "artifact_id": str(uuid)}`.
- **Reply size cap:** `MAX_REPLY_BYTES = 3 MiB`, enforced while streaming the body. A parity test shows base64 of `domain.scanners.MAX_OUTPUT_BYTES` (2 MiB) fits under it.
- **Strict decoding:**
  - The reply must have exactly the four keys.
  - `exit_code` is an int or null, and a bool is refused.
  - `timed_out` and `output_exceeded` must be bools.
  - `stdout_b64` is decoded with `validate=True`, and the decoded bytes must be at most `MAX_OUTPUT_BYTES`.
  - Killed runs come back unchanged as a `SandboxResult`.
- **Error mapping:**
  - 503, timeouts and transport errors raise `TransientJobError`.
  - 3xx, 4xx, 500 and malformed replies raise `SandboxError`.
  - Messages are fixed text and never echo the reply. Logs carry only the status and a reason.
- **Tests:**
  - `httpx.MockTransport` tables for groups A to D.
  - One contract round trip against the real `sandbox_launcher.server.make_server` on `127.0.0.1:0`, with a fake `run` function. Only tests may import `sandbox_launcher`.

### 02: wiring (`config.py`, `.env.example`, `workers/runtime.py`, `workers/app.py`)
- **Setting:** `Settings.sandbox_launcher_url: SecretStr | None = None`, using the same validator pattern as `SandboxLauncherSettings._require_http_proxy_url`. The error message never repeats the value.
  - `.env.example` gets a commented-out entry. This file is read-protected in this session, so that edit may need your approval.
- **Runner:** `runtime.sandbox_runner()` is cached with `lru_cache`. It returns `LauncherSandboxRunner` when the URL is set and `UnconfiguredSandboxRunner` otherwise.
- **Gate:** `scanner_gate()` passes `sandbox=sandbox_runner()`.
- **Fork reset:** the `worker_process_init` handler in `workers/app.py` also calls `sandbox_runner.cache_clear()`, so a forked worker never shares its parent's connection pool.
- **Tests:**
  - `tests/unit/test_config.py`: default, valid URL, rejected URLs, and errors that don't echo the value.
  - `tests/unit/workers/test_app.py`: the type of `gate._sandbox` with and without the URL, and the runner rebuilt after fork.

### 03: docs
- `docs/architecture.md`: the client, the status mapping table, the timeout ordering (client 900 s > launcher ceiling 840 s) and the reply cap.
- `docs/security.md`: the tenant-safety note.
  - The launcher has no authentication and no notion of orgs.
  - So the worker must confirm the artifact belongs to the org before it calls the launcher. Real enforcement comes with #85.
  - The client is deliberately not SSRF-guarded.
- `docs/development.md`: `SANDBOX_LAUNCHER_URL`.
- `AGENTS.md`: the `infra/` layout line gains `sandbox`.
- `CHANGELOG.md` and `STATE.md`.
- After this commit: `finish-task`, then `pre-pr-check`.
- Then open a draft PR stacked on the 3c branch. After 3c merges: retarget it to `main`, run `git rebase --onto origin/main 84-sandbox-launcher-service 84-sandbox-runner-client`, and push with `--force-with-lease`.
- Then propose the follow-up issue to sweep leftover `attacksurf-*` containers.

## Verification
- `grep -n "<[a-z#]\|<!--" docs/plans/84-analysis-sandbox/84-pr3d-sandbox-runner-client/*.md` returns nothing, and the section order matches `plan-template.md`.
- Names, status codes, messages and constants cited in the plans match `sandbox_launcher/server.py`, `config.py`, `domain/sandbox.py` and `domain/scanners.py`.
