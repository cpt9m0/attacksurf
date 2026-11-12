# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-12 · **Branch:** `84-sandbox-launcher-core` · **Issue:** #84 (analysis
sandbox), PR 3b of the 3a to 3d launcher split

## Status
PR 3b (sandbox launcher building blocks) is open as draft #158 on `84-sandbox-launcher-core`;
CI green.

## Last task
- `SandboxLauncherSettings` in `config.py` (env only, wall time at most 840 s, `runc` refused in prod).
- `sandbox_launcher/catalog.py` + `artifacts.py`, and the launcher import-linter contract.
- `sandbox_launcher/container.py`: `build_create_body`, tested against the real proxy policy.
- `sandbox_launcher/stream.py`: `read_stdout` keeps stdout, drops stderr, caps at 2 MiB, fails closed.
- Docs: `AGENTS.md` layout, `docs/architecture.md` (launcher building blocks), `docs/security.md`,
  `CHANGELOG.md`.

## Next step
Get #157 (3a) and then #158 (3b) reviewed and merged, then start PR 3c (`runner.py`,
`server.py` with `POST /runs`, `__main__.py`) per `docs/plans/84-pr3-sandbox-launcher-split-4-prs.md`.

## Open threads
- PR 3a (#157, `84-sandbox-runtime-info`, proxy `GET /info`) is open as a draft. PR 3c needs
  both 3a and 3b merged (or stacks on them as a draft).
- `docs/plans/` (split plan and the per-commit PR 3b plans) is untracked on purpose.

## Notes for the next agent
- PR 3c `runner.py` must decide the outcome from its own flags (`timed_out`, cap tripped) before
  any stream error: a kill mid-frame reaches `read_stdout` as `MalformedStream`. It strips the
  proxy's HTTP response head before handing frames to `read_stdout`.
- PR 3c moves `FakeDocker` to `tests/docker_fakes.py`; it must be able to script stdout/stderr
  frames split across writes.
- PR 3d's ~3 MiB reply cap assumes stdout is at most 2 MiB (base64 about 2.67 MiB).
- The launcher copies proxy constants and `domain.scanners.MAX_OUTPUT_BYTES` on purpose (it may
  not import them); a parity test guards each copy. Don't "fix" that by importing.
- Plan docs for this PR: `docs/plans/84-pr3-sandbox-launcher-split-4-prs.md` and
  `docs/plans/84-pr3b-launcher-building-blocks/`.
