# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-17 · **Branch:** `87-repo-archive-upload` · **Issue:** #87 (Upload a codebase archive as a repo asset)

## Status
Implemented, review findings fixed, local checks pass; rebased onto `origin/main` after #85
(#168) and #86 (#169) merged, conflicts resolved (STATE.md only). PR open (#170).

## Last task
- `domain.assets`: repo values are `host/owner/name` (ADR 0017) or `upload/<slug>`;
  `domain.artifacts.sniff_archive` checks magic bytes only.
- `services.repos.upload_repo_archive`: repo asset + `Artifact` + `Scan` (profile `code`,
  `stats.revision` = archive SHA-256, `stats.artifact_id`) + job `analysis.code_scan`, audited
  as `repo.archive_uploaded`. A failed store keeps the (maybe empty) asset on purpose (deleting
  it raced with concurrent uploads of the same name); a failed enqueue raises `ScanNotQueued`.
- `web/uploads.py` (built for reuse by #101): 2 MiB default body ceiling; one hook ahead of CSRF
  spends the per-user rate limit and raises the ceiling for `UPLOAD_ENDPOINTS` (endpoint ->
  form partial); `upload_form` re-renders the form in place, also for an HTMX 413 / 429.
- Caddyfile: 257 MiB on `/assets/upload` only. `compose.prod.yaml` has an `artifact-store`
  volume; prod uploads stay off until `APP_ENCRYPTION_KEY` is set.

## Next step
Push the rebased branch to update PR #170 (`Closes #87`), wait for checks/review. Then #101
(binary upload, stacked on this branch).

## Open threads
- #85 (`6729177`) and #86 (`e013000`) are merged; this branch now contains only the #87 commit.
- #21 (Scans UI) is not merged: the scan shows only in the asset's "Scan history" tab. No JSON API.
- The `code` scan stays `queued` until #84 adds `worker-analysis` and `analysis.code_scan`;
  its artifact is still purged after `ARTIFACT_RETENTION_HOURS` (24 h if 0).
- Caddyfile and `compose.prod.yaml` changes are unvalidated (no `caddy validate` or deploy).
  Cloudflare caps bodies at 100 MB. The prod artifact volume has no backup (#29).
- Nothing runs the extractor yet: #84 still lacks the launcher service, runner client, images
  and `worker-analysis`.

## Notes for the next agent
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test
  uv run pytest -p no:cacheprovider --basetemp=/tmp/aspt` (short basetemp: macOS AF_UNIX limit).
- `uv sync` after switching branches: this branch needs `cryptography`.
- `tests/unit/sandbox_proxy/test_server.py` has timing-flaky tests; rerun the file if one fails.
- Artifact use cases call `session.rollback()` between steps: service tests must commit their
  fixtures, and `tests/integration/services/test_artifacts.py` expires loaded rows after each
  test so a stale instance can't hide what a use case wrote.
- `tests.helpers.make_settings(...)` ignores `.env` and OS env; artifact tests build settings
  through it.
- Changing a corpus builder: rerun the generator, then delete any file it no longer produces.
