# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-17 · **Branch:** `86-archive-extraction` · **Issue:** #86 (Extract untrusted archives safely inside the sandbox)

## Status
Implemented, review findings fixed, local checks pass; rebased onto `origin/main` after #85
merged (#168), conflicts resolved. PR open (#169).

## Last task
- `sandbox_tools/extract.py`: stdlib-only zip and tar(.gz/.bz2/.xz) extractor per ADR 0017
  (own loop, no links, files `0600`/dirs `0700`, caps counted while writing, zip local vs
  central header comparison, manifest + bounded stdout summary, rejection removes the tree).
  CLI: `python -m attacksurf.sandbox_tools.extract <archive> <dest> [--manifest <path>]`;
  exit 0 ok, 3 rejected, 4 extractor I/O failure, one JSON line each.
- Eighth import contract (no app, no dependencies); stdlib-only itself is a test over imports.
- Corpus in `tests/fixtures/archives/`, built by `uv run python -m tests.archive_fixtures`.

## Next step
Push the rebased branch to update PR #169 (`Closes #86`), wait for checks/review. Then #87
(upload), then #101.

## Open threads
- #85 is merged (`6729177`); this branch now contains only the #86 commit.
- Nothing runs the extractor yet: #84 still lacks the launcher service, runner client, images
  and `worker-analysis`. Each analyzer command must wrap extract-then-tool (architecture.md,
  "Sandbox tools"), tell exit 3 from 4, and surface the summary's skipped list.
- Extractor choices beyond the ADR table (full list: security.md): encrypted or non-deflate
  zip entries, backslashes, old-GNU sparse members and data after a tar's end reject; the
  100,000 cap also counts created directories; the ratio is bytes written (tar: also parsed)
  per archive byte, so a few KB of highly compressible data alone is rejected.
- Known gaps: zip bytes outside the central directory are ignored; a tar pax header sits in
  memory up to the size budget and a huge zip directory has no cap (memory limit stops it).

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
