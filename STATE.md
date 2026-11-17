# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-17 · **Branch:** `101-binary-upload` · **Issue:** #101 (Upload binaries and mobile apps as binary assets)

## Status
Implemented, local checks pass; rebased onto `origin/main` after #87 (#170) merged,
conflicts resolved (STATE.md + `test_repo_upload.py` refactor vs `.lock` filter). PR open (#171).

## Last task
- `domain`: binary values are `sha256:<64 hex>`; `sniff_binary` is the leading-bytes upload gate.
- `sandbox_tools/detect.py`: stdlib-only detector (elf, pe, macho, macho_fat, apk, ipa), CLI
  exit 0 / 3 / 4; inconsistent, over-cap and APK-and-IPA zips are rejected.
- `services.binaries.upload_binary`: hash, asset, `Artifact`, `Scan` (profile `binary_static`),
  job `analysis.binary_static`, audit `binary.uploaded`; quota checked before the asset
  exists (`check_quota`). `services/uploads.py` holds what it shares with `services.repos`.
- Web: `POST /assets/upload-binary` in `UPLOAD_ENDPOINTS` (one shared 20/hour bucket for all
  upload routes), second upload card, "Binary" filter, "Uploaded file" on the asset page.
  Fixtures: `tests/binary_fixtures.py` builds `tests/fixtures/binaries/` (header stubs).

## Next step
Push the rebased branch to update PR #171 (`Closes #101`), wait for checks/review. Then #102
(native parsing with LIEF), which needs #84's launcher and analysis worker first.

## Open threads
- #85 (`6729177`), #86 (`e013000`) and #87 (`56fbaa7`) are merged; this branch now contains
  only the #101 commit. #23 (#166, llm usage) is also on `main`.
- #21 (Scans UI) is not merged: the scan shows only in the asset's "Scan history" tab. No JSON API.
- The `code` and `binary_static` scans stay `queued` until #84 adds `worker-analysis` and
  `analysis.code_scan`; artifacts are still purged after `ARTIFACT_RETENTION_HOURS` (24 h if 0).
- The upload gate lets through any zip, Java class file or DOS program (only the detector
  rejects them); identical bytes are stored twice; a storage failure after the quota check
  leaves an asset without an artifact. Caddyfile change unvalidated; no JSON API for uploads.
- Nothing runs the extractor or detector yet: #84 still lacks the launcher service, runner
  client, images and `worker-analysis`.

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
