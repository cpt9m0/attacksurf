**Updated:** 2026-11-17 · **Branch:** `85-artifact-storage` · **Issue:** #85 (Store uploaded and fetched artifacts encrypted, with retention limits)

## Status
PR open (#168), merged with `origin/main` and all three Codex review findings fixed; checks pass
locally (pytest 2087 passed, coverage 95.53%). Part of the
stacked #85 → #86 → #87 → #101 chain. User asked to merge the PR once the new finding is
addressed.

## Last task
- `Artifact` model + migration `0010_add_artifacts` (renumbered: `main` took `0009` for #23).
- `infra/crypto.py`: `EnvelopeCipher` (HKDF purpose-labelled key wrapping) and streaming
  AES-256-GCM; `infra/storage.py`: `LocalArtifactStore`.
- `services/artifacts.py`: `store_artifact`, `open_artifact`, `stage_artifact`,
  `delete_artifact`, `purge_expired`; beat task `passive.purge_expired_artifacts` (10 min).
- Review fixes: staging and deletion of one artifact are serialised by a `flock` on
  `{ARTIFACT_STORE_ROOT}/{artifact_id}.lock` (staging re-checks the ciphertext under the lock), and
  a failed purge defers its artifact behind everything still waiting instead of starving the
  queue (ADR 0028, Consequences).
- Third review fix: `unstage` no longer swallows removal failures (missing dir stays quiet);
  `delete` fails so the key is kept, the row stays live, and the purge retries it (ADR 0028).

## Next step
Get the owner's OK on the PR size (below), then merge #85 once checks pass; then #86 (archive
extraction in the sandbox), #87 (codebase upload), #101.

## Open threads
- Non-test diff is about 1,100 changed lines, over the ~400 guideline. The owner has not
  approved shipping it whole: ask, and say so in the PR, or move `stage`/`unstage`/
  `sweep_staged`/`stage_artifact` to #84 (the design's cut line).
- Nothing calls `stage`/`unstage`/`stage_artifact` yet: which process stages (and holds the
  key) is #84's decision. #84 must also call `delete_artifact(reason="analysis_complete")`.
- Known gaps (orphan ciphertext, no key rotation, no purge in prod until #29, key optional at
  boot until #87) are recorded in ADR 0028, Consequences.
- #24 should reuse `EnvelopeCipher`, not add Fernet.

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
