# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-13 · **Branch:** `85-artifact-storage` · **Issue:** #85 (Store uploaded and fetched artifacts encrypted, with retention limits)

## Status
In progress: implemented, reviewed and committed locally; not pushed, no PR yet. Local checks pass (pytest 2049 passed, coverage 95.63%).

## Last task
- `Artifact` model + migration 0009; port, errors and limits in `domain/artifacts.py`.
- `infra/crypto.py`: `EnvelopeCipher` (HKDF purpose-labelled key wrapping, 32-byte keys only)
  and streaming AES-256-GCM; `infra/storage.py`: `LocalArtifactStore` (ciphertext in
  `ARTIFACT_STORE_ROOT`, per-run plaintext in `SANDBOX_ARTIFACT_ROOT`).
- `services/artifacts.py`: `store_artifact`, `open_artifact`, `stage_artifact`,
  `delete_artifact`, `purge_expired`; beat task `passive.purge_expired_artifacts` (10 min).
- Settings `APP_ENCRYPTION_KEY`, `ARTIFACT_*`; compose volume `artifact-store` (compose pins
  `ARTIFACT_STORE_ROOT` to it); ADR 0028; dependency `cryptography`; seventh import contract.

## Next step
Get the owner's OK on the PR size (below), then push and open the PR for #85 (`Closes #85`).
After that #86 (archive extraction in the sandbox), #87 (codebase upload), #101.

## Open threads
- Non-test diff is about 1,090 changed lines, over the ~400 guideline. The owner has not
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
- `tests/unit/sandbox_proxy/test_server.py` has timing-flaky tests; rerun the file if one fails.
- Artifact use cases call `session.rollback()` between steps: service tests must commit their
  fixtures. Use `tmp_path` roots or `tests.fakes.FakeArtifactStore`.
