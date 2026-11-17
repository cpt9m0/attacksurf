# 0028. Artifact encryption at rest and per-run staging

- Status: accepted
- Date: 2026-11-13

## Context
Issue #85 stores uploaded and fetched repositories and binaries. They are a tenant's source
code and builds, and they are untrusted input. ADR 0017 requires them encrypted at rest and
decrypted "for a run only, under the artifact root", with the plaintext removed afterwards.
ADR 0016 fixes how a run sees an artifact: the launcher mounts the real directory
`{SANDBOX_ARTIFACT_ROOT}/{artifact_id}` read-only into the sandbox.

Constraints:

- #85 was meant to reuse the app-key encryption from #24 (org API keys), but #24 is not merged
  and no encryption code exists; `infra/crypto.py` only hashed passwords.
- Artifacts can be hundreds of megabytes, so encryption must stream. The standard library has
  no authenticated cipher, and Fernet needs the whole message in memory.
- `artifacts.asset_id` cascades. A deleted asset or org removes the row but cannot reach a file
  on disk in the same transaction.
- Whatever sits under `SANDBOX_ARTIFACT_ROOT` can be mounted into a sandbox.

## Decision
- **Envelope encryption with `cryptography`.** Each artifact gets a random 256-bit data key.
  The file is a 12-byte header (`ASAF`, version, 7 random bytes) followed by AES-256-GCM
  frames of 64 KiB plaintext. A frame's nonce is the header's random bytes, a 32-bit frame
  counter and a last-frame flag, and the header is authenticated with every frame, so a
  flipped, reordered, repeated, spliced or truncated file fails instead of decrypting. The
  data key is wrapped with AES-256-GCM under a key derived from `APP_ENCRYPTION_KEY` by
  HKDF-SHA256 with a purpose label (`artifact`), with the org ID and artifact ID as associated
  data. `cryptography` (Apache-2.0 OR BSD-3-Clause, maintained by the PyCA) is the one new
  dependency; writing AES-GCM ourselves is not an option.
- **The wrapped key lives in the row, not in the file.** `artifacts.key_envelope` (61 bytes)
  is the only copy. `delete_artifact` removes the file and sets the column to NULL in one
  transaction, and a CHECK ties that to `deleted_at`. When an asset or org is deleted the
  cascade removes the row and the key with it: any file left on disk is undecryptable even
  with the app key. Deleting therefore needs no key, and the purge task runs without one.
- **Two roots that may not overlap.** Ciphertext is written to
  `{ARTIFACT_STORE_ROOT}/{org_id}/{artifact_id}` (dirs 0700, files 0600, temp file then
  `os.replace`). `SANDBOX_ARTIFACT_ROOT` holds only plaintext staged for a run, at
  `{root}/{artifact_id}/artifact` (0755/0644, because the sandbox runs as another uid), built
  under a random `.stage-*` name the launcher cannot resolve and then renamed into place.
  Settings refuse equal or nested roots: ciphertext inside the mounted root would hand a
  sandbox other tenants' files, and a store root containing the run root would put plaintext
  inside the "ciphertext only" tree.
- **Staging and deletion of one artifact are serialised across processes.** `stage` and
  `delete` take an exclusive `flock` on `{ARTIFACT_STORE_ROOT}/{artifact_id}.lock`, so a purge
  can't remove the row and the ciphertext while a staging is still reading it and then let that
  staging publish mounted plaintext for a row already marked deleted. `stage` re-checks the
  ciphertext under the lock and fails with `ArtifactNotFound` instead of renaming such a
  directory into place. `flock` is released by the kernel when a process dies, so a killed
  stager cannot wedge a delete, and the lock file is never unlinked (unlinking it would let two
  processes "hold" the same lock). The lock lives in the ciphertext root, never in the
  sandbox-visible one.
- **Limits while reading.** `put` counts and hashes the plaintext as it streams and stops at
  `ARTIFACT_MAX_BYTES` (default 256 MiB, ceiling 512 MiB from ADR 0017) or the org's remaining
  `ARTIFACT_ORG_QUOTA_BYTES`, removing the partial file. The quota is re-checked under a lock on
  the org row before the row is committed.
- **Retention.** `ARTIFACT_RETENTION_HOURS=0` (default) means "delete once analysis
  completes": #84 will call `delete_artifact(reason="analysis_complete")`. Until it does, and
  for artifacts that are never analysed, `delete_after` is set 24 hours after upload; a value
  above 0 keeps the artifact that many hours. `passive.purge_expired_artifacts` (beat, every
  10 minutes) deletes what is past `delete_after` and sweeps staged plaintext older than one
  hour, which is above the launcher's longest run. A deletion that fails keeps the key and the
  file and pushes `delete_after` behind everything still waiting (plus a 60 s floor), so a batch
  of undeletable artifacts cannot starve the artifacts behind it, other orgs' included; it is
  retried once its new deadline passes. A deadline a request moved after the attempt is kept.
- **Staging ships as primitives only.** `stage`, `unstage` and `sweep_staged` on the store and
  the thin `stage_artifact` service exist and are tested, but nothing calls them. ADR 0016 says
  the credentialed worker never opens artifact bytes while ADR 0017 needs someone to decrypt
  for a run; which process stages (and holds the key) is #84's decision.
- **`APP_ENCRYPTION_KEY` is not required at boot.** Without it the store refuses to write or
  read and still deletes, so existing deployments keep starting. #87 should make it mandatory
  when the first upload route ships.
- **The primitive is for #24 too.** `infra.crypto.EnvelopeCipher(app_key, purpose=...)` is the
  app-key wrapping #24 should reuse with its own purpose label, instead of adding Fernet.

## Consequences
- Losing `APP_ENCRYPTION_KEY` loses every stored artifact; there is no rotation yet (the
  envelope's version byte leaves room for it).
- Production runs no beat or workers until #29, so nothing is purged there. No upload route
  may ship to production before that.
- After a cascade, and after a crash between writing a file and committing its row, ciphertext
  files stay on disk. They cannot be decrypted but they occupy space; no sweep removes them
  yet.
- Staging the same artifact twice fails until it is unstaged; concurrent runs of one artifact
  need #84 to decide how they share a staged copy.
- The per-artifact lock files are never removed, so one small file per artifact stays in the
  store root after its artifact is gone. They carry nothing but a name.
- An import-linter contract keeps `attacksurf.ai` away from artifact code: LLMs only ever see
  normalized findings.
