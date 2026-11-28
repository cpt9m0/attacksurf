# State

**Current focus:** Issue #81 implemented (`triage/v2` prompt, `WebContext` for `url` assets with host hints/tech/headers/sibling findings, tight untrusted-field caps, and website eval fixtures); preparing PR for epic `#66`.

## What's done recently

- Epic `#66` (`Website module: HTTP attack surface of verified hosts`) progress:
  - `#69`–`#80` (PRs `#193`–`#208`) merged to `main` (`2bb9a9e`).
  - `#81` (`ai/prompts/triage/v2.md`, `ai/triage.py`, `services/triage.py`, `tests/eval/`, `docs/security.md`): added `triage/v2` (keeping `triage/v1` pinned for cache keys), `WebContext` + `extract_host_hints`, strict web untrusted-field caps (`title` 200, banners/headers 256, file excerpts 500), sensitive header stripping, and 5 website eval fixtures.

## Next step

- Merge PR for `#81` after CI and `@codex review` pass, then plan and implement `#82` (Extend AI exposure summary and digests to website posture).
