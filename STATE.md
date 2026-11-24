# State

**Current focus:** Issue #78 implemented (`web.exposures`, 7 rules, ADR 0033 `http_methods`/`http_paths`/`soft_404_probe` enforcement); preparing PR for epic `#66`.

## What's done recently

- Epic `#66` (`Website module: HTTP attack surface of verified hosts`) progress:
  - `#69`–`#77` (PRs `#193`–`#201`) merged to `main` (`30b3de9`).
  - `#78` (`scanners/web/exposures.py`, `domain/rules/web.py`, `domain/scanners.py`, `infra/http.py`, `infra/scope_guard.py`): added `SafeHttpClient.head`, enforced `ScannerGrant.http_methods`, `http_paths`, and single-shot `soft_404_probe` in `ScopeGuard`, added 7 exposure/security.txt rules, and implemented `web.exposures` (33 curated paths, soft-404 baseline calibration, strict content validators, `HEAD`-only backups & `/actuator/heapdump`, key-name-only `.env` evidence).

## Next step

- Merge PR for `#78` after CI & `@codex review` pass, then plan and implement `#79` (WordPress exposures), followed by `#80`–`#82`.
