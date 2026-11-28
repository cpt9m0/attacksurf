# State

**Current focus:** Issue #79 implemented (`web.wordpress`, 4 rules, passive `?ver=` extraction, local NVD matching, zero plugin enumeration); preparing PR for epic `#66`.

## What's done recently

- Epic `#66` (`Website module: HTTP attack surface of verified hosts`) progress:
  - `#69`–`#78` (PRs `#193`–`#202`) merged to `main` (`a40f191`).
  - `#79` (`scanners/web/wordpress.py`, `scanners/web/fingerprint.py`, `scanners/web/probe.py`, `scanners/web/components.py`, `domain/rules/web.py`): added passive HTML `?ver=` extraction for `/wp-content/plugins/` and `/wp-content/themes/` in `web.probe`, promoted NVD CVE matching helpers in `web.components`, added 4 rules (`web.wordpress.xmlrpc_enabled`, `user_listing`, `debug_log`, `web.exposure.directory_listing`), and implemented `web.wordpress` gated on `#73` WordPress detection under ADR 0033 `ScopeGuard` `http_paths` enforcement.

## Next step

- Merge PR for `#79` after CI & `@codex review` pass, then plan and implement `#80` (Website assets UI), followed by `#81`–`#82`.
