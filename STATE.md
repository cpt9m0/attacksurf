# State

**Current focus:** Issue #80 implemented (`add_url_asset`, "Add a URL" intake tab, URL detail panels for web endpoint/technologies/TLS/security headers, `?tech=` filter, API + E2E tests); preparing PR for epic `#66`.

## What's done recently

- Epic `#66` (`Website module: HTTP attack surface of verified hosts`) progress:
  - `#69`–`#79` (PRs `#193`–`#203`) merged to `main` (`11dd201`).
  - `#80` (`services/assets.py`, `services/asset_views.py`, `web/ui.py`, `web/api/v1.py`, templates, `static/js/app.js`, `static/css/app.css`, `DESIGN.md`): added `add_url_asset` attaching to covering root domains (or unverified fallback), URL overview panels (HTTP status/title/redirect chain, technologies + versions, TLS summary, security-header pass/fail grid), `?tech=` filter across UI & API, and Playwright + tenant-isolation tests.

## Next step

- Merge PR for `#80` after CI, Playwright `web_e2e`, and `@codex review` pass, then plan and implement `#81` (Extend AI triage to website findings) and `#82` (Extend AI exposure summary and digests to website posture).
