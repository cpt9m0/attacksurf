# State

**Current focus:** Issue #82 implemented (`summary/v2` prompt, `web_exposure` and validated `risk_chains`, per-URL tech/exposure context in `SummaryInput`, notable URL tagging, UI sections on `/scans/<id>`, and `web_exposure_scan` eval fixture); preparing final PR for epic `#66`.

## What's done recently

- Epic `#66` (`Website module: HTTP attack surface of verified hosts`) progress:
  - `#69`–`#81` (PRs `#193`–`#209`) merged to `main` (`666d41f`).
  - `#82` (`ai/schemas.py`, `ai/summary.py`, `ai/prompts/summary/v2.md`, `services/summary.py`, `services/summary_views.py`, `templates/pages/_scan_summary.html`): extended AI exposure summaries with `web_exposure`, validated `risk_chains` (unknown refs dropped), per-URL web tech/exposure counts, `notable` tagging on URLs, and website eval fixture.

## Next step

- Merge PR for `#82` after CI, Playwright `web_e2e`, and `@codex review` pass, then confirm Epic `#66` completion.
