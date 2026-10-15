# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-15 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #8 (asset model)

## Status
#8 implemented; PR #47 open. Third Codex round (on `347da8e`) fixed; waiting for CI + the
next Codex review (wait for it before merging), then squash-merge. #1–#7 merged.

## Last task
- `domain/assets.py`: `AssetType`, `AssetSource`, `RelationKind`, `normalize_asset_value`
  (hostname via `idna` UTS46/IDNA2008, IP via `ipaddress`, URL http(s) only, no credentials,
  RFC 3986 percent-encoding; repo/binary → `UnsupportedAssetType`), `AssetNotFound`
- Models `Asset` (incl. `deactivated_at`; CHECKs: no self-parent, user assets are roots,
  `is_active` ⇔ `deactivated_at IS NULL`), `AssetRelation` (migration `0003`)
- `services/assets.py`: `record_asset`, `record_relation` (`INSERT … ON CONFLICT`, parent fixed
  at first sighting, promotion to `user` detaches, endpoints locked `FOR KEY SHARE` →
  `AssetNotFound`; building blocks, no commit)
- Tests: 347 with DB (99%)

## Next step
After #8 merges: #9 (Scan, Job, Finding, Evidence with fingerprint + lifecycle, rule catalog,
migration `0004`). The scan that marks assets gone must set `is_active=False` and
`deactivated_at` together.

## Open threads
- `.env.example` needs: `ALLOW_SIGNUP=true`, `SESSION_LIFETIME_HOURS=12`, `PROXY_COUNT=0`
  (prod behind Caddy: `PROXY_COUNT=1`)
- Optional (user): ruleset on `main` requiring PRs + checks `lint`, `test (3.12)`,
  `test (3.13)`, `secrets`, `compose`, `pr-title`
- #32: GitHub Sponsors / Ko-fi accounts not set up yet (Ko-fi username assumed `cpt9m0`)
- Repo settings for the user: description, topics, Discussions, Sponsorships,
  private vulnerability reporting, social preview
- `DESIGN.md` visual values are placeholders in `static/css/tokens.css` (`TODO(DESIGN.md)`):
  replace via Claude Design (tokens, severity colors, favicon/brand); no template changes needed
- context7 MCP blocked by the environment's network proxy (403); brave-search needs `BRAVE_API_KEY`;
  playwright MCP wants Google Chrome (absent): use Python Playwright with
  `executable_path=/opt/pw-browsers/chromium-1194/chrome-linux/chrome` instead

## Notes for the next agent
- Repo: default branch `main`, squash-merge only (PR title = commit subject), head branches
  auto-deleted
- Cloud sandbox: start Docker with `dockerd &`; Docker Hub may rate-limit (429), so use
  `mirror.gcr.io/library/<image>` with the same digest; GHCR blob downloads are blocked by the proxy;
  image builds need the proxy CA (build from a scratch copy that adds it, never commit that)
- Tests: `tests.helpers.make_settings(...)` ignores `.env` and OS env; env-loading tests use
  `settings_from_env()` + `clean_env` fixture
- `flask --app attacksurf` works (`create_app` lazily re-exported from `__init__.py`)
- First `pre-commit` run downloads hook envs (gitleaks builds with Go): takes a minute
