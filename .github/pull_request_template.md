<!--
Title = squash commit subject, Conventional Commits: `feat(dns): add DMARC policy check`
One issue per PR, ~400 changed lines max (excl. tests/fixtures/lockfile). See docs/conventions.md.
-->

## Summary

<!-- What changes and why, in 1-3 sentences. -->

Closes #

## Changes

-

## How was this tested?

<!-- Commands run, new/updated tests, manual checks. UI: screenshots in light + dark theme. -->

## Notable

<!-- Write "n/a" where not applicable. -->
- **Breaking changes:** n/a
- **Migrations:** n/a
- **New dependencies (and license):** n/a
- **Security impact** (tenancy, outbound traffic, secrets, LLM payloads): n/a

## Checklist

- [ ] Title follows Conventional Commits; branch is `<issue#>-<slug>`
- [ ] `uv run ruff format . && uv run ruff check .` pass
- [ ] `uv run pyright` passes
- [ ] `uv run pytest` passes, coverage ≥ 80%
- [ ] New behavior has tests; bug fixes have a regression test
- [ ] Tenant data is scoped by `org_id`; outbound traffic goes through ScopeGuard (if applicable)
- [ ] Docs, `DESIGN.md`, `CHANGELOG.md`, agent files, and `STATE.md` updated (`finish-task`)
- [ ] AI assistance used: yes / no (if yes, I reviewed and understand every line)
