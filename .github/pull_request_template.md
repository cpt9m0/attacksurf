## Summary

<!-- What does this PR change and why? -->

Closes #

## Changes

-

## How was this tested?

<!-- Commands run, new tests, screenshots for UI changes. -->

## Checklist

- [ ] `uv run ruff format . && uv run ruff check .` pass
- [ ] `uv run pyright` passes
- [ ] `uv run pytest` passes, coverage ≥ 80%
- [ ] New behavior has tests; bug fixes have a regression test
- [ ] Tenant data is scoped by `org_id`; outbound traffic goes through ScopeGuard (if applicable)
- [ ] Docs / ADRs updated (if applicable)
- [ ] AI assistance used: yes / no (if yes, I reviewed and understand every line)
