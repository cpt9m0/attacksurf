# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Layered package layout (`web`, `services`, `domain`, `scanners`, `ai`, `infra`, `workers`) with
  import-linter contracts; app factory with `ui`, `health` (`/healthz`) and `api_v1` blueprints
- Typed settings (pydantic-settings, `.env.example`) and structured logging (structlog) with
  request IDs and secret redaction
- Project skeleton: Flask app factory, src layout, uv, ruff, pyright, pytest with 80% coverage gate
- Architecture docs, ADRs, security model
- AI-agent setup: AGENTS.md, CLAUDE.md, Claude Code skills, hooks, MCP servers
- Open-source community files: AGPL-3.0 license, contributing guide, code of conduct, security
  policy, issue/PR templates, funding
- `STATE.md` handoff file, `finish-task` skill + keep-in-sync rule, SessionStart/Stop hooks
- `DESIGN.md` web UI design system skeleton
- Issue/commit/PR conventions (`docs/conventions.md`), task and epic issue forms, label
  definitions, commit message template, `create-issue` skill
- Label sync workflow from `.github/labels.yml`
- Dependabot commit prefixes (`build(deps)`, `ci(deps)`); `pr-title` checks only the prefix on
  Dependabot PRs
- Git hooks via pre-commit (ruff, hygiene checks, gitleaks, Conventional Commits message check,
  pyright + pytest on push) and GitHub Actions CI (lint, tests on Python 3.12/3.13, PR-title check)
