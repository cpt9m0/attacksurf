# Contributing to attacksurf

Thanks for helping build free, open-source attack surface management! Every contribution counts:
code, new security checks, docs, bug reports, design feedback, and spreading the word.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- 🐛 **Report a bug**: [open a bug report](https://github.com/cpt9m0/attacksurf/issues/new?template=bug_report.yml)
- 💡 **Suggest a feature**: [feature request](https://github.com/cpt9m0/attacksurf/issues/new?template=feature_request.yml)
- 🔍 **Propose a new security check**: [check request](https://github.com/cpt9m0/attacksurf/issues/new?template=new_check.yml)
- 🧑‍💻 **Write code**: pick a [`good first issue`](https://github.com/cpt9m0/attacksurf/labels/good%20first%20issue) or an unblocked issue from the [roadmap](https://github.com/cpt9m0/attacksurf/issues/31)
- 📖 **Improve docs**: typos, clarity, guides, translations
- ❤️ **Sponsor**: [GitHub Sponsors](https://github.com/sponsors/cpt9m0) or [Ko-fi](https://ko-fi.com/cpt9m0)

🔒 **Security vulnerabilities**: never in public issues. See [SECURITY.md](SECURITY.md).

## Development setup

Requirements: [uv](https://docs.astral.sh/uv/getting-started/installation/) (it installs Python 3.12+
for you) and Git. Docker is needed from the Compose setup onward.

```bash
git clone https://github.com/<you>/attacksurf.git
cd attacksurf
uv sync
uv run flask --app attacksurf run --debug
```

More detail: [docs/development.md](docs/development.md).

## Workflow

1. **Comment on the issue** you want to take, so work isn't duplicated. For bigger changes without
   an issue, open one first to agree on the approach.
2. **Fork and branch**: `git checkout -b 42-short-description`
3. **Code + tests**: follow [AGENTS.md](AGENTS.md) (architecture rules and conventions apply to
   humans too). New behavior needs tests; bug fixes need a regression test.
4. **Check locally**, all must pass:
   ```bash
   uv run ruff format . && uv run ruff check .
   uv run pyright
   uv run pytest          # coverage must stay ≥ 80%
   ```
5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(dns): add DMARC policy check`. Enable the template with
   `git config commit.template .gitmessage`.
6. **Open a PR** using the template: title in Conventional Commits format (PRs are
   squash-merged), link the issue (`Closes #42`), one issue per PR, ideally ≤ ~400 changed lines.

Issue, commit, and PR rules in full: [docs/conventions.md](docs/conventions.md).

A maintainer will review it. Expect questions; they're about the code, not about you.

## Adding a security check

New checks are the most valuable contributions and are designed to be self-contained plugins.
Follow the [`add-scanner` guide](.claude/skills/add-scanner/SKILL.md). In short:
rule definition → plugin → recorded fixtures → tests → docs.

Checks must be **defensive**: detect, don't exploit. Anything beyond passive public lookups must
require verified ownership.

## AI-assisted contributions

This project is largely AI-coded, and AI-assisted PRs are welcome, with conditions:

- You are responsible for every line: read it, understand it, and test it.
- The repo includes [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md), Claude Code skills
  (`.claude/skills/`), and MCP config (`.mcp.json`), so point your agent at them.
- Mention AI assistance in the PR description.
- Low-effort, unreviewed generated PRs will be closed.

## License of contributions

attacksurf is licensed under [AGPL-3.0-or-later](LICENSE). By submitting a contribution you agree
it is licensed under the same terms (inbound = outbound), and that you have the right to submit it.

## Recognition

All contributors are credited in release notes. Thank you! 🙌
