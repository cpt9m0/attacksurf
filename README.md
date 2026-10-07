# attacksurf

AI-powered attack surface management. Register your domains; attacksurf discovers subdomains and
DNS assets, checks them for misconfigurations (email spoofing, subdomain takeover, DNSSEC,
expiry, ...), tracks changes over time, and uses an LLM to triage and explain what matters.

> **Status:** early development. Building toward the MVP: see the
> [roadmap epic](https://github.com/cpt9m0/attacksurf/issues/31).

## Planned scope

| Target | Status |
|---|---|
| Domains & DNS | MVP |
| IP addresses / VPS | later |
| Websites (admin panels, WordPress, XSS, ...) | later |
| Codebases (GitHub / upload) | later |
| Binaries | later |

## Stack

Python 3.12+ · uv · Flask · HTMX · SQLAlchemy + PostgreSQL · Celery + Redis · Anthropic / OpenAI-compatible LLMs · Docker Compose

## Quick start

```bash
uv sync
uv run flask --app attacksurf run --debug
uv run pytest          # tests + 80% coverage gate
```

## Docs

- [Architecture](docs/architecture.md)
- [Development](docs/development.md) (including the AI-agent setup)
- [Security model](docs/security.md)
- [Decision records](docs/adr/)
- [AGENTS.md](AGENTS.md): rules for AI coding agents

## Responsible use

Only scan assets you own or are authorized to test. Active checks require proof of domain
ownership.
