<div align="center">

# attacksurf

**Open-source, AI-powered attack surface management (ASM)**

Discover your internet-facing assets, find DNS and security misconfigurations before attackers do,
and let AI explain what matters, self-hosted and free.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/cpt9m0?label=Sponsor&logo=GitHub)](https://github.com/sponsors/cpt9m0)

[Features](#features) · [Quick start](#quick-start) · [Roadmap](#roadmap) · [Contributing](#contributing) · [Sponsor](#sponsor-attacksurf)

</div>

---

> **Status: early development.** The MVP (DNS attack surface monitoring with AI triage) is being
> built in the open. Follow the [roadmap epic](https://github.com/cpt9m0/attacksurf/issues/31),
> star the repo to get updates, or [pick an issue](https://github.com/cpt9m0/attacksurf/issues).

## What is attacksurf?

Your **attack surface** is everything an attacker can reach from the internet: domains,
forgotten subdomains, DNS records, exposed servers, websites, leaked code. **attacksurf**
continuously maps it and checks it for weaknesses: **external attack surface management (EASM)**
for small teams, startups, students, and self-hosters who can't afford commercial ASM platforms.

Scanners find the issues; an LLM (Anthropic Claude or any OpenAI-compatible model, including your
own key) **triages, prioritizes, and explains** them in plain language with fix steps.

## Features

### Domains & DNS (MVP)
- **Subdomain enumeration** from Certificate Transparency logs, with wildcard DNS detection
- **Subdomain takeover detection**: dangling CNAMEs and NS records pointing to unclaimed cloud services
- **Email security**: SPF, DMARC, DKIM, MTA-STS checks (is your domain spoofable?)
- **DNS hygiene**: DNSSEC, nameserver and MX configuration, CAA, zone transfer (AXFR) exposure
- **Domain expiry** monitoring via RDAP
- **Asset graph**: domain → subdomain → CNAME → IP

### Platform
- **AI triage**: severity adjustment, false-positive likelihood, remediation steps, exposure summaries
- **Continuous monitoring**: scheduled rescans with new / fixed / regressed diffs and email alerts
- **Bring your own LLM**: Anthropic or any OpenAI-compatible endpoint (OpenAI, OpenRouter, vLLM, ...)
- **Safe by design**: ownership verification before any active check, SSRF protection, no exploitation
- **Self-hosted**: one `docker compose up` on a single VPS; your data stays with you
- **Multi-user ready**: organizations and roles

### Coming next
IP / VPS exposure (open ports, service CVEs) · Website scanning (admin panels, WordPress, XSS) ·
Codebase scanning (secrets, SAST, vulnerable dependencies) · Binary analysis

## Quick start

> The app is pre-MVP; this runs the development skeleton.

```bash
git clone https://github.com/cpt9m0/attacksurf.git
cd attacksurf
uv sync
uv run flask --app attacksurf run --debug   # http://127.0.0.1:5000
```

Docker Compose setup arrives with [#3](https://github.com/cpt9m0/attacksurf/issues/3).

## How it works

```
 Add domain ─► Discover (CT logs, DNS) ─► Check (takeover, email, DNSSEC, ...) ─► Diff vs last scan ─► AI triage & summary ─► Alert
```

Flask + HTMX web app, Celery workers, PostgreSQL, Redis. Each check is a small plugin, so
**adding a new check is a great first contribution**. Details: [architecture](docs/architecture.md).

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Foundation: tooling, DB, auth, UI shell | 🚧 in progress |
| 2 | Scan engine: plugins, pipeline, ScopeGuard | planned |
| 3 | DNS module | planned |
| 4 | AI triage and summaries | planned |
| 5 | Scheduling, alerts, deployment → **v0.1.0** | planned |
| next | IP, web, code, binary scanning | ideas welcome |

Full plan: [epic #31](https://github.com/cpt9m0/attacksurf/issues/31).

## Contributing

Contributions of all sizes are welcome: new checks, bug reports, docs, UI, ideas.

1. Read [CONTRIBUTING.md](CONTRIBUTING.md)
2. Pick a [`good first issue`](https://github.com/cpt9m0/attacksurf/labels/good%20first%20issue) or any unblocked issue from the [roadmap](https://github.com/cpt9m0/attacksurf/issues/31)
3. Open a PR

AI-assisted contributions are welcome too. The repo ships with [AGENTS.md](AGENTS.md), Claude Code
skills, and MCP config so coding agents follow the project's rules.

## Sponsor attacksurf

attacksurf is free and open source, and we want to keep it that way. Sponsorships pay for:

- **Hosting** a free public instance and a demo
- **API costs** (LLM tokens, threat-intel data sources) for the free tier
- **Maintainer time** for reviews, security fixes, and new scanners

<a href="https://github.com/sponsors/cpt9m0"><img src="https://img.shields.io/badge/Sponsor_on_GitHub-%E2%9D%A4-ea4aaa?style=for-the-badge&logo=github" alt="Sponsor on GitHub"></a>
<a href="https://ko-fi.com/cpt9m0"><img src="https://img.shields.io/badge/Ko--fi-Buy_us_a_coffee-ff5e5b?style=for-the-badge&logo=ko-fi&logoColor=white" alt="Support on Ko-fi"></a>

Companies: sponsoring gets your logo here. See [docs/sponsors.md](docs/sponsors.md).

## Responsible use

attacksurf is a **defensive** tool. Only scan assets you own or are authorized to assess. Active
checks require proof of domain ownership, and the project will not add exploitation, brute-force,
or DoS features. See the [security model](docs/security.md).

Found a vulnerability in attacksurf itself? Please report it privately: [SECURITY.md](SECURITY.md).

## License

[GNU AGPL v3.0](LICENSE). Free to use, modify, and self-host. If you run a modified version as a
network service, you must share your changes under the same license.

---

<div align="center">

If attacksurf is useful to you, please ⭐ **star the repo**: it helps others find it.

</div>
