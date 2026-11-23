# Documentation

| Doc | What's in it |
|---|---|
| [architecture.md](architecture.md) | system design, layers, data model, scan pipeline, AI layer |
| [scanners.md](scanners.md) | scan profiles, registered scanner plugins, and all 25 detection rules |
| [writing-a-scanner.md](writing-a-scanner.md) | contributor guide to building and testing a new scanner plugin |
| [self-hosting.md](self-hosting.md) | quick-start guide to deploying attacksurf on your own server |
| [development.md](development.md) | setup, commands, testing, working with AI agents |
| [deployment.md](deployment.md) | production: Cloudflare Tunnel, Caddy TLS, secrets, backups, deploy runbook |
| [conventions.md](conventions.md) | rules for issues, commits, and pull requests |
| [security.md](security.md) | security model, threat protections, ScopeGuard boundary, data sent to LLMs |
| [responsible-use.md](responsible-use.md) | responsible-use policy, authorization rules, and terms |
| [sponsors.md](sponsors.md) | how sponsorship funds the project |
| [adr/](adr/) | architecture decision records (why things are the way they are) |

Also at the repo root: [`STATE.md`](../STATE.md) (current handoff / next step),
[`DESIGN.md`](../DESIGN.md) (UI design system), [`AGENTS.md`](../AGENTS.md) (agent rules).

Roadmap: GitHub epic [#31](https://github.com/cpt9m0/attacksurf/issues/31).

New architectural decision? Copy `adr/0000-template.md` to the next number.
