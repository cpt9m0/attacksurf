# Security model

attacksurf is a defensive tool that sends traffic to the internet on behalf of users and handles
their security data. Both make it a target. These rules apply to all code.

## Responsible use

- **Passive checks** (public DNS, Certificate Transparency, RDAP) may run on any registered domain.
- **Active checks** (zone transfer now; port/web probing later) run **only on assets whose
  ownership is verified** (DNS TXT token). ScopeGuard enforces this; scanners cannot bypass it.
- **Out of scope, always:** exploitation, brute forcing, credential attacks, DoS, actually
  claiming takeover-able resources, and scanning of third-party targets.

## Protecting the platform

| Threat | Control |
|---|---|
| SSRF via user targets, redirects, custom LLM `base_url` | ScopeGuard blocks private, loopback, link-local (incl. `169.254.169.254`), CGNAT, reserved and IPv6-equivalent ranges; the safe HTTP client pins the resolved IP and re-checks every redirect |
| Cross-tenant data access | `org_id` on every tenant row, scoped queries, an isolation test per endpoint; Postgres RLS later |
| XSS from scan data (TXT records, HTML, banners) | Jinja autoescape, never `|safe` on scan data, strict CSP without inline scripts |
| CSRF | Flask-WTF tokens on all forms and HTMX requests |
| Prompt injection via scan data | scan data is delimited and size-capped in prompts, output is schema-validated, AI cannot take actions |
| Secret leakage / forged sessions | env vars and connection URLs typed as `SecretStr` (masked in repr); `ENV=prod` refuses to start unless `SECRET_KEY` is ≥ 32 chars and not a placeholder such as `change-me`; org API keys encrypted at rest (Fernet/MultiFernet); structlog redacts secret-looking keys; keys never rendered back in full |
| Log injection | client `X-Request-ID` accepted only if it matches `[A-Za-z0-9-]{1,64}`, otherwise replaced; structured (JSON) logs |
| Malicious uploads *(later)* | never executed; analysis in gVisor sandboxes without network |
| Account attacks | argon2id hashing (`infra/crypto.py`, argon2-cffi defaults); passwords 12–1024 chars (upper bound limits hashing DoS), never logged or echoed in errors; emails normalized to lowercase and unique; login rate limiting, secure session cookies (#7); audit log (`details` never holds secrets) |
| Supply chain | locked deps (`uv.lock`), `pip-audit` in CI, pinned MCP server versions, minimal dependencies |

## Data sent to LLM providers

Only normalized findings (rule, severity, asset name, trimmed evidence) and aggregate stats.
Never: credentials, API keys, raw uploads. Each AI feature documents its payload here as it is
added. Orgs can disable AI or bring their own provider key.

## Reporting a vulnerability

Open a private security advisory on GitHub rather than a public issue.
